// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier Memory Tiering
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>
#include <linux/pagewalk.h>

#include "../internal.h"

#include <trace/events/ftier.h>

static void set_tiering_nodes(bool *src_nodes, bool *dst_nodes, bool promote)
{
	int nid;
	for (nid = 0; nid < NR_NODES; ++nid) {
		if (CXL_NID(nid)) {
			src_nodes[nid] = promote ? true : false;
			dst_nodes[nid] = promote ? false : true;
		} else if (DRAM_NID(nid)) {
			src_nodes[nid] = promote ? false : true;
			dst_nodes[nid] = promote ? true : false;
		} else {
			src_nodes[nid] = false;
			dst_nodes[nid] = false;
		}
	}
}

static void compute_histogram(struct ftier_target *t,
		unsigned int *histogram, bool promote)
{
	struct fhot_meta_gb *meta;
	unsigned int idx, spins, period, opt_period_us, cmidx, cmoff;
	bool oncxl;

	opt_period_us = (sysctl_fscan_period_ms * 1000) / MAX_SPINS;
	list_for_each_entry(meta, &t->fhot_list, siblings) {
		period = meta->fspin_period_us;
		for (idx = 0; idx < 512; ++idx) {
			cmidx = idx >> 6;
			cmoff = idx & 0x3f;
			oncxl = ((meta->cxlmap[cmidx] & (1UL << cmoff)) != 0);
			if ((oncxl && !promote) || (!oncxl && promote))
				continue;

			spins = meta->spins[idx];
			if (period < opt_period_us)
				spins *= (opt_period_us / period);
			if (spins < MAX_SPINS)
				histogram[spins]++;
			else
				histogram[MAX_SPINS]++;
		}
	}

	for (idx = 0; idx <= MAX_SPINS; ++idx) {
		if (histogram[idx])
			trace_fhist(idx, 2 * histogram[idx]);
	}
}

static int thresh(unsigned int *histogram, unsigned int promote_pmds)
{
	int sum, idx;

	if (!promote_pmds)
		return 0; /* disable promotion */

	sum = 0;
	for (idx = MAX_SPINS; idx > 0; --idx) {
		sum += histogram[idx];
		if (sum >= promote_pmds)
			break;
	}

	return idx;
}

struct migrate_args {
	struct list_head folio_list;
	int nrpages;
	bool *src_nodes;
};

static int gather_ptep_pages(pte_t *ptep, unsigned long addr,
		unsigned long next, struct mm_walk *walk)
{
	struct migrate_args *args = walk->private;
	struct folio *folio;
	struct page *page;
	pte_t pte = ptep_get(ptep);
	int nid;

	if (pte_none(pte) || !pte_present(pte))
		return 0;

	page = pte_page(pte);
	if (!page || PageTail(page))
		return 0;

	nid = page_to_nid(page);
	if (!args->src_nodes[nid])
		return 0;

	folio = page_folio(page);
	if (!folio_test_lru(folio) || !folio_try_get(folio))
		return 0;
	if (unlikely(page_folio(page) != folio || !folio_test_lru(folio)))
		goto put_folio;

	if (!folio_isolate_lru(folio))
		goto put_folio;

	list_add(&folio->lru, &args->folio_list);
	args->nrpages += folio_nr_pages(folio);

put_folio:
	folio_put(folio);
	return 0;
}

static const struct mm_walk_ops migrate_ops = {
	.pte_entry = gather_ptep_pages,
	.walk_lock = PGWALK_RDLOCK,
};

static inline int ftier_next_node(int curnid, bool *dst_nodes)
{
	int idx;
	for (idx = 0; idx < NR_NODES; ++idx) {
		curnid = (curnid + 1) % NR_NODES;
		if (dst_nodes[curnid])
			return curnid;
	}
	return -1;
}

static int migrate_data(struct mm_struct *mm, unsigned long addr,
		unsigned long len, bool *src_nodes, bool *dst_nodes,
		unsigned int *nr_failed)
{
	struct migrate_args args;
	struct folio *folio;
	nodemask_t allowed_mask = NODE_MASK_NONE;
	int nid, nr_remaining, nr_migrated;
	unsigned int migrated, batchsz;
	struct migration_target_control mtc = {
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.nmask = &allowed_mask
	};
	LIST_HEAD(migrate_folios);

	*nr_failed = 0;
	nr_migrated = 0;
	if ((nid = ftier_next_node(0, dst_nodes)) < 0)
		return -EINVAL;

	args.src_nodes = src_nodes;
	INIT_LIST_HEAD(&args.folio_list);

	mmap_read_lock(mm);

	walk_page_range(mm, addr, addr + len, &migrate_ops, &args);

	batchsz = 0;
	while (!list_empty(&args.folio_list)) {
		folio = lru_to_folio(&args.folio_list);
		list_move(&folio->lru, &migrate_folios);
		++batchsz;
		if (batchsz < MIGRATE_BATCH && !list_empty(&args.folio_list))
			continue;

		mtc.nid = nid;
		nr_remaining = migrate_pages(&migrate_folios,
				alloc_migrate_folio, NULL, (unsigned long)&mtc,
				MIGRATE_ASYNC, MR_FTIER, &migrated);

		if (nr_remaining && !list_empty(&migrate_folios)) {
			*nr_failed += nr_remaining;
			putback_movable_pages(&migrate_folios);
		}
		nr_migrated += migrated;
		nid = ftier_next_node(nid, dst_nodes);
		batchsz = 0;
	}

	mmap_read_unlock(mm);

	return nr_migrated;
}

static unsigned int tier_memory(struct ftier_target *t,
		unsigned int threshold, bool promote,
		unsigned int max_pages, unsigned int *histogram)
{
	struct fhot_meta_gb *meta;
	unsigned int mult, hotness, idx, dur_us, nr_pages;
	unsigned int opt_period_us, cmidx, cmoff;
	int err, success, failed, nr_pages_success, nr_pages_fail, hidx;
	bool src_nodes[NR_NODES], dst_nodes[NR_NODES], oncxl;
	uint64_t start_ns, end_ns;
	unsigned long address;

	set_tiering_nodes(src_nodes, dst_nodes, promote);

	success = 0;
	failed = 0;
	nr_pages_success = 0;
	nr_pages_fail = 0;
	opt_period_us = (sysctl_fscan_period_ms * 1000) / MAX_SPINS;

	start_ns = ktime_get_ns();
	list_for_each_entry(meta, &t->fhot_list, siblings) {
		mult = 1;
		if (meta->fspin_period_us < opt_period_us)
			mult = (opt_period_us / meta->fspin_period_us);

		for (idx = 0; idx < 512; ++idx) {
			cmidx = idx >> 6;
			cmoff = idx & 0x3f;
			oncxl = ((meta->cxlmap[cmidx] & (1UL << cmoff)) != 0);
			if ((oncxl && !promote) || (!oncxl && promote))
				continue;

			hotness = meta->spins[idx] * mult;
			if (hotness < threshold)
				continue;

			hidx = min(hotness, MAX_SPINS);
			address = meta->address + (idx << PMD_SHIFT);
			err = migrate_data(meta->mm, address, PMD_SIZE,
					src_nodes, dst_nodes, &nr_pages);

			if (err < 0) {
				failed++;
			} else {
				success++;
				nr_pages_success += err;
				nr_pages_fail += nr_pages;

				histogram[hidx]--;
				if (!promote)
					meta->cxlmap[cmidx] |= (1UL << cmoff);
				else
					meta->cxlmap[cmidx] &= ~(1UL << cmoff);

				if (nr_pages_success >= max_pages)
					goto end;
			}
		}
	}
end:
	end_ns = ktime_get_ns();
	dur_us = (end_ns - start_ns) / 1000;

	trace_fmigrate(success, failed, nr_pages_success,
			nr_pages_fail, dur_us, threshold, promote);
	return nr_pages_success;
}

void ftier_tier_memory(struct ftier_target *t)
{
	unsigned int *histogram;
	unsigned int tiered_pages, pmds_to_tier, mb;
	int maxpages, threshold;
	bool promote = (sysctl_promote_mb > 0);

	mb = abs(sysctl_promote_mb);
	if (mb == 0)
		return;

	histogram = kzalloc(sizeof(unsigned int) * (MAX_SPINS + 1), GFP_KERNEL);
	if (!histogram)
		return;

	compute_histogram(t, histogram, promote);

	pmds_to_tier = mb / 2;
	maxpages = mb * 256;
	do {
		threshold = thresh(histogram, pmds_to_tier);
		tiered_pages = tier_memory(t, threshold, promote,
				maxpages, histogram);
		maxpages -= tiered_pages;
		pmds_to_tier = (maxpages / 512);
	} while (pmds_to_tier > 0 && threshold > 0);

	kfree(histogram);
}
