// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier Memory Tiering
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>
#include <linux/pagewalk.h>

#include <asm-generic/tlb.h>

#include "../internal.h"

#include <trace/events/ftier.h>

static enum ftier_tiering_mode TIERING_MODE;

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

			spins = meta->oldspins[idx];
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

	if (!histogram || !promote_pmds)
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

	walk_page_range(mm, addr, addr + len, &migrate_ops, &args);

	batchsz = 0;
	while (!list_empty(&args.folio_list)) {
		folio = lru_to_folio(&args.folio_list);
		list_move(&folio->lru, &migrate_folios);
		++batchsz;
		if (batchsz < sysctl_migrate_batch && !list_empty(&args.folio_list))
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

	return nr_migrated;
}

static int change_pte_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr,
		unsigned long end, bool *src_nodes)
{
	pte_t *pte, oldpte, newpte;
	spinlock_t *ptl;
	struct folio *folio;
	int pages = 0;
	int nid;

	tlb_change_page_size(tlb, PAGE_SIZE);
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!pte)
		return -EAGAIN;

	flush_tlb_batched_pending(vma->vm_mm);
	arch_enter_lazy_mmu_mode();
	do {
		oldpte = ptep_get(pte);
		if (!pte_present(oldpte))
			continue;

		if (pte_protnone(oldpte))
			continue;

		folio = vm_normal_folio(vma, addr, oldpte);
		if (!folio || folio_is_zone_device(folio) ||
		    folio_test_ksm(folio))
			continue;

		/* Also skip shared copy-on-write pages */
		if (is_cow_mapping(vma->vm_flags) &&
		    (folio_maybe_dma_pinned(folio) ||
		     folio_maybe_mapped_shared(folio)))
			continue;

		if (folio_is_file_lru(folio) && folio_test_dirty(folio))
			continue;

		nid = folio_nid(folio);
		if (!src_nodes[nid])
			continue;

		if (folio_use_access_time(folio))
			folio_xchg_access_time(folio, jiffies_to_msecs(jiffies));

		oldpte = ptep_modify_prot_start(vma, addr, pte);
		newpte = pte_modify(oldpte, PAGE_NONE);
		ptep_modify_prot_commit(vma, addr, pte, oldpte, newpte);
		if (pte_needs_flush(oldpte, newpte))
			tlb_flush_pte_range(tlb, addr, PAGE_SIZE);
		pages++;
	} while (pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte, ptl);
	return pages;
}

static int change_pmd_range(struct fhot_meta_gb *meta,
		unsigned long addr, unsigned long len, bool *src_nodes)
{
	unsigned long next, end;
	int ret, pages;
	struct mmu_gather tlb;
	struct vm_area_struct *vma;
	struct task_struct *task;
	struct mm_struct *mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, _pmd;

	task = find_task_by_vpid(meta->pid);
	if (!task || task->flags & PF_EXITING)
		return -EINVAL;

	mm = get_task_mm(task);
	if (!mm)
		return -EINVAL;

	pages = 0;
	end = addr + len;
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start) {
		mmput(mm);
		return -EINVAL;
	}

	if (!vma_migratable(vma) || !vma_policy_mof(vma) ||
			is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_MIXEDMAP) ||
			!vma->vm_mm || vma->vm_mm != mm) {
		mmput(mm);
		return -EINVAL;
	}

	if (
			// !vma_is_accessible(vma) ||
			(vma->vm_file && (vma->vm_flags & (VM_READ|VM_WRITE)) == (VM_READ))
		) {
		mmput(mm);
		printk(KERN_INFO "ftier error2: flags=%lx, acc=%d vm_mm=%lx mm=%lx file=%lx\n", 
				vma->vm_flags, vma_is_accessible(vma), (unsigned long)vma->vm_mm,
				(unsigned long)mm, (unsigned long)vma->vm_file);
		return -EINVAL;
	}

	tlb_gather_mmu(&tlb, mm);

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto finish_mmu;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto finish_mmu;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto finish_mmu;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto finish_mmu;

	do {
again:
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;

		_pmd = pmdp_get_lockless(pmd);
		if (is_swap_pmd(_pmd) || pmd_trans_huge(_pmd) || pmd_devmap(_pmd))
			continue;

		ret = change_pte_range(&tlb, vma, pmd, addr, next, src_nodes);
		if (ret < 0)
			goto again;

		pages += ret;
	} while (pmd++, addr = next, addr != end);

finish_mmu:
	tlb_finish_mmu(&tlb);
	mmput(mm);
	if (pages > 0) {
		count_vm_numa_events(NUMA_PTE_UPDATES, pages);
		count_memcg_events_mm(mm, NUMA_PTE_UPDATES, pages);
	}

	return pages;
}

static unsigned int tier_memory(struct ftier_target *t,
		unsigned int threshold, bool promote, int *budget_us,
		unsigned int max_pages, unsigned int *histogram)
{
	struct fhot_meta_gb *meta;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned int mult, hotness, idx, nr_pages;
	unsigned int opt_period_us, cmidx, cmoff;
	int err, success, failed, nr_pages_success;
	int nr_pages_fail, hidx, dur_us;
	bool src_nodes[NR_NODES], dst_nodes[NR_NODES], oncxl;
	uint64_t start_ns, end_ns;
	unsigned long address;

	set_tiering_nodes(src_nodes, dst_nodes, promote);

	success = 0;
	failed = 0;
	nr_pages_success = 0;
	nr_pages_fail = 0;
	nr_pages = 0;
	opt_period_us = (sysctl_fscan_period_ms * 1000) / MAX_SPINS;

	start_ns = ktime_get_ns();
	end_ns = start_ns;
	dur_us = 0;

	list_for_each_entry(meta, &t->fhot_list, siblings) {
		mult = 1;
		if (meta->fspin_period_us < opt_period_us)
			mult = (opt_period_us / meta->fspin_period_us);

		task = find_task_by_vpid(meta->pid);
		if (!task || task->flags & PF_EXITING)
			goto end;

		for (idx = 0; idx < 512; ++idx) {
			cmidx = idx >> 6;
			cmoff = idx & 0x3f;
			oncxl = ((meta->cxlmap[cmidx] & (1UL << cmoff)) != 0);
			if ((oncxl && !promote) || (!oncxl && promote))
				continue;

			hotness = meta->oldspins[idx] * mult;
			if (hotness < threshold)
				continue;

			hidx = min(hotness, MAX_SPINS);
			address = meta->address + (idx << PMD_SHIFT);

			mm = get_task_mm(task);
			if (!mm)
				goto end;

			mmap_read_lock(mm);

			switch (TIERING_MODE) {
				case DEMAND_MIGRATE:
				err = migrate_data(mm, address, PMD_SIZE,
						src_nodes, dst_nodes, &nr_pages);
				break;
				case HINT_FAULT:
					err = change_pmd_range(meta, address, PMD_SIZE, src_nodes);
				break;
				default:
					err = -EINVAL;
			}

			mmap_read_unlock(mm);
			mmput(mm);

			if (err <= 0) {
				failed++;
			} else {
				success++;
				nr_pages_success += err;
				nr_pages_fail += nr_pages;

				histogram[hidx]--;
				if (!promote)
					meta->cxlmap[cmidx] |=
						(1UL << cmoff);
				else
					meta->cxlmap[cmidx] &=
						~(1UL << cmoff);
			}

			end_ns = ktime_get_ns();
			dur_us = (end_ns - start_ns) / 1000;
			if (dur_us >= *budget_us)
				goto end;

			if (nr_pages_success >= max_pages)
				goto end;
		}
	}

end:
	trace_fmigrate(success, failed, nr_pages_success, nr_pages_fail,
			*budget_us, dur_us, threshold, promote, max_pages);

	*budget_us -= dur_us;
	return nr_pages_success;
}

unsigned int *histogram = NULL;

void ftier_tier_memory(struct ftier_target *t,
		int promote_mb, int budget_us, bool hist_update)
{
	unsigned int tiered_pages, pmds_to_tier, mb;
	int maxpages, threshold, max_failed_tries = 5;
	bool promote = (promote_mb > 0);
	ssize_t histsz = sizeof(unsigned int) * (MAX_SPINS + 1);

	mb = abs(promote_mb);
	if (mb == 0)
		return;

	TIERING_MODE = sysctl_tiering_mode;
	if (hist_update) {
		if (histogram)
			memset(histogram, 0, histsz);
		else
			histogram = kzalloc(histsz, GFP_KERNEL);
		if (!histogram)
			return;

		compute_histogram(t, histogram, promote);
	}

	if (!histogram)
		return;

	pmds_to_tier = mb / 2;
	maxpages = mb * 256;
	do {
		threshold = thresh(histogram, pmds_to_tier);
		tiered_pages = tier_memory(t, threshold, promote,
				&budget_us, maxpages, histogram);
		if (!tiered_pages)
			max_failed_tries--;

		maxpages -= tiered_pages;
		pmds_to_tier = (maxpages / 512);
	} while (pmds_to_tier > 0 && threshold > 0 &&
			budget_us > 0 && max_failed_tries > 0);
}
