// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON Primitives for The Physical Address Space
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

#define pr_fmt(fmt) "damon-pa: " fmt

#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/memory-tiers.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>

#include "../internal.h"
#include "ops-common.h"

static const uint64_t DAMON_PEBS_EVENTS[] = {
	LLC_MISS_LOADS_EVENT,
	ALL_STORES_EVENT
};

struct aggregation_metadata {
	unsigned int max_nr_samples;
	unsigned int max_sample_period_sum;
} metapebs;

static bool damon_folio_mkold_one(struct folio *folio,
		struct vm_area_struct *vma, unsigned long addr, void *arg)
{
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, addr, 0);

	while (page_vma_mapped_walk(&pvmw)) {
		addr = pvmw.address;
		if (pvmw.pte)
			damon_ptep_mkold(pvmw.pte, vma, addr);
		else
			damon_pmdp_mkold(pvmw.pmd, vma, addr);
	}
	return true;
}

static void damon_folio_mkold(struct folio *folio)
{
	struct rmap_walk_control rwc = {
		.rmap_one = damon_folio_mkold_one,
		.anon_lock = folio_lock_anon_vma_read,
	};
	bool need_lock;

	if (!folio_mapped(folio) || !folio_raw_mapping(folio)) {
		folio_set_idle(folio);
		return;
	}

	need_lock = !folio_test_anon(folio) || folio_test_ksm(folio);
	if (need_lock && !folio_trylock(folio))
		return;

	rmap_walk(folio, &rwc);

	if (need_lock)
		folio_unlock(folio);

}

static bool damon_folio_young_one(struct folio *folio,
		struct vm_area_struct *vma, unsigned long addr, void *arg)
{
	bool *accessed = arg;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, addr, 0);

	*accessed = false;
	while (page_vma_mapped_walk(&pvmw)) {
		addr = pvmw.address;
		if (pvmw.pte) {
			*accessed = pte_young(ptep_get(pvmw.pte)) ||
				!folio_test_idle(folio) ||
				mmu_notifier_test_young(vma->vm_mm, addr);
		} else {
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
			*accessed = pmd_young(pmdp_get(pvmw.pmd)) ||
				!folio_test_idle(folio) ||
				mmu_notifier_test_young(vma->vm_mm, addr);
#else
			WARN_ON_ONCE(1);
#endif	/* CONFIG_TRANSPARENT_HUGEPAGE */
		}
		if (*accessed) {
			page_vma_mapped_walk_done(&pvmw);
			break;
		}
	}

	/* If accessed, stop walking */
	return *accessed == false;
}

static bool damon_folio_young(struct folio *folio)
{
	bool accessed = false;
	struct rmap_walk_control rwc = {
		.arg = &accessed,
		.rmap_one = damon_folio_young_one,
		.anon_lock = folio_lock_anon_vma_read,
	};
	bool need_lock;

	if (!folio_mapped(folio) || !folio_raw_mapping(folio)) {
		if (folio_test_idle(folio))
			return false;
		else
			return true;
	}

	need_lock = !folio_test_anon(folio) || folio_test_ksm(folio);
	if (need_lock && !folio_trylock(folio))
		return false;

	rmap_walk(folio, &rwc);

	if (need_lock)
		folio_unlock(folio);

	return accessed;
}

static void __damon_pa_check_access(struct damon_region *r,
			struct damon_attrs *attrs, struct damon_pebs_sample *s)
{
	r->nr_pebs_samples++;
	r->pebs_sample_period_sum += s->period;

	if (r->nr_pebs_samples > metapebs.max_nr_samples)
		metapebs.max_nr_samples = r->nr_pebs_samples;
	if (r->pebs_sample_period_sum > metapebs.max_sample_period_sum)
		metapebs.max_sample_period_sum = r->pebs_sample_period_sum;
}

static bool __damon_pa_check_access_sample(struct damon_ctx *ctx,
			struct damon_pebs_sample *sample)
{
	struct damon_target *t;
	struct damon_region *r;

	damon_for_each_target(t, ctx) {
		damon_for_each_region(r, t) {
			if (r->ar.start <= sample->phys_addr && sample->phys_addr < r->ar.end) {
				__damon_pa_check_access(r, &ctx->attrs, sample);
				return true;
			}
		}
	}

	return false;
}

static unsigned int damon_update_nr_accesses(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct damon_region *r;
	unsigned int max_nr_accesses = 0, factor;

	factor = ctx->attrs.aggr_interval / \
			(ctx->attrs.sample_interval ?  ctx->attrs.sample_interval : 1);
	damon_for_each_target(t, ctx) {
		damon_for_each_region(r, t) {
			unsigned int incbp = factor * (metapebs.max_nr_samples ? \
					(10000 * r->nr_pebs_samples / metapebs.max_nr_samples) : 0);
			unsigned int decbp = 10000 * r->last_nr_accesses;
			int delta = incbp - decbp;

			if (delta + r->nr_accesses_bp <= 0)
				r->nr_accesses_bp = 0;
			else
				r->nr_accesses_bp += delta;

			r->nr_accesses = r->nr_accesses_bp / 10000;
			max_nr_accesses = max(r->nr_accesses, max_nr_accesses);
			r->nr_pebs_samples = 0;
			r->pebs_sample_period_sum = 0;
		}
	}

	metapebs.max_nr_samples = 0;
	metapebs.max_sample_period_sum = 0;

	return max_nr_accesses;
}

static unsigned int damon_pa_check_accesses(struct damon_ctx *ctx)
{
	unsigned int sample_batchsz = 1000, ret = 0, nr_samples;
	unsigned long sample_period_sum = 0;
	struct damon_pebs_sample *sample;
	struct perf_event *event;
	struct cpumask *cpumask;

	cpumask = kzalloc(sizeof(struct cpumask), GFP_KERNEL | __GFP_NOWARN);
	if (!cpumask) {
		goto out_mask;
	}
	damon_get_pebs_cpus(cpumask);

	for (int ev = 0; ev < NR_DAMON_PEBS_EVENTS; ++ev) {
		int cpu = -1;
		while ((cpu = cpumask_next(cpu, cpumask)) < MAX_PEBS_CPUS) {
			/* Read PEBS data */
			int pos = ev * MAX_PEBS_CPUS + cpu;
			event = *(ctx->pebs_ctx.pebs_events + pos);
			__sync_synchronize();

			ret = perf_setup_event_for_reading(event);
			if (ret)
				continue;

			for (int i = 0; i < sample_batchsz; ++i) {
				sample = perf_get_event_sample(&ret);
				if (ret == -ENOENT) {
					/* No more samples in buffer */
					break;
				} else if (ret == -EINVAL) {
					/* Bad sample; skipping */
					goto put_sample;
				}

				if(__damon_pa_check_access_sample(ctx, sample)) {
					sample_period_sum += sample->period;
					++nr_samples;
				}
put_sample:
				smp_mb();
				perf_put_event_sample();
			}
			perf_free_event_reader();
		}
	}

out_mask:
	return 0;
}

static bool __damos_pa_filter_out(struct damos_filter *filter,
		struct folio *folio)
{
	bool matched = false;
	struct mem_cgroup *memcg;

	switch (filter->type) {
	case DAMOS_FILTER_TYPE_ANON:
		matched = folio_test_anon(folio);
		break;
	case DAMOS_FILTER_TYPE_MEMCG:
		rcu_read_lock();
		memcg = folio_memcg_check(folio);
		if (!memcg)
			matched = false;
		else
			matched = filter->memcg_id == mem_cgroup_id(memcg);
		rcu_read_unlock();
		break;
	case DAMOS_FILTER_TYPE_YOUNG:
		matched = damon_folio_young(folio);
		if (matched)
			damon_folio_mkold(folio);
		break;
	default:
		break;
	}

	return matched == filter->matching;
}

/*
 * damos_pa_filter_out - Return true if the page should be filtered out.
 */
static bool damos_pa_filter_out(struct damos *scheme, struct folio *folio)
{
	struct damos_filter *filter;

	damos_for_each_filter(filter, scheme) {
		if (__damos_pa_filter_out(filter, folio))
			return true;
	}
	return false;
}

static unsigned long damon_pa_pageout(struct damon_region *r, struct damos *s)
{
	unsigned long addr, applied;
	LIST_HEAD(folio_list);
	bool install_young_filter = true;
	struct damos_filter *filter;

	/* check access in page level again by default */
	damos_for_each_filter(filter, s) {
		if (filter->type == DAMOS_FILTER_TYPE_YOUNG) {
			install_young_filter = false;
			break;
		}
	}
	if (install_young_filter) {
		filter = damos_new_filter(DAMOS_FILTER_TYPE_YOUNG, true);
		if (!filter)
			return 0;
		damos_add_filter(s, filter);
	}

	for (addr = r->ar.start; addr < r->ar.end; addr += PAGE_SIZE) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio)
			continue;

		if (damos_pa_filter_out(s, folio))
			goto put_folio;

		folio_clear_referenced(folio);
		folio_test_clear_young(folio);
		if (!folio_isolate_lru(folio))
			goto put_folio;
		if (folio_test_unevictable(folio))
			folio_putback_lru(folio);
		else
			list_add(&folio->lru, &folio_list);
put_folio:
		folio_put(folio);
	}
	if (install_young_filter)
		damos_destroy_filter(filter);
	applied = reclaim_pages(&folio_list);
	cond_resched();
	return applied * PAGE_SIZE;
}

static inline unsigned long damon_pa_mark_accessed_or_deactivate(
		struct damon_region *r, struct damos *s, bool mark_accessed)
{
	unsigned long addr, applied = 0;

	for (addr = r->ar.start; addr < r->ar.end; addr += PAGE_SIZE) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio)
			continue;

		if (damos_pa_filter_out(s, folio))
			goto put_folio;

		if (mark_accessed)
			folio_mark_accessed(folio);
		else
			folio_deactivate(folio);
		applied += folio_nr_pages(folio);
put_folio:
		folio_put(folio);
	}
	return applied * PAGE_SIZE;
}

static unsigned long damon_pa_mark_accessed(struct damon_region *r,
	struct damos *s)
{
	return damon_pa_mark_accessed_or_deactivate(r, s, true);
}

static unsigned long damon_pa_deactivate_pages(struct damon_region *r,
	struct damos *s)
{
	return damon_pa_mark_accessed_or_deactivate(r, s, false);
}

static unsigned int __damon_pa_migrate_folio_list(
		struct list_head *migrate_folios, struct pglist_data *pgdat,
		int target_nid)
{
	unsigned int nr_succeeded = 0;
	nodemask_t allowed_mask = NODE_MASK_NONE;
	struct migration_target_control mtc = {
		/*
		 * Allocate from 'node', or fail quickly and quietly.
		 * When this happens, 'page' will likely just be discarded
		 * instead of migrated.
		 */
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) |
			__GFP_NOWARN | __GFP_NOMEMALLOC | GFP_NOWAIT,
		.nid = target_nid,
		.nmask = &allowed_mask
	};

	if (pgdat->node_id == target_nid || target_nid == NUMA_NO_NODE)
		return 0;

	if (list_empty(migrate_folios))
		return 0;

	/* Migration ignores all cpuset and mempolicy settings */
	migrate_pages(migrate_folios, alloc_migrate_folio, NULL,
		      (unsigned long)&mtc, MIGRATE_ASYNC, MR_DAMON,
		      &nr_succeeded);

	return nr_succeeded;
}

static unsigned int damon_pa_migrate_folio_list(struct list_head *folio_list,
						struct pglist_data *pgdat,
						int target_nid)
{
	unsigned int nr_migrated = 0;
	struct folio *folio;
	LIST_HEAD(ret_folios);
	LIST_HEAD(migrate_folios);

	while (!list_empty(folio_list)) {
		struct folio *folio;

		cond_resched();

		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);

		if (!folio_trylock(folio))
			goto keep;

		/* Relocate its contents to another node. */
		list_add(&folio->lru, &migrate_folios);
		folio_unlock(folio);
		continue;
keep:
		list_add(&folio->lru, &ret_folios);
	}
	/* 'folio_list' is always empty here */

	/* Migrate folios selected for migration */
	nr_migrated += __damon_pa_migrate_folio_list(
			&migrate_folios, pgdat, target_nid);
	/*
	 * Folios that could not be migrated are still in @migrate_folios.  Add
	 * those back on @folio_list
	 */
	if (!list_empty(&migrate_folios))
		list_splice_init(&migrate_folios, folio_list);

	try_to_unmap_flush();

	list_splice(&ret_folios, folio_list);

	while (!list_empty(folio_list)) {
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}

	return nr_migrated;
}

unsigned long damon_pa_migrate_pages(struct list_head *folio_list,
					    int target_nid)
{
	int nid;
	unsigned long nr_migrated = 0;
	LIST_HEAD(node_folio_list);
	unsigned int noreclaim_flag;

	if (list_empty(folio_list))
		return nr_migrated;

	noreclaim_flag = memalloc_noreclaim_save();

	nid = folio_nid(lru_to_folio(folio_list));
	do {
		struct folio *folio = lru_to_folio(folio_list);

		if (nid == folio_nid(folio)) {
			list_move(&folio->lru, &node_folio_list);
			continue;
		}

		nr_migrated += damon_pa_migrate_folio_list(&node_folio_list,
							   NODE_DATA(nid),
							   target_nid);
		nid = folio_nid(lru_to_folio(folio_list));
	} while (!list_empty(folio_list));

	nr_migrated += damon_pa_migrate_folio_list(&node_folio_list,
						   NODE_DATA(nid),
						   target_nid);

	memalloc_noreclaim_restore(noreclaim_flag);

	return nr_migrated;
}

static unsigned long damon_pa_migrate(struct damon_region *r, struct damos *s)
{
	unsigned long addr, applied2, applied3, nid = 2;
	LIST_HEAD(folio_list_2);
	LIST_HEAD(folio_list_3);

	for (addr = r->ar.start; addr < r->ar.end; addr += PAGE_SIZE) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio)
			continue;

		if (damos_pa_filter_out(s, folio))
			goto put_folio;

		if (!folio_isolate_lru(folio))
			goto put_folio;
		if (nid == 2)
			list_add(&folio->lru, &folio_list_2);
		else
			list_add(&folio->lru, &folio_list_3);
		nid = (nid == 2) ? 3 : 2;
put_folio:
		folio_put(folio);
	}
	applied2 = damon_pa_migrate_pages(&folio_list_2, 2);
	applied3 = damon_pa_migrate_pages(&folio_list_3, 3);
	cond_resched();
	return (applied2 + applied3) * PAGE_SIZE;
}


static unsigned long damon_pa_apply_scheme(struct damon_ctx *ctx,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_pa_pageout(r, scheme);
	case DAMOS_LRU_PRIO:
		return damon_pa_mark_accessed(r, scheme);
	case DAMOS_LRU_DEPRIO:
		return damon_pa_deactivate_pages(r, scheme);
	case DAMOS_MIGRATE_HOT:
	case DAMOS_MIGRATE_COLD:
	case DAMOS_COLLOID_BASIC:
		return damon_pa_migrate(r, scheme);
	case DAMOS_STAT:
		break;
	default:
		/* DAMOS actions that not yet supported by 'paddr'. */
		break;
	}
	return 0;
}

static int damon_pa_scheme_score(struct damon_ctx *context,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_cold_score(context, r, scheme);
	case DAMOS_LRU_PRIO:
		return damon_hot_score(context, r, scheme);
	case DAMOS_LRU_DEPRIO:
		return damon_cold_score(context, r, scheme);
	case DAMOS_MIGRATE_HOT:
	case DAMOS_COLLOID_BASIC:
		return damon_hot_score(context, r, scheme);
	case DAMOS_MIGRATE_COLD:
		return damon_cold_score(context, r, scheme);
	default:
		break;
	}

	return DAMOS_MAX_SCORE;
}

static void damon_pa_init(struct damon_ctx *ctx)
{
	struct cpumask *cpumask;

	cpumask = kzalloc(sizeof(struct cpumask), GFP_KERNEL | __GFP_NOWARN);
	if (!cpumask)
		return;
	damon_get_pebs_cpus(cpumask);

	ctx->pebs_ctx.pebs_attrs.sample_freq = damon_get_pebs_freq();
	ctx->pebs_ctx.pebs_events = kzalloc(sizeof(struct perf_event *) * \
			MAX_PEBS_CPUS * NR_DAMON_PEBS_EVENTS, GFP_KERNEL | __GFP_NOWARN);

	for (int ev = 0; ev < NR_DAMON_PEBS_EVENTS; ++ev) {
		int cpu = -1;
		while ((cpu = cpumask_next(cpu, cpumask)) < MAX_PEBS_CPUS) {
			int pos = ev * MAX_PEBS_CPUS + cpu;
			int ret = perf_event_init_from_kernel(&(ctx->pebs_ctx.pebs_events[pos]),
			PEBS_SAMPLE_TYPE, DAMON_PEBS_EVENTS[ev], cpu, PEBS_EVENT_PAGES,
			ctx->pebs_ctx.pebs_attrs.sample_freq);
			if (ret)
				printk(KERN_ERR
						"[DAMON_PEBS] %d: Failed to initialize event %d on CPU %d\n",
						ret, ev, cpu);
		}
	}

	metapebs.max_nr_samples = 0;
	metapebs.max_sample_period_sum = 0;
}

static void damon_pa_cleanup(struct damon_ctx *ctx)
{
	if (!ctx->pebs_ctx.pebs_events)
		return;

	for (int ev = 0; ev < NR_DAMON_PEBS_EVENTS; ++ev) {
		for (int cpu = 0; cpu < MAX_PEBS_CPUS; ++cpu) {
			int pos = ev * MAX_PEBS_CPUS + cpu;
			if (!ctx->pebs_ctx.pebs_events[pos])
				continue;
			perf_event_release_kernel(ctx->pebs_ctx.pebs_events[pos]);
		}
	}
	kfree(ctx->pebs_ctx.pebs_events);
	ctx->pebs_ctx.pebs_events = NULL;
}

static int __init damon_pa_initcall(void)
{
	struct damon_operations ops = {
		.id = DAMON_OPS_PADDR,
		.init = damon_pa_init,
		.update = NULL,
		.prepare_access_checks = NULL,
		.check_accesses = damon_pa_check_accesses,
		.pre_aggregation = damon_update_nr_accesses,
		.reset_aggregated = NULL,
		.target_valid = NULL,
		.cleanup = damon_pa_cleanup,
		.apply_scheme = damon_pa_apply_scheme,
		.get_scheme_score = damon_pa_scheme_score,
	};

	damon_set_pebs_freq(PEBS_FREQ);
	damon_setall_pebs_cpus();

	return damon_register_ops(&ops);
};

subsys_initcall(damon_pa_initcall);
