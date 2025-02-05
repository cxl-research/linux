// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON Primitives for Virtual Address Spaces
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

#define pr_fmt(fmt) "damon-va: " fmt

#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>

#include "../internal.h"
#include "ops-common.h"

#ifdef CONFIG_DAMON_VADDR_KUNIT_TEST
#undef DAMON_MIN_REGION
#define DAMON_MIN_REGION 1
#endif

static const uint64_t DAMON_PEBS_EVENTS[] = {
	LLC_MISS_LOADS_EVENT,
	ALL_STORES_EVENT
};

struct aggregation_metadata {
	unsigned int max_nr_samples;
	unsigned int max_sample_period_sum;
} metapebs_vaddr;

/*
 * 't->pid' should be the pointer to the relevant 'struct pid' having reference
 * count.  Caller must put the returned task, unless it is NULL.
 */
static inline struct task_struct *damon_get_task_struct(struct damon_target *t)
{
	return get_pid_task(t->pid, PIDTYPE_PID);
}

/*
 * Get the mm_struct of the given target
 *
 * Caller _must_ put the mm_struct after use, unless it is NULL.
 *
 * Returns the mm_struct of the target on success, NULL on failure
 */
static struct mm_struct *damon_get_mm(struct damon_target *t)
{
	struct task_struct *task;
	struct mm_struct *mm;

	task = damon_get_task_struct(t);
	if (!task)
		return NULL;

	mm = get_task_mm(task);
	put_task_struct(task);
	return mm;
}

/*
 * Functions for the initial monitoring target regions construction
 */

/*
 * Size-evenly split a region into 'nr_pieces' small regions
 *
 * Returns 0 on success, or negative error code otherwise.
 */
static int damon_va_evenly_split_region(struct damon_target *t,
		struct damon_region *r, unsigned int nr_pieces)
{
	unsigned long sz_orig, sz_piece, orig_end;
	struct damon_region *n = NULL, *next;
	unsigned long start;
	unsigned int i;

	if (!r || !nr_pieces)
		return -EINVAL;

	if (nr_pieces == 1)
		return 0;

	orig_end = r->ar.end;
	sz_orig = damon_sz_region(r);
	sz_piece = ALIGN_DOWN(sz_orig / nr_pieces, DAMON_MIN_REGION);

	if (!sz_piece)
		return -EINVAL;

	r->ar.end = r->ar.start + sz_piece;
	next = damon_next_region(r);
	for (start = r->ar.end, i = 1; i < nr_pieces; start += sz_piece, i++) {
		n = damon_new_region(start, start + sz_piece);
		if (!n)
			return -ENOMEM;
		damon_insert_region(n, r, next, t);
		r = n;
	}
	/* complement last region for possible rounding error */
	if (n)
		n->ar.end = orig_end;

	return 0;
}

static unsigned long sz_range(struct damon_addr_range *r)
{
	return r->end - r->start;
}

/*
 * Find three regions separated by two biggest unmapped regions
 *
 * vma		the head vma of the target address space
 * regions	an array of three address ranges that results will be saved
 *
 * This function receives an address space and finds three regions in it which
 * separated by the two biggest unmapped regions in the space.  Please refer to
 * below comments of '__damon_va_init_regions()' function to know why this is
 * necessary.
 *
 * Returns 0 if success, or negative error code otherwise.
 */
static int __damon_va_three_regions(struct mm_struct *mm,
				       struct damon_addr_range regions[3])
{
	struct damon_addr_range first_gap = {0}, second_gap = {0};
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma, *prev = NULL;
	unsigned long start;

	/*
	 * Find the two biggest gaps so that first_gap > second_gap > others.
	 * If this is too slow, it can be optimised to examine the maple
	 * tree gaps.
	 */
	rcu_read_lock();
	for_each_vma(vmi, vma) {
		unsigned long gap;

		if (!prev) {
			start = vma->vm_start;
			goto next;
		}
		gap = vma->vm_start - prev->vm_end;

		if (gap > sz_range(&first_gap)) {
			second_gap = first_gap;
			first_gap.start = prev->vm_end;
			first_gap.end = vma->vm_start;
		} else if (gap > sz_range(&second_gap)) {
			second_gap.start = prev->vm_end;
			second_gap.end = vma->vm_start;
		}
next:
		prev = vma;
	}
	rcu_read_unlock();

	if (!sz_range(&second_gap) || !sz_range(&first_gap))
		return -EINVAL;

	/* Sort the two biggest gaps by address */
	if (first_gap.start > second_gap.start)
		swap(first_gap, second_gap);

	/* Store the result */
	regions[0].start = ALIGN(start, DAMON_MIN_REGION);
	regions[0].end = ALIGN(first_gap.start, DAMON_MIN_REGION);
	regions[1].start = ALIGN(first_gap.end, DAMON_MIN_REGION);
	regions[1].end = ALIGN(second_gap.start, DAMON_MIN_REGION);
	regions[2].start = ALIGN(second_gap.end, DAMON_MIN_REGION);
	regions[2].end = ALIGN(prev->vm_end, DAMON_MIN_REGION);

	return 0;
}

/*
 * Get the three regions in the given target (task)
 *
 * Returns 0 on success, negative error code otherwise.
 */
int damon_va_three_regions(struct damon_target *t,
				struct damon_addr_range regions[3])
{
	struct mm_struct *mm;
	int rc;

	mm = damon_get_mm(t);
	if (!mm)
		return -EINVAL;

	mmap_read_lock(mm);
	rc = __damon_va_three_regions(mm, regions);
	mmap_read_unlock(mm);

	mmput(mm);
	return rc;
}

/*
 * Initialize the monitoring target regions for the given target (task)
 *
 * t	the given target
 *
 * Because only a number of small portions of the entire address space
 * is actually mapped to the memory and accessed, monitoring the unmapped
 * regions is wasteful.  That said, because we can deal with small noises,
 * tracking every mapping is not strictly required but could even incur a high
 * overhead if the mapping frequently changes or the number of mappings is
 * high.  The adaptive regions adjustment mechanism will further help to deal
 * with the noise by simply identifying the unmapped areas as a region that
 * has no access.  Moreover, applying the real mappings that would have many
 * unmapped areas inside will make the adaptive mechanism quite complex.  That
 * said, too huge unmapped areas inside the monitoring target should be removed
 * to not take the time for the adaptive mechanism.
 *
 * For the reason, we convert the complex mappings to three distinct regions
 * that cover every mapped area of the address space.  Also the two gaps
 * between the three regions are the two biggest unmapped areas in the given
 * address space.  In detail, this function first identifies the start and the
 * end of the mappings and the two biggest unmapped areas of the address space.
 * Then, it constructs the three regions as below:
 *
 *     [mappings[0]->start, big_two_unmapped_areas[0]->start)
 *     [big_two_unmapped_areas[0]->end, big_two_unmapped_areas[1]->start)
 *     [big_two_unmapped_areas[1]->end, mappings[nr_mappings - 1]->end)
 *
 * As usual memory map of processes is as below, the gap between the heap and
 * the uppermost mmap()-ed region, and the gap between the lowermost mmap()-ed
 * region and the stack will be two biggest unmapped regions.  Because these
 * gaps are exceptionally huge areas in usual address space, excluding these
 * two biggest unmapped regions will be sufficient to make a trade-off.
 *
 *   <heap>
 *   <BIG UNMAPPED REGION 1>
 *   <uppermost mmap()-ed region>
 *   (other mmap()-ed regions and small unmapped regions)
 *   <lowermost mmap()-ed region>
 *   <BIG UNMAPPED REGION 2>
 *   <stack>
 */
static void __damon_va_init_regions(struct damon_ctx *ctx,
				     struct damon_target *t)
{
	struct damon_target *ti;
	struct damon_region *r;
	struct damon_addr_range regions[3];
	unsigned long sz = 0, nr_pieces;
	int i, tidx = 0;

	if (damon_va_three_regions(t, regions)) {
		damon_for_each_target(ti, ctx) {
			if (ti == t)
				break;
			tidx++;
		}
		pr_debug("Failed to get three regions of %dth target\n", tidx);
		return;
	}

	for (i = 0; i < 3; i++)
		sz += regions[i].end - regions[i].start;
	if (ctx->attrs.min_nr_regions)
		sz /= ctx->attrs.min_nr_regions;
	if (sz < DAMON_MIN_REGION)
		sz = DAMON_MIN_REGION;

	/* Set the initial three regions of the target */
	for (i = 0; i < 3; i++) {
		r = damon_new_region(regions[i].start, regions[i].end);
		if (!r) {
			pr_err("%d'th init region creation failed\n", i);
			return;
		}
		damon_add_region(r, t);

		nr_pieces = (regions[i].end - regions[i].start) / sz;
		damon_va_evenly_split_region(t, r, nr_pieces);
	}
}

static void damon_va_init_pebs(struct damon_ctx *ctx)
{
	struct cpumask *cpumask;

	cpumask = kzalloc(sizeof(struct cpumask), GFP_KERNEL | __GFP_NOWARN);
	if (!cpumask)
		return;
	damon_get_pebs_cpus(cpumask);
	ctx->pebs_ctx.pebs_attrs.sample_freq = damon_get_pebs_freq();
	ctx->pebs_ctx.pebs_events = kzalloc(sizeof(struct perf_event *) *
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
					"[DAMON_VADDR] %d: Failed to initialize event %d on CPU %d\n",
					ret, ev, cpu);
		}
	}
}


/* Initialize '->regions_list' of every target (task) */
static void damon_va_init(struct damon_ctx *ctx)
{
	struct damon_target *t;

	damon_for_each_target(t, ctx) {
		/* the user may set the target regions as they want */
		if (!damon_nr_regions(t))
			__damon_va_init_regions(ctx, t);
	}
	damon_va_init_pebs(ctx);
}

/*
 * Update regions for current memory mappings
 */
static void damon_va_update(struct damon_ctx *ctx)
{
	struct damon_addr_range three_regions[3];
	struct damon_target *t;

	damon_for_each_target(t, ctx) {
		if (damon_va_three_regions(t, three_regions))
			continue;
		damon_set_regions(t, three_regions, 3);
	}
}

static void __damon_va_check_access(struct damon_region *r,
		struct damon_attrs *attrs, struct damon_pebs_sample *s)
{
	r->nr_pebs_samples++;
	r->pebs_sample_period_sum += s->period;

	if (r->nr_pebs_samples > metapebs_vaddr.max_nr_samples)
		metapebs_vaddr.max_nr_samples = r->nr_pebs_samples;
	if (r->pebs_sample_period_sum > metapebs_vaddr.max_sample_period_sum)
		metapebs_vaddr.max_sample_period_sum = r->pebs_sample_period_sum;
}

static bool __damon_va_check_access_sample(struct damon_ctx *ctx,
			struct damon_pebs_sample *sample)
{
	struct damon_target *t;
	struct damon_region *r;

	damon_for_each_target(t, ctx) {
		if (t->pid != find_get_pid(sample->pid))
			continue;
		damon_for_each_region(r, t) {
			if (r->ar.start <= sample->address && sample->address < r->ar.end) {
				__damon_va_check_access(r, &ctx->attrs, sample);
				return true;
			}
		}
		return false;
	}

	return false;
}

static unsigned int damon_va_check_accesses(struct damon_ctx *ctx)
{
	unsigned int batchsz = 100, ret = 0, nr_samples = 0;
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

			for (int i = 0; i < batchsz; ++i) {
				sample = perf_get_event_sample(&ret);
				if (ret == -ENOENT) {
					/* No more samples in buffer */
					break;
				} else if (ret == -EINVAL || !sample->address) {
					/* Bad sample; skipping */
					goto put_sample;
				}

				if(__damon_va_check_access_sample(ctx, sample)) {
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

static unsigned int damon_update_nr_accesses(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct damon_region *r;
	unsigned int max_nr_accesses = 0, factor;

	factor = ctx->attrs.aggr_interval / \
			(ctx->attrs.sample_interval ?  ctx->attrs.sample_interval : 1);
	damon_for_each_target(t, ctx) {
		damon_for_each_region(r, t) {
			unsigned int incbp = factor * (metapebs_vaddr.max_nr_samples ? \
					(10000 * r->nr_pebs_samples / metapebs_vaddr.max_nr_samples) : 0);
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

	metapebs_vaddr.max_nr_samples = 0;
	metapebs_vaddr.max_sample_period_sum = 0;
	return max_nr_accesses;
}

/*
 * Functions for the target validity check and cleanup
 */

static bool damon_va_target_valid(struct damon_target *t)
{
	struct task_struct *task;

	task = damon_get_task_struct(t);
	if (task) {
		put_task_struct(task);
		return true;
	}

	return false;
}

static void damon_va_cleanup(struct damon_ctx *ctx)
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

#ifndef CONFIG_ADVISE_SYSCALLS
static unsigned long damos_madvise(struct damon_target *target,
		struct damon_region *r, int behavior)
{
	return 0;
}
#else
static unsigned long damos_madvise(struct damon_target *target,
		struct damon_region *r, int behavior)
{
	struct mm_struct *mm;
	unsigned long start = PAGE_ALIGN(r->ar.start);
	unsigned long len = PAGE_ALIGN(damon_sz_region(r));
	unsigned long applied;

	mm = damon_get_mm(target);
	if (!mm)
		return 0;

	applied = do_madvise(mm, start, len, behavior) ? 0 : len;
	mmput(mm);

	return applied;
}
#endif	/* CONFIG_ADVISE_SYSCALLS */

struct damon_migrate_list {
	struct list_head folio_2;
	struct list_head folio_3;
};

static int damon_add_to_migrate_list(pte_t *pte, unsigned long addr,
			unsigned long next, struct mm_walk *walk)
{
	struct damon_migrate_list *migrate_list = walk->private;
	struct folio *folio;
	static char nid = 2;

	if (!pte_present(*pte))
		return 0;

	folio = damon_get_folio(pte_pfn(*pte));
	if (!folio)
		return 0;

	if (!folio_isolate_lru(folio))
		goto put_folio;

	if (nid == 2)
		list_add(&folio->lru, &migrate_list->folio_2);
	else
		list_add(&folio->lru, &migrate_list->folio_3);
	nid = (nid == 2) ? 3 : 2;

put_folio:
	folio_put(folio);
	return 0;
}

static const struct mm_walk_ops migrate_ops = {
	.pte_entry = damon_add_to_migrate_list,
	.walk_lock = PGWALK_RDLOCK,
};

static unsigned long damon_va_migrate(struct damon_target *t,
			struct damon_region *r, struct damos *scheme)
{
	struct mm_struct *mm;
	unsigned long start = PAGE_ALIGN(r->ar.start);
	unsigned long len = PAGE_ALIGN(damon_sz_region(r));
	unsigned long migrated2 = 0, migrated3 = 0;
	struct damon_migrate_list to_migrate = {
		.folio_2 = LIST_HEAD_INIT(to_migrate.folio_2),
		.folio_3 = LIST_HEAD_INIT(to_migrate.folio_3),
	};

	mm = damon_get_mm(t);
	if (!mm)
		return 0;

	mmap_read_lock(mm);
	walk_page_range(mm, start, start + len, &migrate_ops, &to_migrate);
	mmap_read_unlock(mm);
	mmput(mm);

	migrated2 = damon_pa_migrate_pages(&to_migrate.folio_2, 2);
	migrated3 = damon_pa_migrate_pages(&to_migrate.folio_3, 3);
	cond_resched();

	return (migrated2 + migrated3) * PAGE_SIZE;
}

static unsigned long damon_va_apply_scheme(struct damon_ctx *ctx,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	int madv_action;

	switch (scheme->action) {
	case DAMOS_WILLNEED:
		madv_action = MADV_WILLNEED;
		break;
	case DAMOS_COLD:
		madv_action = MADV_COLD;
		break;
	case DAMOS_PAGEOUT:
		madv_action = MADV_PAGEOUT;
		break;
	case DAMOS_HUGEPAGE:
		madv_action = MADV_HUGEPAGE;
		break;
	case DAMOS_NOHUGEPAGE:
		madv_action = MADV_NOHUGEPAGE;
		break;
	case DAMOS_STAT:
		return 0;
	case DAMOS_COLLOID_BASIC:
		return damon_va_migrate(t, r, scheme);
	default:
		/*
		 * DAMOS actions that are not yet supported by 'vaddr'.
		 */
		return 0;
	}

	return damos_madvise(t, r, madv_action);
}

static int damon_va_scheme_score(struct damon_ctx *context,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{

	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_cold_score(context, r, scheme);
	case DAMOS_COLLOID_BASIC:
		return damon_hot_score(context, r, scheme);
	default:
		break;
	}

	return DAMOS_MAX_SCORE;
}

static int __init damon_va_initcall(void)
{
	struct damon_operations ops = {
		.id = DAMON_OPS_VADDR,
		.init = damon_va_init,
		.update = damon_va_update,
		.prepare_access_checks = NULL,
		.check_accesses = damon_va_check_accesses,
		.pre_aggregation = damon_update_nr_accesses,
		.reset_aggregated = NULL,
		.target_valid = damon_va_target_valid,
		.cleanup = damon_va_cleanup,
		.apply_scheme = damon_va_apply_scheme,
		.get_scheme_score = damon_va_scheme_score,
	};
	/* ops for fixed virtual address ranges */
	struct damon_operations ops_fvaddr = ops	;
	int err;

	/* Don't set the monitoring target regions for the entire mapping */
	ops_fvaddr.id = DAMON_OPS_FVADDR;
	ops_fvaddr.init = NULL;
	ops_fvaddr.update = NULL;

	damon_set_pebs_freq(PEBS_FREQ);
	damon_setall_pebs_cpus();

	err = damon_register_ops(&ops);
	if (err)
		return err;
	return damon_register_ops(&ops_fvaddr);
};

subsys_initcall(damon_va_initcall);

#include "tests/vaddr-kunit.h"
