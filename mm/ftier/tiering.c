// SPDX-License-Identifier: GPL-2.0
/*
 * FTier memory tiering: candidate selection and data migration.
 *
 * Every tick, the target migration rate set by the tier latency monitor
 * (sysctl_promote_mb, MB/s, capped by max_migrate_mbps) is converted to
 * a page budget. Candidates are PMD entries taken from the Hotlist,
 * starting at a hotness level adapted to the response of the tier
 * latencies (adapt_level()). Depending on the tiering mode, the pages of
 * a candidate that sit on the source tier are either migrated right away
 * (demand_migrate) or protected so that their next access raises a hint
 * fault, which migrates them if the hint-fault latency is low enough
 * (hint_fault).
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/mmu_notifier.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>
#include <linux/sort.h>
#include <linux/swap.h>
#include <linux/vmstat.h>

#include <asm/tlb.h>

#include "../internal.h"
#include "internal.h"

#include <trace/events/ftier.h>

struct tier_round {
	bool promote;
	nodemask_t src;
	nodemask_t dst;
	int next_dst;
	enum ftier_tiering_mode mode;
	unsigned long max_pages;
	unsigned long nr_pages;		/* migrated or protected */
	unsigned long nr_failed;
	unsigned int nr_regions;
	unsigned int nr_skipped;
};

static void set_tiering_nodes(struct tier_round *r)
{
	r->src = r->promote ? ftier_cxl_nodes : ftier_dram_nodes;
	r->dst = r->promote ? ftier_dram_nodes : ftier_cxl_nodes;
	r->next_dst = NUMA_NO_NODE;
}

/* Round-robin over the destination tier. */
static int next_dst_node(struct tier_round *r)
{
	int nid = next_node_in(r->next_dst, r->dst);

	if (nid >= MAX_NUMNODES)
		return NUMA_NO_NODE;
	r->next_dst = nid;
	return nid;
}

static bool src_node(const struct tier_round *r, int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES && node_isset(nid, r->src);
}

static bool dst_node(const struct tier_round *r, int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES && node_isset(nid, r->dst);
}

/* ---------------------------------------------------------------------
 * Residency hints: skip regions recently found to have nothing to move.
 * FTier's own migrations keep them up to date, so they only go stale when
 * pages move or are allocated outside FTier; residency_epochs bounds that.
 */

static u8 hot_stamp(const struct ftier_hotlist *hl)
{
	return hl->epoch & 0x1f;
}

#define FTIER_HOT_STAMP_SHIFT	2

static bool residency_valid(const struct ftier_hotlist *hl,
			    const struct ftier_hot *hot)
{
	u8 stamp = hot->flags >> FTIER_HOT_STAMP_SHIFT;

	return ((hot_stamp(hl) - stamp) & 0x1f) <= FTIER_CFG(residency_epochs);
}

static bool region_has_no_src(const struct ftier_hotlist *hl,
			      const struct ftier_hot *hot, bool promote)
{
	u8 bit = promote ? FTIER_HOT_NO_CXL : FTIER_HOT_NO_DRAM;

	return (hot->flags & bit) && residency_valid(hl, hot);
}

static void set_residency(const struct ftier_hotlist *hl,
			  struct ftier_hot *hot, bool no_dram, bool no_cxl)
{
	hot->flags = (hot_stamp(hl) << FTIER_HOT_STAMP_SHIFT) |
		     (no_dram ? FTIER_HOT_NO_DRAM : 0) |
		     (no_cxl ? FTIER_HOT_NO_CXL : 0);
}

/* ---------------------------------------------------------------------
 * Demand migration.
 */

struct gather {
	struct tier_round *r;
	struct list_head folios;
	struct folio *last;		/* PTE-mapped large folios */
	unsigned long nr_isolated;	/* pages */
	unsigned long nr_src;		/* pages seen on the source tier */
	unsigned long nr_dst;		/* pages seen on the destination tier */
};

static void gather_folio(struct gather *g, struct folio *folio)
{
	int nid = folio_nid(folio);

	if (folio == g->last)
		return;
	g->last = folio;

	if (!src_node(g->r, nid)) {
		if (dst_node(g->r, nid))
			g->nr_dst += folio_nr_pages(folio);
		return;
	}
	g->nr_src += folio_nr_pages(folio);

	if (g->r->nr_pages + g->nr_isolated >= g->r->max_pages)
		return;
	/* Like mbind(MPOL_MF_MOVE): leave folios shared with others alone. */
	if (folio_maybe_mapped_shared(folio))
		return;
	if (!folio_isolate_lru(folio))
		return;
	list_add_tail(&folio->lru, &g->folios);
	node_stat_mod_folio(folio, NR_ISOLATED_ANON + folio_is_file_lru(folio),
			    folio_nr_pages(folio));
	g->nr_isolated += folio_nr_pages(folio);
}

static int gather_pmd_entry(pmd_t *pmd, unsigned long addr,
			    unsigned long end, struct mm_walk *walk)
{
	struct gather *g = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct folio *folio;
	spinlock_t *ptl;
	pte_t *start_pte, *pte, ptent;

	walk->action = ACTION_CONTINUE;

	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		pmd_t val = pmdp_get(pmd);

		if (pmd_present(val) && !is_huge_zero_pmd(val)) {
			folio = pmd_folio(val);
			gather_folio(g, folio);
		}
		spin_unlock(ptl);
		return 0;
	}

	start_pte = pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
	if (!pte)
		return 0;
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		ptent = ptep_get(pte);
		if (!pte_present(ptent))
			continue;
		folio = vm_normal_folio(vma, addr, ptent);
		if (!folio || folio_is_zone_device(folio))
			continue;
		gather_folio(g, folio);
	}
	pte_unmap_unlock(start_pte, ptl);
	cond_resched();
	return 0;
}

static int gather_test_walk(unsigned long start, unsigned long end,
			    struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->vma;

	if (!vma_migratable(vma) || is_vm_hugetlb_page(vma) ||
	    (vma->vm_flags & (VM_MIXEDMAP | VM_PFNMAP)))
		return 1;
	return 0;
}

static const struct mm_walk_ops gather_ops = {
	.pmd_entry = gather_pmd_entry,
	.test_walk = gather_test_walk,
	.walk_lock = PGWALK_RDLOCK,
};

static unsigned long migrate_gathered(struct tier_round *r,
				      struct list_head *folios)
{
	struct migration_target_control mtc = {
		/* No direct reclaim from FTier; wake kswapd on the target. */
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) |
			    __GFP_KSWAPD_RECLAIM | __GFP_NOWARN |
			    __GFP_NOMEMALLOC | __GFP_NORETRY,
		.reason = MR_FTIER,
	};
	unsigned int batch = max(FTIER_CFG(migrate_batch), 1U);
	nodemask_t allowed = NODE_MASK_NONE;
	unsigned long nr_done = 0;
	unsigned int n, succeeded;
	LIST_HEAD(batch_list);
	struct folio *folio;

	mtc.nmask = &allowed;
	while (!list_empty(folios)) {
		for (n = 0; n < batch && !list_empty(folios); n++) {
			folio = list_first_entry(folios, struct folio, lru);
			list_move_tail(&folio->lru, &batch_list);
		}
		mtc.nid = next_dst_node(r);
		if (mtc.nid == NUMA_NO_NODE)
			break;
		succeeded = 0;
		migrate_pages(&batch_list, alloc_migrate_folio, NULL,
			      (unsigned long)&mtc, MIGRATE_ASYNC, MR_FTIER,
			      &succeeded);
		if (!list_empty(&batch_list))
			putback_movable_pages(&batch_list);
		nr_done += succeeded;
	}
	if (!list_empty(&batch_list))
		putback_movable_pages(&batch_list);
	if (!list_empty(folios))
		putback_movable_pages(folios);
	return nr_done;
}

/* Called with mmap_read_lock(mm) held; drops it. */
static long demand_migrate(struct tier_round *r, struct mm_struct *mm,
			   struct ftier_hot *hot)
{
	unsigned long start = ftier_hot_addr(hot);
	struct gather g = { .r = r, .folios = LIST_HEAD_INIT(g.folios) };
	unsigned long done;

	walk_page_range(mm, start, start + PMD_SIZE, &gather_ops, &g);
	/* Migration does not need the lock: do not hold up writers. */
	mmap_read_unlock(mm);

	if (!g.nr_isolated) {
		set_residency(&ftier_ctx.hotlist, hot,
			      r->promote ? !g.nr_dst : !g.nr_src,
			      r->promote ? !g.nr_src : !g.nr_dst);
		trace_fregion(hot->pud->space->tgid, start, r->promote, false,
			      g.nr_src, g.nr_dst, 0, 0);
		return 0;
	}
	done = migrate_gathered(r, &g.folios);
	trace_fregion(hot->pud->space->tgid, start, r->promote, false,
		      g.nr_src, g.nr_dst, g.nr_isolated, done);
	r->nr_failed += g.nr_isolated - min(done, g.nr_isolated);
	if (done == g.nr_src)
		set_residency(&ftier_ctx.hotlist, hot, !r->promote, r->promote);
	return done;
}

/* ---------------------------------------------------------------------
 * Hint-fault protection.
 */

static long protect_pte_range(struct mmu_gather *tlb, struct tier_round *r,
			      struct vm_area_struct *vma, pmd_t *pmd,
			      unsigned long addr, unsigned long end,
			      unsigned long *nr_src)
{
	pte_t *start_pte, *pte, oldpte, newpte;
	struct folio *folio;
	spinlock_t *ptl;
	long pages = 0;

	tlb_change_page_size(tlb, PAGE_SIZE);
	start_pte = pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!pte)
		return 0;

	flush_tlb_batched_pending(vma->vm_mm);
	arch_enter_lazy_mmu_mode();
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		oldpte = ptep_get(pte);
		if (!pte_present(oldpte))
			continue;
		/* Protected earlier and still waiting for its hint fault. */
		if (pte_protnone(oldpte)) {
			(*nr_src)++;
			continue;
		}

		folio = vm_normal_folio(vma, addr, oldpte);
		if (!folio || folio_is_zone_device(folio) ||
		    folio_test_ksm(folio))
			continue;
		/* Also skip shared copy-on-write pages */
		if (is_cow_mapping(vma->vm_flags) &&
		    (folio_maybe_dma_pinned(folio) ||
		     folio_maybe_mapped_shared(folio)))
			continue;
		/* Dirty file folios cannot always move with MIGRATE_ASYNC. */
		if (folio_is_file_lru(folio) && folio_test_dirty(folio))
			continue;
		if (!src_node(r, folio_nid(folio)))
			continue;
		(*nr_src)++;

		if (folio_use_access_time(folio))
			folio_xchg_access_time(folio, jiffies_to_msecs(jiffies));

		oldpte = ptep_modify_prot_start(vma, addr, pte);
		newpte = pte_modify(oldpte, PAGE_NONE);
		ptep_modify_prot_commit(vma, addr, pte, oldpte, newpte);
		if (pte_needs_flush(oldpte, newpte))
			tlb_flush_pte_range(tlb, addr, PAGE_SIZE);
		pages++;
	}
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(start_pte, ptl);
	return pages;
}

static long protect_vma_range(struct tier_round *r, struct vm_area_struct *vma,
			      unsigned long start, unsigned long end,
			      unsigned long *nr_src)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_notifier_range range;
	struct mmu_gather tlb;
	unsigned long addr, next;
	long pages = 0, ret;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, val;

	pgd = pgd_offset(mm, start);
	if (pgd_none_or_clear_bad(pgd))
		return 0;
	p4d = p4d_offset(pgd, start);
	if (p4d_none_or_clear_bad(p4d))
		return 0;
	pud = pud_offset(p4d, start);
	if (pud_none(*pud) || !pud_present(*pud) || pud_leaf(*pud))
		return 0;

	tlb_gather_mmu(&tlb, mm);
	tlb_start_vma(&tlb, vma);
	mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_VMA, 0,
				mm, start, end);
	mmu_notifier_invalidate_range_start(&range);

	pmd = pmd_offset(pud, start);
	for (addr = start; addr != end; pmd++, addr = next) {
		next = pmd_addr_end(addr, end);
		val = pmdp_get_lockless(pmd);
		if (pmd_none(val) || !pmd_present(val))
			continue;
		if (pmd_trans_huge(val)) {
			/* Only promotion: change_huge_pmd() skips top tier. */
			if (!r->promote || next - addr != PMD_SIZE)
				continue;
			/* Returns 1 if it left the entry alone. */
			ret = change_huge_pmd(&tlb, vma, pmd, addr, PAGE_NONE,
					      MM_CP_PROT_NUMA);
			if (ret == HPAGE_PMD_NR) {
				pages += HPAGE_PMD_NR;
				*nr_src += HPAGE_PMD_NR;
			} else if (pmd_protnone(val)) {
				*nr_src += HPAGE_PMD_NR;
			}
			continue;
		}
		pages += protect_pte_range(&tlb, r, vma, pmd, addr, next,
					   nr_src);
	}

	mmu_notifier_invalidate_range_end(&range);
	tlb_end_vma(&tlb, vma);
	tlb_finish_mmu(&tlb);
	return pages;
}

static long hint_protect(struct tier_round *r, struct mm_struct *mm,
			 struct ftier_hot *hot)
{
	unsigned long start = ftier_hot_addr(hot), end = start + PMD_SIZE;
	struct vm_area_struct *vma;
	unsigned long nr_src = 0;
	long pages = 0;
	VMA_ITERATOR(vmi, mm, start);

	for_each_vma_range(vmi, vma, end) {
		if (!vma_migratable(vma) || !vma_is_accessible(vma) ||
		    is_vm_hugetlb_page(vma) ||
		    (vma->vm_flags & (VM_MIXEDMAP | VM_PFNMAP)))
			continue;
		/* Shared libraries are read-only and shared: not worth it. */
		if (vma->vm_file &&
		    (vma->vm_flags & (VM_READ | VM_WRITE)) == VM_READ)
			continue;
		pages += protect_vma_range(r, vma, max(start, vma->vm_start),
					   min(end, vma->vm_end), &nr_src);
	}

	if (pages > 0) {
		count_vm_numa_events(NUMA_PTE_UPDATES, pages);
		count_memcg_events_mm(mm, NUMA_PTE_UPDATES, pages);
		ftier_ctx.stats.nr_protected += pages;
	}
	if (!nr_src)
		set_residency(&ftier_ctx.hotlist, hot,
			      !r->promote, r->promote);
	trace_fregion(hot->pud->space->tgid, start, r->promote, true,
		      nr_src, 0, 0, pages);
	return pages;
}

/* ---------------------------------------------------------------------
 * Selection.
 */

static long tier_region(struct tier_round *r, struct ftier_hot *hot)
{
	struct mm_struct *mm = hot->pud->space->mm;
	long ret;

	if (!mmget_not_zero(mm))
		return 0;
	if (!mmap_read_trylock(mm)) {
		mmput(mm);
		r->nr_skipped++;
		return 0;
	}
	if (r->mode == HINT_FAULT) {
		ret = hint_protect(r, mm, hot);
		mmap_read_unlock(mm);
	} else {
		ret = demand_migrate(r, mm, hot);
	}
	mmput(mm);
	return ret;
}

/*
 * Candidates are taken from the Hotlist starting level_off levels below
 * the hottest non-empty level and going colder. Handled entries move to
 * the tail of their bucket, so consecutive rounds use the remaining
 * entries of a level before revisiting any.
 */
static struct ftier_hot *cands[FTIER_MAX_CANDIDATES];
static u32 cand_hot[FTIER_MAX_CANDIDATES];

static unsigned int collect_candidates(struct ftier_hotlist *hl, bool promote,
				       unsigned int max, unsigned int *first)
{
	unsigned int level, top, n = 0;
	struct ftier_hot *hot;

	for (top = FTIER_HOT_LEVELS; top-- > 0; )
		if (hl->nr[ftier_hotlist_pos(hl, top)])
			break;
	if (top >= FTIER_HOT_LEVELS)
		return 0;
	level = top > ftier_ctx.level_off ? top - ftier_ctx.level_off : 0;
	*first = level;

	for (level++; level-- > 0; ) {
		list_for_each_entry(hot, &hl->bucket[ftier_hotlist_pos(hl, level)],
				    link) {
			if (region_has_no_src(hl, hot, promote))
				continue;
			cand_hot[n] = ftier_hot_effective(hl, hot);
			cands[n++] = hot;
			if (n == max)
				return n;
		}
	}
	return n;
}

static int cmp_u32(const void *a, const void *b)
{
	u32 x = *(const u32 *)a, y = *(const u32 *)b;

	return x < y ? -1 : x > y;
}

/*
 * Hint-fault latency threshold for a round: 1/h for the median access
 * frequency h of the selected regions. In steady state the hotness of an
 * entry averages 1.5x the accesses counted per cooling period, so
 * h = hotness / (1.5 * cool_ms) accesses per ms.
 */
static int round_threshold_ms(u32 *hot, unsigned int n)
{
	u32 median;
	u64 ms;

	if (FTIER_CFG(hint_mode) == FTIER_HINT_FIXED || !n)
		return FTIER_CFG(hint_max_ms);
	sort(hot, n, sizeof(*hot), cmp_u32, NULL);
	median = max(hot[n / 2], 1U);
	ms = div_u64(3ULL * FTIER_CFG(cool_ms), 2 * median);
	return clamp_t(u64, ms, FTIER_CFG(hint_min_ms), FTIER_CFG(hint_max_ms));
}

/* ---------------------------------------------------------------------
 * Tier state and the adaptive hotness level.
 */

struct ftier_tier_state ftier_tier = {
	.lock = __SPIN_LOCK_UNLOCKED(ftier_tier.lock),
};

/**
 * ftier_report_tier_state - report a measurement of the memory tiers
 * @sample: latest measurement and the migration rate it calls for
 *
 * For tier latency monitors. Sets sysctl_promote_mb and lets FTier adapt
 * the hotness of its migration candidates to the latency response. May
 * be called from any context.
 */
void ftier_report_tier_state(const struct ftier_tier_sample *sample)
{
	unsigned long flags;

	spin_lock_irqsave(&ftier_tier.lock, flags);
	ftier_tier.sample = *sample;
	ftier_tier.time_ns = ktime_get_ns();
	spin_unlock_irqrestore(&ftier_tier.lock, flags);
	WRITE_ONCE(sysctl_promote_mb, sample->promote_mb);
	trace_ftier_tier(sample->dram_lat, sample->cxl_lat, sample->dram_mbps,
			 sample->cxl_mbps, sample->promote_mb);
}
EXPORT_SYMBOL_GPL(ftier_report_tier_state);

/*
 * Migration rate for this tick, and the signed tier imbalance in per
 * mille (> 0: DRAM is faster, promotion helps). Without a fresh latency
 * report, the requested rate stands in for the imbalance: monitors such
 * as Colloid make it proportional to the latency gap.
 */
static int tier_signal(u64 now, int *gap)
{
	u64 period = (u64)FTIER_CFG(level_period_ms) * NSEC_PER_MSEC;
	u64 timeout = (u64)FTIER_CFG(monitor_timeout_ms) * NSEC_PER_MSEC;
	int rate = READ_ONCE(sysctl_promote_mb);
	unsigned int cap = max(FTIER_CFG(max_migrate_mbps), 1U);
	struct ftier_tier_sample s;
	unsigned long flags;
	u64 t;
	s64 g;

	spin_lock_irqsave(&ftier_tier.lock, flags);
	s = ftier_tier.sample;
	t = ftier_tier.time_ns;
	spin_unlock_irqrestore(&ftier_tier.lock, flags);

	if (timeout && t && now - t > timeout) {
		/* The monitor stopped reporting: do not act on stale data. */
		ftier_ctx.stats.nr_monitor_stale++;
		*gap = 0;
		return 0;
	}
	if (t && now - t <= 2 * period && s.dram_lat && s.cxl_lat)
		g = div64_s64(((s64)s.cxl_lat - (s64)s.dram_lat) * 1000,
			      (s64)s.dram_lat);
	else
		g = (s64)rate * 1000 / cap;
	*gap = clamp_t(s64, g, -10000, 10000);
	return rate;
}

enum { LEVEL_KEEP, LEVEL_OVERSHOOT, LEVEL_SENSITIVE, LEVEL_SLOW };

/*
 * Once per level period: if migration flipped the sign of the imbalance,
 * or moved it a lot with little data, the selected regions are too hot
 * for fine control, so select colder ones. If migrating near the
 * permitted rate barely reduced the imbalance, select hotter ones.
 */
static void adapt_level(u64 now, int gap, unsigned long cap_pages)
{
	int prev = ftier_ctx.gap_prev, dead = FTIER_CFG(level_deadband_pm);
	unsigned long pct;
	int reason = LEVEL_KEEP;

	if (!FTIER_CFG(level_adapt)) {
		ftier_ctx.level_off = 0;
		return;
	}
	if (now < ftier_ctx.level_next_ns)
		return;

	pct = cap_pages ? ftier_ctx.level_pages * 100 / cap_pages : 0;
	if (abs(prev) > dead && abs(gap) > dead && (gap ^ prev) < 0)
		reason = LEVEL_OVERSHOOT;
	else if (abs(prev) > dead && ftier_ctx.level_pages &&
		 pct < FTIER_CFG(level_small_pct) &&
		 abs(prev - gap) * 100 > FTIER_CFG(level_jump_pct) * abs(prev))
		reason = LEVEL_SENSITIVE;
	else if (abs(gap) > dead && pct >= FTIER_CFG(level_full_pct) &&
		 (abs(prev) - abs(gap)) * 100 <
		 (int)FTIER_CFG(level_progress_pct) * abs(prev))
		reason = LEVEL_SLOW;

	if (reason == LEVEL_SLOW && ftier_ctx.level_off) {
		ftier_ctx.level_off--;
		ftier_ctx.stats.nr_level_hotter++;
	} else if ((reason == LEVEL_OVERSHOOT || reason == LEVEL_SENSITIVE) &&
		   ftier_ctx.level_off < FTIER_HOT_LEVELS - 1) {
		ftier_ctx.level_off++;
		ftier_ctx.stats.nr_level_colder++;
	}
	trace_flevel(ftier_ctx.level_off, gap, prev, pct, reason);

	ftier_ctx.gap_prev = gap;
	ftier_ctx.level_pages = 0;
	ftier_ctx.level_next_ns = now +
		(u64)FTIER_CFG(level_period_ms) * NSEC_PER_MSEC;
}

/* ---------------------------------------------------------------------
 * The tiering tick.
 */

static unsigned long migrate_credit;	/* demand mode, pages */
static long hint_migrated_seen;		/* ftier_hint.nr_migrate consumed */

void ftier_tier_reset(void)
{
	migrate_credit = 0;
	hint_migrated_seen = 0;
	ftier_ctx.level_off = 0;
	ftier_ctx.gap_prev = 0;
	ftier_ctx.level_next_ns = 0;
	ftier_ctx.level_pages = 0;
	ftier_ctx.round_end_ns = 0;
	ftier_ctx.tier_ival_end_ns = 0;
	ftier_ctx.ival_target = 0;
	ftier_ctx.ival_done = 0;
	ftier_hint_reset();
}

/*
 * Handle candidates until @max_pages, max_candidates regions with pages
 * to move, or the time budget is reached. Regions with nothing to move
 * do not count: after a cooling period, AFS relinks entries in address
 * order, so the bucket heads may hold many regions already moved.
 */
static unsigned int tier_candidates(struct tier_round *r, unsigned int n,
				    u64 t0, u64 budget_ns)
{
	struct ftier_hotlist *hl = &ftier_ctx.hotlist;
	unsigned int i, nr_hot = 0;
	long ret;

	for (i = 0; i < n && r->nr_pages < r->max_pages &&
		    nr_hot < FTIER_CFG(max_candidates); i++) {
		ret = tier_region(r, cands[i]);
		r->nr_regions++;
		if (ret > 0) {
			r->nr_pages += ret;
			cand_hot[nr_hot++] = cand_hot[i];
		}
		ftier_hotlist_rotate(hl, cands[i]);
		if (ktime_get_ns() - t0 >= budget_ns)
			break;
	}
	return nr_hot;
}

void ftier_tier_tick(unsigned int tick_ms, u64 budget_ns)
{
	struct ftier_hotlist *hl = &ftier_ctx.hotlist;
	unsigned long mbps, credit_max, cap_pages;
	unsigned int n, nr_hot, first = 0;
	struct tier_round r = {};
	u64 t0 = ktime_get_ns(), elapsed;
	long migrated;
	int rate, gap, thresh;

	rate = tier_signal(t0, &gap);
	mbps = min_t(unsigned long, abs(rate), FTIER_CFG(max_migrate_mbps));
	r.promote = rate > 0;
	r.mode = READ_ONCE(sysctl_tiering_mode);
	set_tiering_nodes(&r);

	/* Pages moved per level period at the permitted rate. */
	cap_pages = (mbps << (20 - PAGE_SHIFT)) * FTIER_CFG(level_period_ms) /
		    MSEC_PER_SEC;
	credit_max = mbps << (20 - PAGE_SHIFT);	/* one second worth */

	if (r.mode == HINT_FAULT) {
		migrated = atomic_long_read(&ftier_hint.nr_migrate);
		ftier_ctx.ival_done += migrated - hint_migrated_seen;
		ftier_ctx.level_pages += migrated - hint_migrated_seen;
		hint_migrated_seen = migrated;
		ftier_hint_refill(mbps ? credit_max * tick_ms / MSEC_PER_SEC
				       : -credit_max, credit_max);
	}
	adapt_level(t0, gap, cap_pages);

	if (!mbps) {
		migrate_credit = 0;
		ftier_ctx.ival_target = 0;
		return;
	}

	if (r.mode == DEMAND_MIGRATE) {
		migrate_credit = min(credit_max,
				     migrate_credit + credit_max * tick_ms /
						      MSEC_PER_SEC);
		r.max_pages = migrate_credit;
		n = collect_candidates(hl, r.promote, FTIER_MAX_CANDIDATES,
				       &first);
		tier_candidates(&r, n, t0, budget_ns);
		migrate_credit -= min(migrate_credit, r.nr_pages);
		ftier_ctx.level_pages += r.nr_pages;
		if (r.promote)
			ftier_ctx.stats.nr_promoted += r.nr_pages;
		else
			ftier_ctx.stats.nr_demoted += r.nr_pages;
		goto out;
	}

	/*
	 * Hint-fault mode: migration rounds, each protecting regions up to
	 * the volume still due in this interval and lasting the latency
	 * threshold of the round, until the interval volume is met.
	 */
	if (t0 >= ftier_ctx.tier_ival_end_ns) {
		ftier_ctx.tier_ival_end_ns = t0 +
			(u64)FTIER_CFG(interval_ms) * NSEC_PER_MSEC;
		ftier_ctx.ival_target = (mbps << (20 - PAGE_SHIFT)) *
					FTIER_CFG(interval_ms) / MSEC_PER_SEC;
		ftier_ctx.ival_done = 0;
	}
	if (t0 < ftier_ctx.round_end_ns ||
	    ftier_ctx.ival_done >= ftier_ctx.ival_target)
		goto out;

	r.max_pages = ftier_ctx.ival_target - ftier_ctx.ival_done;
	n = collect_candidates(hl, r.promote, FTIER_MAX_CANDIDATES, &first);
	nr_hot = tier_candidates(&r, n, t0, budget_ns);
	if (!r.nr_pages)
		goto out;
	thresh = round_threshold_ms(cand_hot, nr_hot);
	if (FTIER_CFG(hint_mode) != FTIER_HINT_HISTOGRAM)
		ftier_hint_set_thresh(thresh);
	ftier_ctx.round_end_ns = t0 + (u64)max_t(unsigned int, thresh, tick_ms) *
				      NSEC_PER_MSEC;
	ftier_ctx.stats.nr_rounds++;
	trace_fround(ftier_ctx.stats.nr_rounds, r.nr_regions, r.nr_pages,
		     nr_hot ? cand_hot[nr_hot / 2] : 0, thresh, first);

out:
	elapsed = ktime_get_ns() - t0;
	ftier_ctx.stats.nr_migrate_fail += r.nr_failed;
	ftier_ctx.stats.nr_tier_ticks++;
	ftier_ctx.stats.tier_ns += elapsed;

	trace_fmigrate(r.nr_regions, r.nr_skipped, r.nr_pages, r.nr_failed,
		       div_u64(budget_ns, NSEC_PER_USEC),
		       div_u64(elapsed, NSEC_PER_USEC), first, r.promote,
		       r.max_pages);
}

#ifdef CONFIG_FTIER_KUNIT_TEST
#include "tests/ftier_kunit.c"
#endif
