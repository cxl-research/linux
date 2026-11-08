// SPDX-License-Identifier: GPL-2.0
/*
 * FTier memory tiering: candidate selection and data migration.
 *
 * Every tick, the target migration rate set by the tier latency monitor
 * (sysctl_promote_mb, MB/s, capped by max_migrate_mbps) is converted to
 * a page budget. Candidates are PMD entries taken from the Hotlist,
 * hottest first. Depending on the tiering mode, the pages of a candidate
 * that sit on the source tier are either migrated right away
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
#include <linux/swap.h>
#include <linux/vmstat.h>

#include <asm/tlb.h>

#include "../internal.h"
#include "internal.h"

#include <trace/events/ftier.h>

/* Residency flags stay valid for this many Hotlist epochs. */
#define FTIER_RESIDENCY_TTL	1

struct tier_round {
	bool promote;
	bool src[NR_NODES];
	bool dst[NR_NODES];
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
	int nid;

	for (nid = 0; nid < NR_NODES; ++nid) {
		r->src[nid] = r->promote ? CXL_NID(nid) : DRAM_NID(nid);
		r->dst[nid] = r->promote ? DRAM_NID(nid) : CXL_NID(nid);
	}
	r->next_dst = 0;
}

static int next_dst_node(struct tier_round *r)
{
	int i, nid = r->next_dst;

	for (i = 0; i < NR_NODES; i++) {
		nid = (nid + 1) % NR_NODES;
		if (r->dst[nid]) {
			r->next_dst = nid;
			return nid;
		}
	}
	return NUMA_NO_NODE;
}

static bool src_node(const struct tier_round *r, int nid)
{
	return nid >= 0 && nid < NR_NODES && r->src[nid];
}

/* ---------------------------------------------------------------------
 * Residency hints: skip regions recently found to have nothing to move.
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

	return ((hot_stamp(hl) - stamp) & 0x1f) <= FTIER_RESIDENCY_TTL;
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
		if (nid >= 0 && nid < NR_NODES && g->r->dst[nid])
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

static unsigned long migrate_credit;	/* pages, carried across ticks */

void ftier_tier_tick(unsigned int tick_ms, u64 budget_ns)
{
	struct ftier_hotlist *hl = &ftier_ctx.hotlist;
	int rate = READ_ONCE(sysctl_promote_mb);
	unsigned long mbps, credit_max;
	struct tier_round r = {};
	struct ftier_hot *hot;
	u64 t0 = ktime_get_ns(), elapsed = 0;
	unsigned int level, last_level = 0;
	long ret;

	mbps = min_t(unsigned long, abs(rate), FTIER_CFG(max_migrate_mbps));
	if (!mbps) {
		migrate_credit = 0;
		return;
	}

	/* Rate limit with up to one second worth of accumulated credit. */
	credit_max = mbps << (20 - PAGE_SHIFT);
	migrate_credit = min(credit_max,
			     migrate_credit + credit_max * tick_ms / 1000);

	r.promote = rate > 0;
	r.mode = READ_ONCE(sysctl_tiering_mode);
	r.max_pages = migrate_credit;
	set_tiering_nodes(&r);

	/* The Hotlist only changes under ftier_lock, which we hold. */
	ftier_for_each_hot(hl, level, hot) {
		if (region_has_no_src(hl, hot, r.promote))
			continue;
		last_level = level;
		ret = tier_region(&r, hot);
		r.nr_regions++;
		if (ret > 0)
			r.nr_pages += ret;
		elapsed = ktime_get_ns() - t0;
		if (r.nr_pages >= r.max_pages || elapsed >= budget_ns)
			goto out;
	}
	elapsed = ktime_get_ns() - t0;
out:
	migrate_credit -= min(migrate_credit, r.nr_pages);

	if (r.mode == DEMAND_MIGRATE) {
		if (r.promote)
			ftier_ctx.stats.nr_promoted += r.nr_pages;
		else
			ftier_ctx.stats.nr_demoted += r.nr_pages;
	}
	ftier_ctx.stats.nr_migrate_fail += r.nr_failed;
	ftier_ctx.stats.nr_tier_ticks++;
	ftier_ctx.stats.tier_ns += elapsed;

	trace_fmigrate(r.nr_regions, r.nr_skipped, r.nr_pages, r.nr_failed,
		       div_u64(budget_ns, NSEC_PER_USEC),
		       div_u64(elapsed, NSEC_PER_USEC), last_level, r.promote,
		       r.max_pages);
}
