// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Core Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>
#include <linux/pagewalk.h>

#include "../internal.h"

#define MIN_DRAM_OCC_BLK_PGS 1

struct tiering_candidate {
	struct pg_temp_block *blk;
	struct list_head siblings;
};

struct tiering_ctx {
	struct task_struct *task;
	struct list_head dram_cands;
	struct list_head cxl_cands;
	int nr_dram_cands, nr_cxl_cands;
} __tierctx;

// int tier_frame_pg_order = 3; /* 8-page frames by default  */
enum tiering_interleave_mode tiering_interleave_mode = TIM_HALF;

static int promote_pg_epoch = 0;
static int epoch_usecs = 1E6; /* 1s by default */
static int tiering_epoch_usecs = 1E6; /* 1 second by default */
static enum tiering_mode tiering_mode = TIERING_MODE_OFF;
static int tiering_reset_epochs = 1;
static int TIER_TEMPCLS_MAX = 12;
static int TIER_TEMPCLS_MIN = 1;

static int epochid = 0;
static int next_tiering_epoch = 0;

static bool tiering_need_stop(void)
{
	if (kthread_should_stop())
		return true;
	return false;
}

static void congestier_usleep(unsigned long us)
{
	if (us >= USLEEP_RANGE_UPPER_BOUND)
		schedule_timeout_idle(usecs_to_jiffies(us));
	else
		usleep_range_idle(us, us + 1);
}

static int tiering_fn(void *data);

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

int pebs_tracking_start(void)
{
	int err = -EBUSY;

	if (!__tierctx.task) {
		err = 0;
		__tierctx.task = kthread_run(tiering_fn, NULL, "tiering");
		if (IS_ERR(__tierctx.task)) {
			err = PTR_ERR(__tierctx.task);
			__tierctx.task = NULL;
		}
	}

	printk(KERN_INFO "START returned %d\n", err);
	return err;
}

int pebs_tracking_stop(void)
{
	if (__tierctx.task) {
		get_task_struct(__tierctx.task);
		kthread_stop_put(__tierctx.task);
		__tierctx.task = NULL;
		printk(KERN_INFO "PGTemp PEBS tracking stopped\n");
		return 0;
	}

	printk(KERN_INFO "STOP failed\n");
	return -EPERM;
}

int tiering_start(void) { return 0; }
int tiering_stop(void) { return 0; }

static void pgtemp_track_init(void)
{
	pebs_track_init();
}

static int pgtemp_track_epoch_work(int epoch_id)
{
	return pebs_track_epoch_work(epoch_id);
}

#else /* CONFIG_CONGESTIER_PGTEMP_PEBS */

int tiering_start(void)
{
	int err = -EBUSY;

	if (!__tierctx.task) {
		__tierctx.task = kthread_run(tiering_fn, NULL, "tiering");
		if (IS_ERR(__tierctx.task)) {
			err = PTR_ERR(__tierctx.task);
			__tierctx.task = NULL;
		}
	}

	printk(KERN_INFO "START Tiering returned %d\n", err);
	return err;
}

int tiering_stop(void)
{
	if (__tierctx.task) {
		get_task_struct(__tierctx.task);
		kthread_stop_put(__tierctx.task);
		__tierctx.task = NULL;
		printk(KERN_INFO "Tiering stopped\n");
		return 0;
	}

	printk(KERN_ERR "STOP failed\n");
	return -EPERM;
}

static void pgtemp_track_init(void) {}
static int pgtemp_track_epoch_work(int epoch_id) { return 0; }

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */

static bool can_promote_once(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	bool candec = false;
	switch (mode) {
	case TIM_HALF:
	case TIM_GSTEP:
		if (blk->cxl_pages > 0)
			candec = true;
		break;
	default:
	}
	return candec;
}

// static bool can_dec_demotion_level(struct pg_temp_block *blk) 
// {
// 	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
// 	bool candec = false;
// 	switch (mode) {
// 	case TIM_HALF:
// 	case TIM_GSTEP:
// 		if (blk->demotion_level > 0)
// 			candec = true;
// 		break;
// 	default:
// 	}
// 	return candec;
// }

static bool can_demote_once(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	bool caninc = false;
	switch (mode) {
	case TIM_HALF:
		if (blk->cxl_pages < (blk->total_pages / 2))
			caninc = true;
		break;
	case TIM_GSTEP:
		if (blk->dram_pages > MIN_DRAM_OCC_BLK_PGS)
			caninc = true;
		break;
	default:
	}
	return caninc;
}

// static bool can_inc_demotion_level(struct pg_temp_block *blk)
// {
// 	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
// 	bool caninc = false;
// 	switch (mode) {
// 	case TIM_HALF:
// 		if (blk->demotion_level < (1 << (tier_frame_pg_order - 1)))
// 			caninc = true;
// 		break;
// 	case TIM_GSTEP:
// 		if (blk->demotion_level < ((1 << tier_frame_pg_order) - 1))
// 			caninc = true;
// 		break;
// 	default:
// 	}
// 	return caninc;
// }

// static inline int gstepdown(int level)
// {
// 	int new_level = (1 << tier_frame_pg_order) - 1, step = 1;
// 	while (new_level >= level) {
// 		new_level -= step;
// 		step <<= 1;
// 	}
// 	return new_level;
// }

// static inline int gstepup(int level)
// {
// 	int new_level = 0, step = (1 << (tier_frame_pg_order - 1));
// 	while (new_level <= level) {
// 		new_level += step;
// 		step >>= 1;
// 	}
// 	return new_level;
// }

// static int prev_demotion_level(struct pg_temp_block *blk)
// {
// 	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
// 	switch(mode) {
// 		case TIM_HALF:

// 	}
// }

static int demote_once_pages(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	int demote_pages = 0, total_pages = blk->total_pages;
	switch (mode) {
	case TIM_HALF:
		demote_pages = (total_pages / 2) - blk->cxl_pages;
		if (demote_pages < 0)
			return 0;
		break;
	case TIM_GSTEP:
		while ((total_pages /= 2)) {
			demote_pages += total_pages;
			if (demote_pages > blk->cxl_pages)
				break;
		}
		demote_pages -= blk->cxl_pages;
		break;
	default:
	}
	if (demote_pages > blk->dram_pages - MIN_DRAM_OCC_BLK_PGS)
		demote_pages = blk->dram_pages - MIN_DRAM_OCC_BLK_PGS;
	return demote_pages;
}

static int promote_once_pages(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	int promote_pages = 0, total_pages = blk->total_pages;
	switch (mode) {
	case TIM_HALF:
		promote_pages = blk->cxl_pages;
		break;
	case TIM_GSTEP:
		while ((total_pages /= 2)) {
			promote_pages = total_pages;
			if (promote_pages <= blk->cxl_pages)
				break;
		}
	default:
	}
	return promote_pages;
}

// static int prev_demotion_level(struct pg_temp_block *blk)
// {
// 	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
// 	int dlev = blk->demotion_level, ret = -EINVAL;
// 	switch (mode) {
// 	case TIM_HALF:
// 		ret = 0;
// 		break;
// 	case TIM_GSTEP:
// 		ret = gstepdown(dlev);
// 		break;
// 	default:
// 	}
// 	return ret;
// }

// static int next_demotion_level(struct pg_temp_block *blk)
// {
// 	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
// 	int dlev = blk->demotion_level, ret = -EINVAL;
// 	switch (mode) {
// 	case TIM_HALF:
// 		ret = 1 << (tier_frame_pg_order - 1);
// 		break;
// 	case TIM_GSTEP:
// 		ret = gstepup(dlev);
// 		break;
// 	default:
// 	}
// 	return ret;
// }

struct tiering_pgwalk_private {
	struct tiering_candidate *tiering_candidate;
	struct list_head *folio_list;
	int target_cand_pgs, found_cand_pgs, oldlevel, newlevel;
	bool tier_promote; /* true for promotion, false for demotion */
};

static unsigned int congestier_promote_pages(struct list_head *folios)
{
	unsigned int nr_migrated = 0, ret;
	nodemask_t allowed_mask = NODE_MASK_NONE;
	struct migration_target_control mtc = {
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.nid = 1, /* DRAM NID */
		.nmask = &allowed_mask
	};

	if (list_empty(folios))
		return 0;

	ret = congestier_migrate_pages(folios, alloc_migrate_folio, NULL,
		      (unsigned long)&mtc, MIGRATE_ASYNC, MR_CONGESTIER,
		      &nr_migrated);
	return nr_migrated;
}

static unsigned int congestier_demote_pages(struct list_head *folios)
{
	nodemask_t allowed_mask = NODE_MASK_NONE;
	struct migration_target_control mtc2, mtc3;
	struct list_head *mid, *tmp;
	int ret2, ret3;
	unsigned int nlist = 0, nr_migr_2, nr_migr_3, n1 = 0, n2 = 0;
	gfp_t gfp = GFP_HIGHUSER_MOVABLE;
	LIST_HEAD(fol2);
	LIST_HEAD(fol3);

	if (list_empty(folios))
		return 0;

	mtc2.gfp_mask = gfp;
	mtc2.nid = 2;
	mtc2.nmask = &allowed_mask;

	mtc3.gfp_mask = gfp;
	mtc3.nid = 3;
	mtc3.nmask = &allowed_mask;

	list_for_each(mid, folios)
		nlist++;
	nlist /= 2;

	mid = folios;
	while (nlist--)
		mid = mid->next;

	list_cut_position(&fol2, folios, mid);
	list_splice_tail_init(folios, &fol3);

	list_for_each(tmp, &fol2)
		n1++;
	list_for_each(tmp, &fol3)
		n2++;

	ret2 = congestier_migrate_pages(&fol2, alloc_migrate_folio, NULL,
															(unsigned long)&mtc2, MIGRATE_ASYNC,
															MR_CONGESTIER, &nr_migr_2);
	ret3 = congestier_migrate_pages(&fol3, alloc_migrate_folio, NULL,
															(unsigned long)&mtc3, MIGRATE_ASYNC,
															MR_CONGESTIER, &nr_migr_3);
	return (nr_migr_2 + nr_migr_3);
}

static unsigned int congestier_migrate_folios(struct list_head *folios,
					uint8_t targetmask)
{
	if (targetmask == DRAM_NID_MASK)
		return congestier_promote_pages(folios);
	else if (targetmask == CXL_NID_MASK)
		return congestier_demote_pages(folios);
	else
		return 0; /* Invalid target mask */
}

static int do_tiering_ptep(pte_t *ptep, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	struct tiering_pgwalk_private *priv = walk->private;
	struct page *page;
	struct folio *folio;
	pte_t pte = ptep_get(ptep);
	int nid, ret = 0;

	if (pte_none(pte) || !pte_present(pte))
		goto out;

	page = pte_page(pte);
	if (!page || PageTail(page))
		goto out;

	/* skip page if it is not on the right src tier */
	nid = page_to_nid(page);
	if ((!priv->tier_promote && CXLNID(nid)) ||
	    (priv->tier_promote && !CXLNID(nid))) {
		goto out;
	}

	folio = page_folio(page);
	if (!folio_test_lru(folio) || !folio_try_get(folio))
		goto out;
	if (unlikely(page_folio(page) != folio || !folio_test_lru(folio)))
		goto put_folio;

	if (!folio_isolate_lru(folio))
		goto put_folio;

	list_add(&folio->lru, priv->folio_list);
	priv->found_cand_pgs++;
	if (priv->found_cand_pgs >= priv->target_cand_pgs)
		ret = -1; /* Stop walking */
put_folio:
	folio_put(folio);

out:
	return ret;
}

static const struct mm_walk_ops tiering_core_ops = {
	.pte_entry = do_tiering_ptep,
	.walk_lock = PGWALK_RDLOCK,
};

static int do_tiering(void)
{
	struct pg_temp_block *blk;
	struct tiering_candidate *cand, *cand2;
	struct list_head *tier_head;
	struct folio *folio;
	struct task_struct *task;
	struct mm_struct *mm;
	struct tiering_pgwalk_private tierinfo = {
		.target_cand_pgs = 0, .found_cand_pgs = 0,
		.tiering_candidate = NULL,
		.tier_promote = (promote_pg_epoch > 0),
		.folio_list = NULL,
	};
	uint64_t addr_start, addr_end;
	unsigned nr_migrated = 0, nr_migratable = 0;
	uint8_t target_nid_mask, blkshift;
	pid_t pid;
	int numpages = READ_ONCE(promote_pg_epoch), *nrcands;
	bool canpromote, candemote;
	LIST_HEAD(tier_folios);

	if (!numpages)
		return 0;
	if (numpages < 0)
		numpages *= -1;

	if (!tierinfo.tier_promote) {
		tier_head = &__tierctx.dram_cands;
		nrcands = &(__tierctx.nr_dram_cands);
		target_nid_mask = CXL_NID_MASK;
	} else if (tierinfo.tier_promote) {
		tier_head = &__tierctx.cxl_cands;
		nrcands = &(__tierctx.nr_cxl_cands);
		target_nid_mask = DRAM_NID_MASK;
	} else
		return 0;

	printk(KERN_INFO "do_tiering: epoch %d, target_nid_mask %d\n",
			epochid, target_nid_mask);

	blkshift = PAGE_SHIFT + pgtemp_granularity_order;
	list_for_each_entry_safe_reverse(cand, cand2, tier_head, siblings) {
		blk = cand->blk;
		if (blk->tiering_state != TIERING_CANDIDATE)
			continue;
		if (blk->tiering_epoch > epochid)
			continue;

		canpromote = tierinfo.tier_promote && can_promote_once(blk);
		candemote = !tierinfo.tier_promote && can_demote_once(blk);
		if (!canpromote && !candemote)
			continue;

		list_del(&cand->siblings);
		kfree(cand);
		(*nrcands)--;

		pid = blk->pid;
		task = find_task_by_vpid(pid);
		if (!task) {
			printk(KERN_ERR "do_tiering: task %d not found\n", pid);
			continue;
		}

		mm = get_task_mm(task);
		if (!mm)
			goto putback_return;
		mmap_read_lock(mm);

		tierinfo.folio_list = &tier_folios;
		addr_start = blk->blocknum << blkshift;
		if (tierinfo.tier_promote)
			tierinfo.target_cand_pgs = min(promote_once_pages(blk), numpages);
		else
			tierinfo.target_cand_pgs = min(demote_once_pages(blk), numpages);
		addr_end = addr_start + (1 << blkshift);

		// newlevel = tierinfo.tier_promote ? 
		// 		prev_demotion_level(blk) : next_demotion_level(blk);
		// tierinfo.oldlevel = blk->demotion_level;
		// tierinfo.newlevel = newlevel;

		// printk(KERN_INFO "do_tiering start: %p, pid %d, "
		// 		"addr_start %llx, addr_end %llx, "
		// 		"oldlevel %d, newlevel %d tempclass %d\n",
		// 		blk, pid, addr_start, addr_end,
		// 		tierinfo.oldlevel, tierinfo.newlevel, temp_class(blk->ld_temp));
		walk_page_range(mm, addr_start, addr_end,
				&tiering_core_ops, &tierinfo);
		mmap_read_unlock(mm);
		mmput(mm);
		// printk(KERN_INFO "do_tiering end: blk %p, pid %d, "
		// 		"nr_migratable %d, nr_candidates %d\n",
		// 		blk, pid, tierinfo.nr_migratable,
		// 		tierinfo.nr_candidates);

		nr_migratable += tierinfo.found_cand_pgs;
		blk->tiering_state = TIERED;
		// blk->demotion_level = newlevel;

		numpages -= tierinfo.found_cand_pgs;
		if (numpages <= 0)
			break;
	}

	/* Migrate the folios in tier_folios */
	nr_migrated = congestier_migrate_folios(&tier_folios,
					target_nid_mask);

	printk(KERN_INFO "do_tiering: migrated %u (of %u) folios\n",
				nr_migrated, nr_migratable);

	try_to_unmap_flush();

putback_return:
	while (!list_empty(&tier_folios)) {
		folio = lru_to_folio(&tier_folios);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}
	return nr_migrated;
}

struct setdl_private {
	int nr_dram_pages, nr_cxl_pages, nr_total_pages;
};

static int setdlpte(pte_t *ptep, unsigned long addr, unsigned long next,
	 struct mm_walk *walk)
{
	struct setdl_private *priv = walk->private;
	struct page *page;
	pte_t pte = ptep_get(ptep);
	int nid;

	if (pte_none(pte) || !pte_present(pte))
		return 0;

	page = pte_page(pte);
	if (!page || PageTail(page))
		return 0;

	priv->nr_total_pages++;
	nid = page_to_nid(page);
	if (nid & DRAM_NID_MASK) {
		priv->nr_dram_pages++;
	} else if (nid & CXL_NID_MASK) {
		priv->nr_cxl_pages++;
	}

	return 0;
}

static const struct mm_walk_ops setdlops = {
	.pte_entry = setdlpte,
	.walk_lock = PGWALK_RDLOCK,
};

int set_demotion_level(struct pg_temp_block *blk)
{
	struct task_struct *task;
	struct mm_struct *mm;
	uint64_t start, end;
	int blkshift = PAGE_SHIFT + pgtemp_granularity_order;
	struct setdl_private priv = { 0, 0, 0 };

	task = find_task_by_vpid(blk->pid);
	if (!task)
		return -EINVAL;

	mm = get_task_mm(task);
	if (!mm)
		return -EINVAL;

	start = blk->blocknum << blkshift;
	end = start + (1 << blkshift);

	mmap_read_lock(mm);
	walk_page_range(mm, start, end, &setdlops, &priv);
	mmap_read_unlock(mm);
	mmput(mm);

	blk->dram_pages = priv.nr_dram_pages;
	blk->cxl_pages = priv.nr_cxl_pages;
	blk->total_pages = priv.nr_total_pages;

	return 0;
}

static bool mk_candidate_blk(struct pg_temp_block *blk,
														int epochid, bool is_promote)
{
	struct tiering_candidate *candidate;
	bool canpromote, candemote;

	set_demotion_level(blk);
	canpromote = can_promote_once(blk);
	candemote = can_demote_once(blk);

	if (blk->tiering_state == NOT_TIERED) {
		if ((is_promote && !canpromote) || (!is_promote && !candemote))
			return false;
			
		blk->tiering_state = TIERING_CANDIDATE;
		blk->tiering_epoch = epochid;

		candidate = kmalloc(sizeof(struct tiering_candidate), GFP_KERNEL);
		candidate->blk = blk;
		if (!is_promote) {
			list_add(&candidate->siblings, &__tierctx.dram_cands);
			__tierctx.nr_dram_cands++;
		} else {
			list_add(&candidate->siblings, &__tierctx.cxl_cands);
			__tierctx.nr_cxl_cands++;
		}
		return true;
	} else if (blk->tiering_state == TIERED) {
		if (blk->tiering_epoch + tiering_reset_epochs <= epochid) {
			if (canpromote || candemote)	
				blk->tiering_state = NOT_TIERED;
		}
		return false;
	}

	return false;
}

static inline int exp_pages_in_block(void)
{
	return (1 << pgtemp_granularity_order);
}

// static inline int tierable_pages(int total_pages)
// {
// 	int framesz = (1 << tier_frame_pg_order), tierable_per_frame;
// 	switch (READ_ONCE(tiering_interleave_mode)) {
// 	case TIM_HALF:
// 		tierable_per_frame = framesz / 2;
// 		break;
// 	case TIM_GSTEP:
// 		tierable_per_frame = framesz - 1;
// 		break;
// 	default:
// 		tierable_per_frame = 0;
// 	}
// 	return (total_pages / framesz) * tierable_per_frame;
// }

/* we assume `totalpages` contiguous , start and end 2MB-aligned */
static inline int tierable_pages(int total_pages)
{
	int nr_pages, nr_blks;
	int blkshift = PAGE_SHIFT + pgtemp_granularity_order;
	switch (READ_ONCE(tiering_interleave_mode)) {
	case TIM_HALF:
		nr_pages = total_pages / 2;
		break;
	case TIM_GSTEP:
		nr_blks = total_pages >> blkshift;
		nr_pages = total_pages - (nr_blks * MIN_DRAM_OCC_BLK_PGS);
		break;
	default:
	}
	return nr_pages;
}

static void reclaim_stale_candidates(int max_candidates)
{
	struct tiering_candidate *cand, *cand2;
	struct pg_temp_block *blk;

	list_for_each_entry_safe(cand, cand2, &__tierctx.dram_cands, siblings) {
		blk = cand->blk;
		if (blk->tiering_epoch + tiering_reset_epochs <= epochid) {
			list_del(&cand->siblings);
			kfree(cand);
			__tierctx.nr_dram_cands--;
		}
	}

	list_for_each_entry_safe(cand, cand2, &__tierctx.cxl_cands, siblings) {
		blk = cand->blk;
		if (blk->tiering_epoch + tiering_reset_epochs <= epochid) {
			list_del(&cand->siblings);
			kfree(cand);
			__tierctx.nr_cxl_cands--;
		}
	}
}

/*
 * refresh_candidates - Refresh the candidates for tiering.
 * First clean up the old candidates
 * and then add candidates to ensure that the max nr of candidates
 * is not exceeded.
 */
static void refresh_candidates(void)
{
	struct pg_temp_block *blk, *n;
	struct temperature_class *cls;
	int num_pages, nr_candidates = 0, found_candidates = 0, max_candidates;
	int blkshift = pgtemp_granularity_order + PAGE_SHIFT;
	bool is_promote = (promote_pg_epoch > 0);

	if (!promote_pg_epoch)
		return;

	num_pages = promote_pg_epoch;
	if (num_pages < 0)
		num_pages *= -1;
	num_pages = (((num_pages >> blkshift) + 1) << blkshift); /* block-align */

	max_candidates = 5 * (num_pages / tierable_pages(exp_pages_in_block())) / 4;

	reclaim_stale_candidates(max_candidates);

	if (is_promote && __tierctx.nr_dram_cands < max_candidates) {
		nr_candidates = max_candidates - __tierctx.nr_dram_cands;
	} else if (!is_promote && __tierctx.nr_cxl_cands < max_candidates) {
		nr_candidates = max_candidates - __tierctx.nr_cxl_cands;
	} else {
		printk(KERN_INFO "No candidates to refresh (%d %d %d), skipping\n",
					__tierctx.nr_dram_cands, __tierctx.nr_cxl_cands, max_candidates);
		return;
	}

	for (int idx = TIER_TEMPCLS_MAX; idx >= TIER_TEMPCLS_MIN; --idx) {
		cls = get_temp_cls(idx);
		if (!cls || !cls->nr_blocks)
			continue;

		mutex_lock(&cls->templock);
		list_for_each_entry_safe(blk, n, &cls->blocks, temper_class) {
			if (mk_candidate_blk(blk, epochid, is_promote))
				found_candidates++;
			if (found_candidates >= nr_candidates)
				break;
		}
		mutex_unlock(&cls->templock);
	}

	printk(KERN_INFO "Tiering epoch %d: %d candidates\n",
				epochid, found_candidates);
}

static void __commit_sysctl_vals(void)
{
	tiering_mode = READ_ONCE(sysctl_tiering_mode);
	promote_pg_epoch = READ_ONCE(sysctl_promote_pg_epoch);
	epoch_usecs = READ_ONCE(sysctl_epoch_usecs);
	tiering_epoch_usecs = READ_ONCE(sysctl_tiering_epoch_usecs);
	TIER_TEMPCLS_MAX = READ_ONCE(sysctl_max_tier_tmpcls);
	TIER_TEMPCLS_MIN = READ_ONCE(sysctl_min_tier_tmpcls);
}

static int tiering_fn(void *data)
{
	uint64_t start, end, dur_usecs;
	int migrated = 0;

	INIT_LIST_HEAD(&__tierctx.dram_cands);
	INIT_LIST_HEAD(&__tierctx.cxl_cands);
	__tierctx.nr_dram_cands = 0;
	__tierctx.nr_cxl_cands = 0;
	pgtemp_track_init();

	while (!tiering_need_stop()) {
		start = ktime_get_ns();

		migrated = 0;
		__commit_sysctl_vals();

		pgtemp_track_epoch_work(epochid);

		if (READ_ONCE(tiering_mode) == TIERING_MODE_OFF)
			goto end_epoch;

		if (epochid >= next_tiering_epoch) {
			refresh_candidates();
			migrated = do_tiering();
			next_tiering_epoch = epochid + (tiering_epoch_usecs / epoch_usecs);
		}

end_epoch:
		end = ktime_get_ns();
		dur_usecs = (end - start) / 1000;
		printk(KERN_INFO "Tiering epoch %d took %llu usecs, migrated %d KB\n",
					epochid, dur_usecs, migrated * 4);
		++epochid;

		printk(KERN_INFO "----------\n");
		if (dur_usecs < epoch_usecs) {
			end = ktime_get_ns();
			dur_usecs = (end - start) / 1000;
			congestier_usleep(epoch_usecs - dur_usecs);
		} else {
			printk(KERN_WARNING "Tiering took too long: %llu usecs\n", dur_usecs);
			congestier_usleep(epoch_usecs);
		}
	}

	return 0;
}

void reset_tiering_ctx(void)
{
	struct tiering_candidate *pos, *n;
	epochid = 0;
	next_tiering_epoch = 0;
	list_for_each_entry_safe(pos, n, &__tierctx.dram_cands, siblings) {
		list_del(&pos->siblings);
		kfree(pos);
	}
	list_for_each_entry_safe(pos, n, &__tierctx.cxl_cands, siblings) {
		list_del(&pos->siblings);
		kfree(pos);
	}
}