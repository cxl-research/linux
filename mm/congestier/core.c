// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Core Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>
#include <linux/pagewalk.h>

#include "../internal.h"

struct tiering_candidate {
	struct pg_temp_block *blk;
	struct list_head siblings;
};

struct tiering_ctx {
	struct task_struct *task;
	struct list_head dram_cands;
	struct list_head cxl_cands;
} __tierctx;

int tier_frame_pg_order = 3; /* 8-page frames by default  */
enum tiering_interleave_mode tiering_interleave_mode = TIM_HALF;

static int promote_pg_epoch = 0;
static int epoch_usecs = 1E5; /* 100ms by default */
static int tiering_epoch_usecs = 1E6; /* 1 second by default */
static int dirty_latency_threshold_usecs = 2E5; /* 200ms by default */
static enum tiering_mode tiering_mode = TIERING_MODE_OFF;
static int tiering_reset_epochs = 10;

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

static bool can_dec_demotion_level(struct pg_temp_block *blk) 
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	bool candec = false;
	switch (mode) {
	case TIM_HALF:
	case TIM_GSTEP:
		if (blk->demotion_level > 0)
			candec = true;
		break;
	default:
	}
	return candec;
}

static bool can_inc_demotion_level(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	bool caninc = false;
	switch (mode) {
	case TIM_HALF:
		if (blk->demotion_level < (1 << (tier_frame_pg_order - 1)))
			caninc = true;
		break;
	case TIM_GSTEP:
		if (blk->demotion_level < ((1 << tier_frame_pg_order) - 1))
			caninc = true;
		break;
	default:
	}
	return caninc;
}

static inline int gstepdown(int level)
{
	int new_level = (1 << tier_frame_pg_order) - 1, step = 1;
	while (new_level >= level) {
		new_level -= step;
		step <<= 1;
	}
	return new_level;
}

static inline int gstepup(int level)
{
	int new_level = 0, step = (1 << (tier_frame_pg_order - 1));
	while (new_level <= level) {
		new_level += step;
		step >>= 1;
	}
	return new_level;
}

static int prev_demotion_level(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	int dlev = blk->demotion_level, ret = -EINVAL;
	switch (mode) {
	case TIM_HALF:
		ret = 0;
		break;
	case TIM_GSTEP:
		ret = gstepdown(dlev);
		break;
	default:
	}
	return ret;
}

static int next_demotion_level(struct pg_temp_block *blk)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	int dlev = blk->demotion_level, ret = -EINVAL;
	switch (mode) {
	case TIM_HALF:
		ret = 1 << (tier_frame_pg_order - 1);
		break;
	case TIM_GSTEP:
		ret = gstepup(dlev);
		break;
	default:
	}
	return ret;
}

struct tiering_pgwalk_private {
	struct tiering_candidate *tiering_candidate;
	struct list_head *folio_list;
	int nr_candidates, nr_migratable, oldlevel, newlevel;
	bool tier_promote, update_blk; /* true for promotion, false for demotion */
};

static int mk_tiering_candidate(pte_t *ptep, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	struct tiering_pgwalk_private *priv = walk->private;
	struct page *page;
	int nid;

	if (pte_none(*ptep) || !pte_present(*ptep))
		goto skip_page;

	page = pte_page(*ptep);
	if (!page || PageTail(page))
		goto skip_page;

	nid = page_to_nid(page);

	/* skip page if it is not on the right src tier */
	if ((!priv->tier_promote && CXLNID(nid)) ||
	    (priv->tier_promote && !CXLNID(nid))) {
		goto skip_page;
	}

	ptep_test_and_clear_dirty(walk->mm, addr, ptep);
	priv->nr_candidates++;
	return 0;
skip_page:
	return 0;
}

static const struct mm_walk_ops tiering_mk_candidate_ops = {
	.pte_entry = mk_tiering_candidate,
	.walk_lock = PGWALK_RDLOCK,
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
	int nid, tier_frame_offset, tier_frame_pages;

	tier_frame_pages = 1 << tier_frame_pg_order;
	tier_frame_offset = (addr >> PAGE_SHIFT) & (tier_frame_pages - 1);
	if (priv->tier_promote) {
		/* exp: oldlevel >= tfoffset > newlevel */
		if (tier_frame_offset <= priv->newlevel ||
		    tier_frame_offset > priv->oldlevel) {
			goto out;
		}
	} else {
		/* exp: oldlevel < tfoffset <= newlevel */
		if (tier_frame_offset > priv->newlevel ||
		    tier_frame_offset <= priv->oldlevel) {
			goto out;
		}
	}

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

	priv->nr_candidates++;
	if (!pte_dirty(pte)) {
		/* If the page is not dirty, add it to folio_list */
		folio = page_folio(page);
		if (!folio_test_lru(folio) || !folio_try_get(folio))
			goto out;
		if (unlikely(page_folio(page) != folio || !folio_test_lru(folio)))
			goto put_folio;

		if (!folio_isolate_lru(folio))
			goto put_folio;

		list_add(&folio->lru, priv->folio_list);
		priv->nr_migratable++;
put_folio:
		folio_put(folio);
	}

out:
	return 0;
}

static const struct mm_walk_ops tiering_core_ops = {
	.pte_entry = do_tiering_ptep,
	.walk_lock = PGWALK_RDLOCK,
};

static int do_tiering(void)
{
	struct pg_temp_block *blk;
	struct tiering_candidate *pos, *n;
	struct list_head *tier_head;
	struct folio *folio;
	struct task_struct *task;
	struct mm_struct *mm;
	struct tiering_pgwalk_private tierinfo = {
		.nr_candidates = 0, .nr_migratable = 0,
		.tiering_candidate = NULL,
		.tier_promote = (promote_pg_epoch > 0),
		.update_blk = false, .folio_list = NULL,
	};
	uint64_t addr_start, addr_end;
	unsigned nr_migrated = 0, nr_migratable = 0, nr_tried = 0;
	uint8_t target_nid_mask, blkshift;
	pid_t pid;
	int numpages = READ_ONCE(promote_pg_epoch), newlevel;
	bool canpromote, candemote;
	LIST_HEAD(tier_folios);

	if (!numpages)
		return 0;
	if (numpages < 0)
		numpages *= -1;

	if (!tierinfo.tier_promote) {
		tier_head = &__tierctx.dram_cands;
		target_nid_mask = CXL_NID_MASK;
	} else if (tierinfo.tier_promote) {
		tier_head = &__tierctx.cxl_cands;
		target_nid_mask = DRAM_NID_MASK;
	} else
		return 0;

	printk(KERN_INFO "do_tiering: epoch %d, target_nid_mask %d\n",
			epochid, target_nid_mask);

	blkshift = PAGE_SHIFT + pgtemp_granularity_order;
	list_for_each_entry_safe_reverse(pos, n, tier_head, siblings) {
		blk = pos->blk;
		if (blk->tiering_state != TIERING_CANDIDATE)
			continue;
		if (blk->tiering_epoch > epochid)
			continue;

		canpromote = tierinfo.tier_promote && can_dec_demotion_level(blk);
		candemote = !tierinfo.tier_promote && can_inc_demotion_level(blk);
		if (!canpromote && !candemote)
			continue;

		list_del(&pos->siblings);
		kfree(pos);

		pid = blk->pid;
		task = find_task_by_vpid(pid);
		if (!task) {
			printk(KERN_ERR "do_tiering: task %d not found\n", pid);
			continue;
		}
		mm = get_task_mm(task);

		tierinfo.folio_list = &tier_folios;
		addr_start = blk->blocknum << blkshift;
		addr_end = addr_start + min((numpages << PAGE_SHIFT),
					(1 << (pgtemp_granularity_order + PAGE_SHIFT)));
		tierinfo.nr_migratable = 0;
		tierinfo.nr_candidates = 0;

		newlevel = tierinfo.tier_promote ? 
				prev_demotion_level(blk) : next_demotion_level(blk);
		tierinfo.oldlevel = blk->demotion_level;
		tierinfo.newlevel = newlevel;

		mmap_read_lock(mm);
		walk_page_range(mm, addr_start, addr_end,
				&tiering_core_ops, &tierinfo);
		mmap_read_unlock(mm);
		mmput(mm);

		nr_migratable += tierinfo.nr_migratable;
		nr_tried += tierinfo.nr_candidates;
		blk->tiering_state = TIERED;
		blk->demotion_level = newlevel;
	}

	printk(KERN_INFO "do_tiering: %u/%u migratable\n",
				nr_migratable, nr_tried);

	/* Migrate the folios in tier_folios */
	nr_migrated = congestier_migrate_folios(&tier_folios,
					target_nid_mask);

	printk(KERN_INFO "do_tiering: migrated %u folios\n", nr_migrated);

	try_to_unmap_flush();

	while (!list_empty(&tier_folios)) {
		folio = lru_to_folio(&tier_folios);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}
	return nr_migrated;
}

static int mk_candidate_blk(struct pg_temp_block *blk,
														int epochid)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct tiering_candidate *candidate;
	struct tiering_pgwalk_private tierinfo = {
		.nr_candidates = 0, .nr_migratable = 0,
		.tiering_candidate = NULL,
		.tier_promote = (promote_pg_epoch > 0),
		.update_blk = false, .folio_list = NULL,
	};
	uint64_t addr_start, addr_end;
	int blkshift, dlt_epochs, num_pages, nr_candidates = 0;
	pid_t pid;
	bool canpromote, candemote;

	blkshift = PAGE_SHIFT + pgtemp_granularity_order;
	dlt_epochs = dirty_latency_threshold_usecs / epoch_usecs;
	num_pages = READ_ONCE(promote_pg_epoch);
	if (!num_pages)
		return 0;
	if (num_pages < 0)
		num_pages *= -1;

	if (blk->tiering_state == NOT_TIERED) {
		blk->tiering_state = TIERING_CANDIDATE;
		blk->tiering_epoch = epochid + dlt_epochs;

		pid = blk->pid;
		addr_start = blk->blocknum << blkshift;
		addr_end = addr_start + min((num_pages << PAGE_SHIFT),
					(1 << (pgtemp_granularity_order + PAGE_SHIFT)));

		task = find_task_by_vpid(pid);
		if (!task)
			return -ENOENT;

		mm = get_task_mm(task);
		if (!mm)
			return -ENOMEM;

		candidate = kmalloc(sizeof(struct tiering_candidate), GFP_KERNEL);
		candidate->blk = blk;
		if (tierinfo.tier_promote)
			list_add(&candidate->siblings, &__tierctx.cxl_cands);
		else
			list_add(&candidate->siblings, &__tierctx.dram_cands);
		tierinfo.tiering_candidate = candidate;
		tierinfo.nr_candidates = 0;

		mmap_read_lock(mm);
		walk_page_range(mm, addr_start, addr_end,
				&tiering_mk_candidate_ops, &tierinfo);
		mmap_read_unlock(mm);
		mmput(mm);

		nr_candidates = tierinfo.nr_candidates;
	} else if (blk->tiering_state == TIERED) {
		if (blk->tiering_epoch + tiering_reset_epochs <= epochid) {
			canpromote = tierinfo.tier_promote && can_dec_demotion_level(blk);
			candemote = !tierinfo.tier_promote && can_inc_demotion_level(blk);
			if (canpromote || candemote)	
				blk->tiering_state = NOT_TIERED;
		}
	}
	return nr_candidates;
}

static void find_tiering_candidates(void)
{
	struct pg_temp_block *blk, *n;
	struct temperature_class *cls;
	int num_pages, nr_candidates = 0;

	num_pages = READ_ONCE(promote_pg_epoch);
	if (!num_pages)
		return;
	if (num_pages < 0)
		num_pages *= -1;

	for (int idx = NR_TEMPERATURE_CLASSES - 1; idx >= 0; --idx) {
		cls = get_temp_cls(idx);
		if (!cls || !cls->nr_blocks)
			continue;

		mutex_lock(&cls->templock);
		list_for_each_entry_safe(blk, n, &cls->blocks, temper_class) {
			nr_candidates += mk_candidate_blk(blk, epochid);
			if (nr_candidates >= num_pages)
				break;
		}
		mutex_unlock(&cls->templock);
	}

	printk(KERN_INFO "Tiering epoch %d: %d candidates\n",
				epochid, nr_candidates);
}

static void __commit_sysctl_vals(void)
{
	tiering_mode = READ_ONCE(sysctl_tiering_mode);
	promote_pg_epoch = READ_ONCE(sysctl_promote_pg_epoch);
	epoch_usecs = READ_ONCE(sysctl_epoch_usecs);
	tiering_epoch_usecs = READ_ONCE(sysctl_tiering_epoch_usecs);
	dirty_latency_threshold_usecs = READ_ONCE(sysctl_dirty_latency_threshold_usecs);
}

static int tiering_fn(void *data)
{
	uint64_t start, end, dur_usecs;
	int migrated = 0;

	INIT_LIST_HEAD(&__tierctx.dram_cands);
	INIT_LIST_HEAD(&__tierctx.cxl_cands);
	pgtemp_track_init();

	while (!tiering_need_stop()) {
		start = ktime_get_ns();

		migrated = 0;
		__commit_sysctl_vals();

		pgtemp_track_epoch_work(epochid);

		if (READ_ONCE(tiering_mode) == TIERING_MODE_OFF)
			goto end_epoch;

		if (epochid >= next_tiering_epoch) {
			next_tiering_epoch = epochid + (tiering_epoch_usecs / epoch_usecs);
			find_tiering_candidates();
		}
		migrated = do_tiering();

end_epoch:
		end = ktime_get_ns();
		dur_usecs = (end - start) / 1000;
		printk(KERN_INFO "Tiering epoch %d took %llu usecs, migrated %d MB\n",
					epochid, dur_usecs, migrated / 256);
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