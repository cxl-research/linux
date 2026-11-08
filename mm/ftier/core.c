// SPDX-License-Identifier: GPL-2.0
/*
 * FTier core: targets, tracked address spaces, PUD-level scanning and
 * the main thread.
 *
 * Locking:
 *  - ftier_state_lock (outer) serialises state changes from sysfs:
 *    start/stop, target and tunable updates.
 *  - ftier_lock protects the target, the tracked spaces and their PUDs,
 *    and the Hotlist. The main thread holds it while it works and drops
 *    it while sleeping; scanners never take it.
 *  - Each scanner's lock protects its queue and the scan state of the
 *    PUDs it owns (see afs.c).
 *
 * Address spaces are pinned with mmgrab() and only walked after
 * mmget_not_zero() under mmap_read_lock(), so the exit or pid reuse of
 * a target never leaves FTier with dangling pointers.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/cgroup.h>
#include <linux/hashtable.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/memory-tiers.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/oom.h>
#include <linux/pagewalk.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ftier.h>

struct ftier_config ftier_cfg = {
	.tick_ms		= 100,
	.interval_ms		= 1000,
	.fscan_period_ms	= 10000,
	.pud_idle_scans		= 1,
	.scans_per_interval	= 1000,
	.init_period_us		= 50000,	/* 20 Hz */
	.min_period_us		= 50,
	.max_period_us		= 500000,
	.low_wm			= 3,
	.high_wm_pct		= 60,
	.slack_us		= 20,
	.cool_ms		= 2000,
	.nr_scanners		= 4,
	.track_thp		= true,
	.notify_secondary	= true,
	.flush_tlb		= FTIER_FLUSH_NEVER,
	.migrate_batch		= 512,
	.max_migrate_mbps	= 1024,
	.max_candidates		= 256,
	.residency_epochs	= 8,
	.hint_mode		= FTIER_HINT_MEDIAN,
	.hint_min_ms		= 1,
	.hint_max_ms		= 1000,
	.hint_pass_bp		= 10000,
	.level_adapt		= true,
	.level_period_ms	= 1000,
	.level_small_pct	= 25,
	.level_full_pct		= 90,
	.level_jump_pct		= 50,
	.level_progress_pct	= 10,
	.level_deadband_pm	= 20,
	.monitor_timeout_ms	= 0,
};

nodemask_t ftier_dram_nodes;
nodemask_t ftier_cxl_nodes;
EXPORT_SYMBOL_GPL(ftier_dram_nodes);
EXPORT_SYMBOL_GPL(ftier_cxl_nodes);

/*
 * Default tiers. The FTier evaluation server has DRAM node 1 (node 0
 * runs everything else) and CPU-less CXL nodes 2 and 3: keep that layout
 * where it applies. Otherwise, memory nodes in the top memory tier are
 * DRAM and the remaining memory nodes are CXL.
 */
int ftier_nodes_init(void)
{
	nodemask_t dram = NODE_MASK_NONE, cxl = NODE_MASK_NONE;
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		if (nid > 1 && !node_state(nid, N_CPU))
			node_set(nid, cxl);
	}
	if (node_state(1, N_MEMORY) && node_state(1, N_CPU) &&
	    !nodes_empty(cxl)) {
		node_set(1, dram);
	} else {
		nodes_clear(cxl);
		for_each_node_state(nid, N_MEMORY) {
			if (node_is_toptier(nid))
				node_set(nid, dram);
			else
				node_set(nid, cxl);
		}
	}
	ftier_dram_nodes = dram;
	ftier_cxl_nodes = cxl;
	pr_info("ftier: DRAM nodes %*pbl, CXL nodes %*pbl\n",
		nodemask_pr_args(&dram), nodemask_pr_args(&cxl));
	return 0;
}

struct ftier_ctx ftier_ctx = {
	.spaces = LIST_HEAD_INIT(ftier_ctx.spaces),
};

DEFINE_MUTEX(ftier_lock);
DEFINE_MUTEX(ftier_state_lock);

/* Tracked mms, looked up locklessly from the hint-fault path. */
static DEFINE_HASHTABLE(ftier_mm_hash, 8);

/**
 * ftier_mm_is_target - is @mm currently tracked by FTier?
 * @mm: address space
 *
 * Safe from any context. The result may be stale by an RCU grace period.
 */
bool ftier_mm_is_target(struct mm_struct *mm)
{
	struct ftier_space *sp;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(ftier_mm_hash, sp, hnode, (unsigned long)mm) {
		if (sp->mm == mm) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static struct ftier_space *space_find(struct mm_struct *mm)
{
	struct ftier_space *sp;

	lockdep_assert_held(&ftier_lock);
	hash_for_each_possible(ftier_mm_hash, sp, hnode, (unsigned long)mm)
		if (sp->mm == mm)
			return sp;
	return NULL;
}

static struct ftier_space *space_create(struct mm_struct *mm, pid_t tgid)
{
	struct ftier_space *sp;

	sp = kzalloc(sizeof(*sp), GFP_KERNEL);
	if (!sp)
		return NULL;
	mmgrab(mm);
	sp->mm = mm;
	sp->tgid = tgid;
	xa_init(&sp->puds);
	list_add_tail(&sp->link, &ftier_ctx.spaces);
	hash_add_rcu(ftier_mm_hash, &sp->hnode, (unsigned long)mm);
	ftier_ctx.nr_spaces++;
	ftier_ctx.stats.nr_space_added++;
	return sp;
}

static void space_remove_pud(struct ftier_space *sp, unsigned long idx,
			     struct ftier_pud *pud)
{
	ftier_pud_dequeue(pud);
	xa_erase(&sp->puds, idx);
	sp->nr_puds--;
	ftier_pud_free(pud);
	ftier_ctx.stats.nr_pud_removed++;
}

static void space_destroy(struct ftier_space *sp)
{
	struct ftier_pud *pud;
	unsigned long idx;

	xa_for_each(&sp->puds, idx, pud)
		space_remove_pud(sp, idx, pud);
	xa_destroy(&sp->puds);
	list_del(&sp->link);
	hash_del_rcu(&sp->hnode);
	ftier_ctx.nr_spaces--;
	ftier_ctx.stats.nr_space_removed++;
	/*
	 * Lockless readers only compare the mm pointer, so the mm may go
	 * before the grace period ends; the space itself may not.
	 */
	mmdrop(sp->mm);
	kfree_rcu(sp, rcu);
}

static void destroy_all_spaces(void)
{
	struct ftier_space *sp, *tmp;

	list_for_each_entry_safe(sp, tmp, &ftier_ctx.spaces, link)
		space_destroy(sp);
}

struct fscan_walk {
	struct ftier_space *sp;
	unsigned long last_idx;
	u64 gen;
	bool notify;
	unsigned int nr_young;
};

static int fscan_pud_entry(pud_t *pudp, unsigned long addr,
			   unsigned long next, struct mm_walk *walk)
{
	struct fscan_walk *w = walk->private;
	unsigned long idx = addr >> PUD_SHIFT;
	unsigned long start = addr & PUD_MASK;
	pud_t val = READ_ONCE(*pudp);
	struct ftier_pud *pud;
	int young;

	walk->action = ACTION_CONTINUE;

	/* A PUD entry spanning several VMAs is visited once per VMA. */
	if (idx == w->last_idx)
		return 0;
	w->last_idx = idx;

	/* Only PUD entries referencing a page of PMD entries. */
	if (!pud_present(val) || pud_leaf(val))
		return 0;

	young = pudp_test_and_clear_young(walk->vma, addr, pudp);
	if (w->notify)
		young |= mmu_notifier_clear_young(walk->mm, start,
						  start + PUD_SIZE);
	w->nr_young += !!young;

	pud = xa_load(&w->sp->puds, idx);
	if (!pud) {
		if (!young)
			return 0;
		pud = ftier_pud_alloc(w->sp, start);
		if (!pud)
			return 0;
		if (xa_err(xa_store(&w->sp->puds, idx, pud, GFP_KERNEL))) {
			ftier_pud_free(pud);
			return 0;
		}
		w->sp->nr_puds++;
		ftier_ctx.stats.nr_pud_added++;
		ftier_pud_enqueue(pud);
	}
	pud->seen_gen = w->gen;
	pud->idle_fscans = young ? 0 : pud->idle_fscans + 1;
	return 0;
}

static const struct mm_walk_ops fscan_walk_ops = {
	.pud_entry = fscan_pud_entry,
	.walk_lock = PGWALK_RDLOCK,
};

/* PUD-level scan of one address space. @mm holds an mm_users ref. */
static void fscan_mm(struct mm_struct *mm, pid_t tgid)
{
	struct ftier_space *sp = space_find(mm);
	struct fscan_walk w = { .last_idx = ULONG_MAX, .gen = ftier_ctx.gen };
	struct ftier_pud *pud;
	unsigned long idx;
	u64 t0;

	if (sp && sp->seen_gen == ftier_ctx.gen)
		return;		/* another thread of a scanned process */
	if (!sp)
		sp = space_create(mm, tgid);
	if (!sp)
		return;
	sp->seen_gen = ftier_ctx.gen;
	w.sp = sp;

	t0 = ktime_get_ns();
	if (mmap_read_lock_killable(mm))
		return;
	w.notify = FTIER_CFG(notify_secondary) && mm_has_notifiers(mm);
	walk_page_range(mm, 0, mm->task_size, &fscan_walk_ops, &w);
	mmap_read_unlock(mm);

	/* Untrack PUDs that were unmapped or stayed idle for too long. */
	xa_for_each(&sp->puds, idx, pud) {
		if (pud->seen_gen != ftier_ctx.gen ||
		    pud->idle_fscans > FTIER_CFG(pud_idle_scans))
			space_remove_pud(sp, idx, pud);
	}

	trace_fscan(tgid, sp->nr_puds,
		    div_u64(ktime_get_ns() - t0, NSEC_PER_USEC));
}

static void fscan_task(struct task_struct *task)
{
	struct task_struct *t;
	struct mm_struct *mm;
	pid_t tgid;

	/* The group leader may be a zombie while other threads run. */
	t = find_lock_task_mm(task);
	if (!t)
		return;
	mm = t->mm;
	if (t->flags & PF_KTHREAD) {
		task_unlock(t);
		return;
	}
	mmget(mm);
	tgid = task_tgid_nr(t);
	task_unlock(t);

	fscan_mm(mm, tgid);
	mmput(mm);
}

static void ftier_fscan(void)
{
	struct ftier_space *sp, *tmp;
	struct task_struct *task;
	struct css_task_iter it;
	u64 t0 = ktime_get_ns();

	ftier_ctx.gen++;

	switch (ftier_ctx.type) {
	case FTIER_TARGET_PID:
		task = get_pid_task(ftier_ctx.pid, PIDTYPE_PID);
		if (task) {
			fscan_task(task);
			put_task_struct(task);
		}
		break;
	case FTIER_TARGET_CGROUP:
		css_task_iter_start(&ftier_ctx.cgrp->self, 0, &it);
		while ((task = css_task_iter_next(&it)))
			fscan_task(task);
		css_task_iter_end(&it);
		break;
	default:
		break;
	}

	/* Processes that exited or left the target. */
	list_for_each_entry_safe(sp, tmp, &ftier_ctx.spaces, link)
		if (sp->seen_gen != ftier_ctx.gen)
			space_destroy(sp);

	ftier_ctx.stats.nr_fscans++;
	ftier_ctx.stats.fscan_ns += ktime_get_ns() - t0;
}

static void ftier_close_interval(u64 now)
{
	u64 cfg_ns = (u64)FTIER_CFG(interval_ms) * NSEC_PER_MSEC;
	struct ftier_space *sp;
	struct ftier_pud *pud;
	unsigned long idx;

	list_for_each_entry(sp, &ftier_ctx.spaces, link) {
		xa_for_each(&sp->puds, idx, pud) {
			ftier_afs_collect(pud, now, cfg_ns);
			cond_resched();
		}
	}

	ftier_ctx.stats.nr_intervals++;
	ftier_ctx.stats.collect_ns += ktime_get_ns() - now;
	WRITE_ONCE(ftier_ctx.ival_start_ns, now);
	WRITE_ONCE(ftier_ctx.ival_end_ns, now + cfg_ns);
}

static void ftier_cool(void)
{
	struct ftier_hotlist *hl = &ftier_ctx.hotlist;
	unsigned int level, nr;

	ftier_hotlist_cool(hl);
	ftier_ctx.stats.nr_cool++;
	trace_fhotlist(hl->epoch, hl->nr_entries, hl->nr_discarded);
	if (trace_fhist_enabled()) {
		for (level = 0; level < FTIER_HOT_LEVELS; level++) {
			nr = hl->nr[ftier_hotlist_pos(hl, level)];
			if (nr)
				trace_fhist(level, nr * (PMD_SIZE >> 20));
		}
	}
}

static int ftier_main_fn(void *unused)
{
	u64 t0, tick_ns, budget_ns, elapsed;
	ktime_t wake;

	while (!kthread_should_stop()) {
		tick_ns = (u64)FTIER_CFG(tick_ms) * NSEC_PER_MSEC;

		mutex_lock(&ftier_lock);
		t0 = ktime_get_ns();

		if (t0 >= ftier_ctx.next_fscan_ns) {
			ftier_fscan();
			ftier_ctx.next_fscan_ns = t0 +
				(u64)FTIER_CFG(fscan_period_ms) * NSEC_PER_MSEC;
		}

		if (t0 >= ftier_ctx.ival_end_ns)
			ftier_close_interval(ktime_get_ns());

		if (t0 >= ftier_ctx.next_cool_ns) {
			ftier_cool();
			ftier_ctx.next_cool_ns = t0 +
				(u64)FTIER_CFG(cool_ms) * NSEC_PER_MSEC;
		}

		elapsed = ktime_get_ns() - t0;
		budget_ns = tick_ns * 9 / 10;
		if (READ_ONCE(ftier_ctx.tiering)) {
			ftier_hint_age();
			if (elapsed < budget_ns)
				ftier_tier_tick(FTIER_CFG(tick_ms),
						budget_ns - elapsed);
		}

		elapsed = ktime_get_ns() - t0;
		if (elapsed > tick_ns)
			ftier_ctx.stats.nr_overrun++;
		mutex_unlock(&ftier_lock);

		wake = t0 + tick_ns;
		set_current_state(TASK_INTERRUPTIBLE);
		if (!kthread_should_stop() && ktime_get_ns() < wake)
			schedule_hrtimeout_range(&wake, NSEC_PER_MSEC,
						 HRTIMER_MODE_ABS);
		__set_current_state(TASK_RUNNING);
	}
	return 0;
}

static void clear_target_locked(void)
{
	lockdep_assert_held(&ftier_lock);
	destroy_all_spaces();
	put_pid(ftier_ctx.pid);
	ftier_ctx.pid = NULL;
	if (ftier_ctx.cgrp)
		cgroup_put(ftier_ctx.cgrp);
	ftier_ctx.cgrp = NULL;
	ftier_ctx.type = FTIER_TARGET_NONE;
}

/* Rescan the target as soon as possible. */
void ftier_kick(void)
{
	ftier_ctx.next_fscan_ns = 0;
	if (ftier_ctx.task)
		wake_up_process(ftier_ctx.task);
}

/**
 * ftier_set_target_pid - track the process that @nr belongs to
 * @nr: pid or tid in the caller's namespace; <= 0 clears the target
 */
int ftier_set_target_pid(pid_t nr)
{
	struct task_struct *task;
	struct pid *pid = NULL;

	if (nr > 0) {
		pid = find_get_pid(nr);
		if (!pid)
			return -ESRCH;
		task = get_pid_task(pid, PIDTYPE_PID);
		if (!task) {
			put_pid(pid);
			return -ESRCH;
		}
		put_task_struct(task);
	}

	mutex_lock(&ftier_lock);
	clear_target_locked();
	if (pid) {
		ftier_ctx.type = FTIER_TARGET_PID;
		ftier_ctx.pid = pid;
	}
	ftier_kick();
	mutex_unlock(&ftier_lock);
	return 0;
}

/**
 * ftier_set_target_cgroup - track all processes of a cgroup v2
 * @path: path relative to the cgroup v2 root; NULL clears the target
 */
int ftier_set_target_cgroup(const char *path)
{
	struct cgroup *cgrp = NULL;

	if (path) {
		cgrp = cgroup_get_from_path(path);
		if (IS_ERR(cgrp))
			return PTR_ERR(cgrp);
	}

	mutex_lock(&ftier_lock);
	clear_target_locked();
	if (cgrp) {
		ftier_ctx.type = FTIER_TARGET_CGROUP;
		ftier_ctx.cgrp = cgrp;
	}
	ftier_kick();
	mutex_unlock(&ftier_lock);
	return 0;
}

void ftier_set_tiering(bool on)
{
	WRITE_ONCE(ftier_ctx.tiering, on);
	/* Pages protected earlier must not migrate once tiering stops. */
	if (!on)
		atomic_long_set(&ftier_hint.credit, 0);
}

/* Called with ftier_state_lock held. */
int ftier_start(void)
{
	struct task_struct *task;
	u64 now;
	int err;

	lockdep_assert_held(&ftier_state_lock);
	if (ftier_ctx.task)
		return -EBUSY;

	err = ftier_hotlist_cache_init();
	if (err)
		return err;

	mutex_lock(&ftier_lock);
	ftier_hotlist_init(&ftier_ctx.hotlist);
	ftier_tier_reset();
	memset(&ftier_ctx.stats, 0, sizeof(ftier_ctx.stats));
	now = ktime_get_ns();
	ftier_ctx.next_fscan_ns = now;
	ftier_ctx.next_cool_ns = now + (u64)FTIER_CFG(cool_ms) * NSEC_PER_MSEC;
	WRITE_ONCE(ftier_ctx.ival_start_ns, now);
	WRITE_ONCE(ftier_ctx.ival_end_ns,
		   now + (u64)FTIER_CFG(interval_ms) * NSEC_PER_MSEC);
	err = ftier_scanners_start(FTIER_CFG(nr_scanners));
	mutex_unlock(&ftier_lock);
	if (err)
		return err;

	task = kthread_run(ftier_main_fn, NULL, "ftier");
	if (IS_ERR(task)) {
		ftier_scanners_stop();
		return PTR_ERR(task);
	}
	ftier_ctx.task = task;
	return 0;
}

/* Called with ftier_state_lock held. */
void ftier_stop(void)
{
	lockdep_assert_held(&ftier_state_lock);
	if (!ftier_ctx.task)
		return;

	ftier_set_tiering(false);
	kthread_stop(ftier_ctx.task);
	ftier_ctx.task = NULL;

	mutex_lock(&ftier_lock);
	clear_target_locked();
	ftier_hotlist_destroy(&ftier_ctx.hotlist);
	mutex_unlock(&ftier_lock);

	ftier_scanners_stop();
}
