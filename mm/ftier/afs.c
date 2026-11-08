// SPDX-License-Identifier: GPL-2.0
/*
 * FTier Adaptive Frequency Scanning (AFS), PMD level.
 *
 * Every tracked page of PMD entries (one per active PUD entry) is
 * scanned repeatedly by one of a fixed pool of scanner threads. Each
 * scan test-and-clears the accessed bit of every PMD entry in the page
 * and increments the 16-bit counter of the entries found accessed.
 * After each scan the scan period of the page adapts to the number of
 * accessed entries: fewer than low_wm slows it down, more than
 * high_wm_pct of the mapped entries speeds it up.
 *
 * A page is scanned at most scans_per_interval (S) times per
 * measurement interval. When the budget runs out early, scanning is
 * suspended until the next interval, and ftier_afs_collect() scales the
 * counts by interval / observed time.
 *
 * Scanners keep their pages in a timerqueue ordered by next deadline
 * and sleep on hrtimers in between, so sub-millisecond periods do not
 * busy-wait and the number of threads does not grow with the working
 * set.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/pagewalk.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>

#include "internal.h"

#include <trace/events/ftier.h>

struct afs_walk {
	struct ftier_pud *pud;
	u16 *counts;
	unsigned int last_idx;
	unsigned int nr_mapped;
	unsigned int nr_young;
	unsigned int flush_tlb;
	unsigned long flush_start, flush_end;	/* young entries to flush */
	bool track_thp;
	bool notify;
};

static int afs_pmd_entry(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk)
{
	struct afs_walk *w = walk->private;
	unsigned int idx = pmd_index(addr);
	pmd_t val = pmdp_get_lockless(pmd);
	unsigned long start = addr & PMD_MASK;
	int young;

	walk->action = ACTION_CONTINUE;

	/* A PMD entry spanning several VMAs is visited once per VMA. */
	if (idx == w->last_idx)
		return 0;
	w->last_idx = idx;

	if (!pmd_present(val))
		return 0;
	if (pmd_trans_huge(val) && !w->track_thp)
		return 0;

	w->nr_mapped++;
	young = pmdp_test_and_clear_young(walk->vma, addr, pmd);
	if (w->notify)
		young |= mmu_notifier_clear_young(walk->mm, start,
						  start + PMD_SIZE);
	if (young) {
		w->nr_young++;
		if (w->counts[idx] < U16_MAX)
			w->counts[idx]++;
		if (w->flush_tlb == FTIER_FLUSH_ALL ||
		    (w->flush_tlb == FTIER_FLUSH_LEAF && pmd_trans_huge(val))) {
			w->flush_start = min(w->flush_start, start);
			w->flush_end = start + PMD_SIZE;
		}
	}
	return 0;
}

static const struct mm_walk_ops afs_walk_ops = {
	.pmd_entry = afs_pmd_entry,
	.walk_lock = PGWALK_RDLOCK,
};

static unsigned int afs_adapt_period(unsigned int period_us,
				     unsigned int nr_young,
				     unsigned int nr_mapped, u64 dur_ns)
{
	unsigned int min_us = FTIER_CFG(min_period_us);
	unsigned int max_us = FTIER_CFG(max_period_us);
	unsigned int floor_us;

	/* Speed-up first: a small region with every entry hot is not idle. */
	if (nr_young && nr_young * 100 > FTIER_CFG(high_wm_pct) * nr_mapped)
		period_us /= 2;
	else if (nr_young < FTIER_CFG(low_wm))
		period_us = period_us > max_us / 2 ? max_us : period_us * 2;

	/* Spend at most half of the period scanning. */
	floor_us = max_t(u64, min_us, div_u64(dur_ns, NSEC_PER_USEC) * 2);
	return clamp(period_us, floor_us, max(floor_us, max_us));
}

/* Scan one PMD page and set the deadline of its next scan. */
static void afs_scan(struct ftier_pud *pud)
{
	struct mm_struct *mm = pud->space->mm;
	struct afs_walk w = {
		.pud = pud,
		.counts = pud->counts[READ_ONCE(pud->cur)],
		.last_idx = UINT_MAX,
		.flush_tlb = FTIER_CFG(flush_tlb),
		.flush_start = ULONG_MAX,
		.track_thp = FTIER_CFG(track_thp),
	};
	u64 now = ktime_get_ns(), t0, t1;
	u64 period_ns = (u64)pud->period_us * NSEC_PER_USEC;

	if (pud->nr_scans >= FTIER_CFG(scans_per_interval)) {
		/* Budget exhausted: resume in the next interval. */
		pud->tq.expires = max(READ_ONCE(ftier_ctx.ival_end_ns),
				      now + period_ns);
		return;
	}

	if (!mmget_not_zero(mm)) {
		/* Exiting; the main thread will untrack the space. */
		pud->tq.expires = now + (u64)FTIER_CFG(max_period_us) *
				  NSEC_PER_USEC;
		return;
	}
	/* Never queue behind a writer of the target's mmap_lock. */
	if (!mmap_read_trylock(mm)) {
		mmput(mm);
		pud->nr_lock_miss++;
		pud->tq.expires = now + period_ns;
		return;
	}

	w.notify = FTIER_CFG(notify_secondary) && mm_has_notifiers(mm);
	t0 = ktime_get_ns();
	walk_page_range(mm, pud->addr, pud->addr + PUD_SIZE,
			&afs_walk_ops, &w);
	if (w.flush_end) {
		flush_tlb_mm_range(mm, w.flush_start, w.flush_end, PMD_SHIFT,
				   false);
		pud->scanner->nr_tlb_flush++;
	}
	t1 = ktime_get_ns();
	mmap_read_unlock(mm);
	mmput(mm);

	pud->nr_mapped = w.nr_mapped;
	pud->nr_scans++;
	pud->scan_ns += t1 - t0;
	if (pud->nr_scans >= FTIER_CFG(scans_per_interval))
		pud->throttled_ns = t1;

	pud->period_us = afs_adapt_period(pud->period_us, w.nr_young,
					  w.nr_mapped, t1 - t0);
	pud->tq.expires = t0 + (u64)pud->period_us * NSEC_PER_USEC;
}

static int afs_scanner_fn(void *data)
{
	struct ftier_scanner *s = data;
	struct timerqueue_node *node;
	struct ftier_pud *pud;
	ktime_t expires;
	u64 t0;
	bool dead;

	while (!kthread_should_stop()) {
		spin_lock(&s->lock);
		node = timerqueue_getnext(&s->queue);
		if (!node || node->expires > ktime_get_ns()) {
			expires = node ? node->expires : KTIME_MAX;
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock(&s->lock);
			if (kthread_should_stop()) {
				__set_current_state(TASK_RUNNING);
				break;
			}
			if (expires == KTIME_MAX)
				schedule();
			else
				schedule_hrtimeout_range(&expires,
					(u64)FTIER_CFG(slack_us) * NSEC_PER_USEC,
					HRTIMER_MODE_ABS);
			__set_current_state(TASK_RUNNING);
			continue;
		}
		timerqueue_del(&s->queue, node);
		pud = container_of(node, struct ftier_pud, tq);
		pud->scanning = true;
		spin_unlock(&s->lock);

		t0 = ktime_get_ns();
		afs_scan(pud);
		s->busy_ns += ktime_get_ns() - t0;
		s->nr_scans++;

		spin_lock(&s->lock);
		pud->scanning = false;
		dead = pud->dead;
		if (!dead)
			timerqueue_add(&s->queue, &pud->tq);
		spin_unlock(&s->lock);
		if (dead)
			wake_up_all(&s->idle_wq);
		cond_resched();
	}
	return 0;
}

int ftier_scanners_start(unsigned int nr)
{
	struct ftier_scanner *s;
	unsigned int i;

	nr = clamp(nr, 1U, (unsigned int)FTIER_MAX_SCANNERS);
	ftier_ctx.scanners = kcalloc(nr, sizeof(*s), GFP_KERNEL);
	if (!ftier_ctx.scanners)
		return -ENOMEM;

	for (i = 0; i < nr; i++) {
		s = &ftier_ctx.scanners[i];
		s->id = i;
		spin_lock_init(&s->lock);
		timerqueue_init_head(&s->queue);
		init_waitqueue_head(&s->idle_wq);
		s->task = kthread_run(afs_scanner_fn, s, "ftier_afs/%u", i);
		if (IS_ERR(s->task)) {
			int err = PTR_ERR(s->task);

			s->task = NULL;
			ftier_ctx.nr_scanners = i;
			ftier_scanners_stop();
			return err;
		}
	}
	ftier_ctx.nr_scanners = nr;
	return 0;
}

/* All PUDs must have been dequeued. */
void ftier_scanners_stop(void)
{
	unsigned int i;

	for (i = 0; i < ftier_ctx.nr_scanners; i++) {
		struct ftier_scanner *s = &ftier_ctx.scanners[i];

		WARN_ON_ONCE(s->nr_puds);
		if (s->task)
			kthread_stop(s->task);
	}
	kfree(ftier_ctx.scanners);
	ftier_ctx.scanners = NULL;
	ftier_ctx.nr_scanners = 0;
}

struct ftier_pud *ftier_pud_alloc(struct ftier_space *space,
				  unsigned long addr)
{
	struct ftier_pud *pud;

	pud = kzalloc(sizeof(*pud), GFP_KERNEL);
	if (!pud)
		return NULL;
	pud->hot = kcalloc(FTIER_NR_PMD, sizeof(*pud->hot), GFP_KERNEL);
	if (!pud->hot) {
		kfree(pud);
		return NULL;
	}
	pud->space = space;
	pud->addr = addr & PUD_MASK;
	pud->period_us = FTIER_CFG(init_period_us);
	pud->born_ns = ktime_get_ns();
	timerqueue_init(&pud->tq);
	return pud;
}

/* Hand a new PUD to the least loaded scanner. */
void ftier_pud_enqueue(struct ftier_pud *pud)
{
	struct ftier_scanner *s = &ftier_ctx.scanners[0];
	unsigned int i;
	bool first;

	for (i = 1; i < ftier_ctx.nr_scanners; i++)
		if (ftier_ctx.scanners[i].nr_puds < s->nr_puds)
			s = &ftier_ctx.scanners[i];

	pud->scanner = s;
	pud->tq.expires = ktime_get_ns();
	spin_lock(&s->lock);
	s->nr_puds++;
	first = timerqueue_add(&s->queue, &pud->tq);
	spin_unlock(&s->lock);
	if (first)
		wake_up_process(s->task);
}

/* Remove a PUD from its scanner, waiting for an ongoing scan of it. */
void ftier_pud_dequeue(struct ftier_pud *pud)
{
	struct ftier_scanner *s = pud->scanner;

	if (!s)
		return;
	spin_lock(&s->lock);
	if (pud->scanning) {
		pud->dead = true;
		spin_unlock(&s->lock);
		wait_event(s->idle_wq, !READ_ONCE(pud->scanning));
		spin_lock(&s->lock);
	} else {
		timerqueue_del(&s->queue, &pud->tq);
	}
	s->nr_puds--;
	spin_unlock(&s->lock);
	pud->scanner = NULL;
}

void ftier_pud_free(struct ftier_pud *pud)
{
	int i;

	for (i = 0; i < FTIER_NR_PMD; i++)
		if (pud->hot[i])
			ftier_hotlist_remove(&ftier_ctx.hotlist, pud->hot[i]);
	kfree(pud->hot);
	kfree(pud);
}

/**
 * ftier_afs_collect - close the measurement interval of a PMD page
 * @pud: AFS state of the PMD page
 * @now: time the interval is closed
 * @cfg_ns: configured interval length
 *
 * Swaps the count buffers and reports the counts of the closed interval
 * to the Hotlist, normalised to @cfg_ns over the time actually observed:
 * if scanning was suspended after S scans, counts are scaled up by the
 * fraction of the interval not observed. Called by the main thread.
 */
void ftier_afs_collect(struct ftier_pud *pud, u64 now, u64 cfg_ns)
{
	struct ftier_scanner *s = pud->scanner;
	u64 start = max(ftier_ctx.ival_start_ns, pud->born_ns);
	u64 throttled_ns, scan_ns, end, observed;
	u32 nr_scans, nr_lock_miss;
	unsigned int i, nr_hot = 0;
	u16 *counts;

	spin_lock(&s->lock);
	while (pud->scanning) {
		spin_unlock(&s->lock);
		cpu_relax();
		spin_lock(&s->lock);
	}
	counts = pud->counts[pud->cur];
	pud->cur ^= 1;
	nr_scans = pud->nr_scans;
	throttled_ns = pud->throttled_ns;
	scan_ns = pud->scan_ns;
	nr_lock_miss = pud->nr_lock_miss;
	pud->nr_scans = 0;
	pud->throttled_ns = 0;
	pud->scan_ns = 0;
	pud->nr_lock_miss = 0;
	spin_unlock(&s->lock);

	/* Assume a stationary access rate over the interval. */
	end = now;
	if (throttled_ns) {
		end = throttled_ns;
		ftier_ctx.stats.nr_throttled++;
	}
	observed = end > start ? end - start : 0;
	/* Bound the extrapolation from very short observations. */
	observed = max(observed, div_u64(cfg_ns, 1U << 10));

	for (i = 0; i < FTIER_NR_PMD; i++) {
		if (!counts[i])
			continue;
		nr_hot++;
		ftier_hotlist_add(&ftier_ctx.hotlist, pud, i,
			min_t(u64, div64_u64((u64)counts[i] * cfg_ns, observed),
			      U32_MAX));
		counts[i] = 0;
	}

	pud->total_scans += nr_scans;
	ftier_ctx.stats.nr_lock_miss += nr_lock_miss;
	trace_fspin(pud->space->tgid, pud->addr, nr_scans, pud->period_us,
		    div_u64(scan_ns, NSEC_PER_USEC), nr_hot, pud->nr_mapped,
		    div64_u64(cfg_ns * 1000, observed));
}
