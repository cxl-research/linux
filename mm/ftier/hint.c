// SPDX-License-Identifier: GPL-2.0
/*
 * FTier hint-fault filter.
 *
 * In hint-fault mode the tiering loop protects the pages of selected
 * Hotlist regions and stamps them with the current time. The next access
 * to such a page raises a NUMA hint fault, and ftier_hint_fault() decides
 * whether the page migrates: only if the time since protection (the hint
 * fault latency) is below a threshold, i.e. if the page is accessed at
 * least about as often as the threshold implies.
 *
 * The threshold comes from one of:
 *  - median: 1/h for the median access frequency h of the regions
 *    selected in the current migration round (the FTier design);
 *  - fixed: hint_max_ms;
 *  - histogram: the pre-rework filter, passing the hint_pass_bp fraction
 *    of recent faults with the lowest latency on each tier.
 *
 * Migrations are also bounded by a credit of pages, refilled by the
 * tiering loop from the target migration rate, so that the fault path
 * enforces the global migration-rate cap.
 *
 * Runs with the page table lock held: lock-free and non-sleeping.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/topology.h>

#include "internal.h"

#include <trace/events/ftier.h>

struct ftier_hint ftier_hint;

/*
 * Histogram mode. Bucket i < 1000 holds latencies of i ms, then 500 ms
 * steps up to 10 s, then 10 s steps up to 60 s. Updated racily by the
 * fault path (statistics only), aged and evaluated by the main thread.
 */
#define HIST_LEN	1024
static unsigned int hint_hist[2][HIST_LEN];	/* [is_cxl][bucket] */
static int hist_thresh_ms[2] = { 60000, 60000 };
static unsigned long hist_aged_jiffies;

static int hist_idx(int ms)
{
	if (ms < 1000)
		return ms;
	if (ms < 10000)
		return 1000 + (ms - 1000) / 500;
	return 1018 + min((ms - 10000) / 10000, 5);
}

static int hist_ms(int idx)
{
	if (idx < 1000)
		return idx;
	if (idx < 1018)
		return 1000 + (idx - 1000) * 500;
	return 10000 + (idx - 1018) * 10000;
}

static int hist_threshold(const unsigned int *hist, unsigned int pass_bp)
{
	long sum = 0, left;
	int i;

	for (i = 0; i < HIST_LEN; i++)
		sum += hist[i];
	left = sum * pass_bp / 10000;
	for (i = 0; i < HIST_LEN; i++) {
		left -= hist[i];
		if (left <= 0 && sum)
			return hist_ms(i);
	}
	return 60000;
}

/* Main thread: halve the histograms every second, recompute thresholds. */
void ftier_hint_age(void)
{
	unsigned long now = jiffies;
	unsigned int secs, t, i;

	if (FTIER_CFG(hint_mode) != FTIER_HINT_HISTOGRAM)
		return;
	if (time_before(now, hist_aged_jiffies + HZ))
		return;
	secs = min_t(unsigned long, (now - hist_aged_jiffies) / HZ, 32);
	hist_aged_jiffies = now;

	if (trace_fhint_enabled()) {
		trace_fhint(-1, hist_thresh_ms[0], hist_thresh_ms[1]);
		for (i = 0; i < HIST_LEN; i++)
			if (hint_hist[0][i] || hint_hist[1][i])
				trace_fhint(i, hint_hist[0][i], hint_hist[1][i]);
	}
	for (t = 0; t < 2; t++) {
		for (i = 0; i < HIST_LEN; i++)
			WRITE_ONCE(hint_hist[t][i], hint_hist[t][i] >> secs);
		WRITE_ONCE(hist_thresh_ms[t],
			   hist_threshold(hint_hist[t], FTIER_CFG(hint_pass_bp)));
	}
}

void ftier_hint_set_thresh(int ms)
{
	WRITE_ONCE(ftier_hint.thresh_ms, ms);
}

/* Add @pages of migration credit, keeping at most @max. */
void ftier_hint_refill(long pages, long max)
{
	long old = atomic_long_read(&ftier_hint.credit), new;

	do {
		new = clamp(old + pages, 0L, max);
	} while (!atomic_long_try_cmpxchg(&ftier_hint.credit, &old, new));
}

void ftier_hint_reset(void)
{
	atomic_long_set(&ftier_hint.credit, 0);
	atomic_long_set(&ftier_hint.nr_faults, 0);
	atomic_long_set(&ftier_hint.nr_migrate, 0);
	atomic_long_set(&ftier_hint.nr_reject_tier, 0);
	atomic_long_set(&ftier_hint.nr_reject_lat, 0);
	atomic_long_set(&ftier_hint.nr_reject_rate, 0);
	WRITE_ONCE(ftier_hint.thresh_ms, FTIER_CFG(hint_max_ms));
	memset(hint_hist, 0, sizeof(hint_hist));
	hist_thresh_ms[0] = hist_thresh_ms[1] = 60000;
	hist_aged_jiffies = jiffies;
}

/* Prefer the faulting CPU's node, else round-robin over the tier. */
static int hint_target(const nodemask_t *dst)
{
	static atomic_t rr = ATOMIC_INIT(0);
	unsigned int n, k;
	int nid = numa_node_id();

	if (node_isset(nid, *dst))
		return nid;
	n = nodes_weight(*dst);
	if (!n)
		return NUMA_NO_NODE;
	k = (unsigned int)atomic_inc_return(&rr) % n;
	for_each_node_mask(nid, *dst)
		if (!k--)
			return nid;
	return NUMA_NO_NODE;
}

/**
 * ftier_hint_fault - decide whether a hint-faulting folio migrates
 * @folio: folio whose protected mapping was accessed
 *
 * Called from the NUMA hint fault path of FTier target processes with
 * the page table lock held.
 *
 * Return: the node to migrate @folio to, or NUMA_NO_NODE.
 */
int ftier_hint_fault(struct folio *folio)
{
	int promote_mb = READ_ONCE(sysctl_promote_mb);
	long nr = folio_nr_pages(folio);
	int src = folio_nid(folio), now, lat, thresh, nid;
	bool promote = promote_mb > 0, cxl;

	atomic_long_inc(&ftier_hint.nr_faults);
	cxl = ftier_node_is_cxl(src);
	if (!promote_mb || (promote ? !cxl : !ftier_node_is_dram(src))) {
		atomic_long_inc(&ftier_hint.nr_reject_tier);
		return NUMA_NO_NODE;
	}

	now = jiffies_to_msecs(jiffies);
	lat = (now - folio_xchg_access_time(folio, now)) & PAGE_ACCESS_TIME_MASK;

	if (FTIER_CFG(hint_mode) == FTIER_HINT_HISTOGRAM) {
		unsigned int *b = &hint_hist[cxl][hist_idx(lat)];

		data_race((*b)++);
		thresh = READ_ONCE(hist_thresh_ms[cxl]);
	} else {
		thresh = READ_ONCE(ftier_hint.thresh_ms);
	}
	if (lat > thresh) {
		atomic_long_inc(&ftier_hint.nr_reject_lat);
		return NUMA_NO_NODE;
	}

	if (atomic_long_sub_return(nr, &ftier_hint.credit) < 0) {
		atomic_long_add(nr, &ftier_hint.credit);
		atomic_long_inc(&ftier_hint.nr_reject_rate);
		return NUMA_NO_NODE;
	}

	nid = hint_target(promote ? &ftier_dram_nodes : &ftier_cxl_nodes);
	if (nid == NUMA_NO_NODE) {
		atomic_long_add(nr, &ftier_hint.credit);
		return NUMA_NO_NODE;
	}
	atomic_long_add(nr, &ftier_hint.nr_migrate);
	return nid;
}
