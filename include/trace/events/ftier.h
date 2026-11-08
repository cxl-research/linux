/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ftier

#if !defined(_TRACE_FTIER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FTIER_H

#include <linux/types.h>
#include <linux/tracepoint.h>

/* PUD-level scan of one tracked process. */
TRACE_EVENT(fscan,

	TP_PROTO(int pid, unsigned int nr_fhot, unsigned int dur_us),

	TP_ARGS(pid, nr_fhot, dur_us),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned int, nr_fhot)
		__field(unsigned int, dur_us)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->nr_fhot = nr_fhot;
		__entry->dur_us = dur_us;
	),

	TP_printk("pid=%d, nr_fhot=%u, dur=%u us",
			__entry->pid, __entry->nr_fhot, __entry->dur_us)
);

/* End of a measurement interval of one page of PMD entries (AFS). */
TRACE_EVENT(fspin,

	TP_PROTO(int pid, unsigned long addr, unsigned int spins,
		unsigned int spin_period_final_us, unsigned int dur_sum_us,
		unsigned int hot, unsigned int mapped, unsigned int scale_pm),

	TP_ARGS(pid, addr, spins, spin_period_final_us,
			dur_sum_us, hot, mapped, scale_pm),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned long, addr)
		__field(unsigned int, spins)
		__field(unsigned int, spin_period_final_us)
		__field(unsigned int, dur_sum_us)
		__field(unsigned int, hot)
		__field(unsigned int, mapped)
		__field(unsigned int, scale_pm)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->addr = addr;
		__entry->spins = spins;
		__entry->spin_period_final_us = spin_period_final_us;
		__entry->dur_sum_us = dur_sum_us;
		__entry->hot = hot;
		__entry->mapped = mapped;
		__entry->scale_pm = scale_pm;
	),

	TP_printk("pid=%d, addr=%lx, spins=%u, spin_period_final=%u us,"
			" dur_sum=%u us, hot=%u, mapped=%u, scale=%u.%03u",
			__entry->pid, __entry->addr, __entry->spins,
			__entry->spin_period_final_us, __entry->dur_sum_us,
			__entry->hot, __entry->mapped,
			__entry->scale_pm / 1000, __entry->scale_pm % 1000)
);

/* Hotlist level occupancy: @mb of tracked data at log2 hotness @hotval. */
TRACE_EVENT(fhist,

	TP_PROTO(unsigned int hotval, unsigned int mb),

	TP_ARGS(hotval, mb),

	TP_STRUCT__entry(
		__field(unsigned int, hotval)
		__field(unsigned int, mb)
	),

	TP_fast_assign(
		__entry->hotval = hotval;
		__entry->mb = mb;
	),

	TP_printk("hotval=%u, mb=%u", __entry->hotval, __entry->mb)
);

/* Hotlist cooling step. */
TRACE_EVENT(fhotlist,

	TP_PROTO(u32 epoch, unsigned long nr_entries, u64 nr_discarded),

	TP_ARGS(epoch, nr_entries, nr_discarded),

	TP_STRUCT__entry(
		__field(u32, epoch)
		__field(unsigned long, nr_entries)
		__field(u64, nr_discarded)
	),

	TP_fast_assign(
		__entry->epoch = epoch;
		__entry->nr_entries = nr_entries;
		__entry->nr_discarded = nr_discarded;
	),

	TP_printk("epoch=%u, entries=%lu, discarded=%llu",
		  __entry->epoch, __entry->nr_entries, __entry->nr_discarded)
);

/* One tiering tick. */
TRACE_EVENT(fmigrate,

	TP_PROTO(unsigned int regions, unsigned int skipped,
		 unsigned long pages, unsigned long failed,
		 unsigned int budget_us, unsigned int dur_us,
		 unsigned int level, bool promote, unsigned long max_pages),

	TP_ARGS(regions, skipped, pages, failed, budget_us,
		dur_us, level, promote, max_pages),

	TP_STRUCT__entry(
		__field(unsigned int, regions)
		__field(unsigned int, skipped)
		__field(unsigned long, pages)
		__field(unsigned long, failed)
		__field(unsigned int, budget_us)
		__field(unsigned int, dur_us)
		__field(unsigned int, level)
		__field(bool, promote)
		__field(unsigned long, max_pages)
	),

	TP_fast_assign(
		__entry->regions = regions;
		__entry->skipped = skipped;
		__entry->pages = pages;
		__entry->failed = failed;
		__entry->budget_us = budget_us;
		__entry->dur_us = dur_us;
		__entry->level = level;
		__entry->promote = promote;
		__entry->max_pages = max_pages;
	),

	TP_printk("regions=%u, skipped=%u, pages=%lu, failed=%lu,"
		  " budget_us=%u, dur_us=%u, level=%u, promote=%d,"
		  " max_pages=%lu",
		  __entry->regions, __entry->skipped, __entry->pages,
		  __entry->failed, __entry->budget_us, __entry->dur_us,
		  __entry->level, __entry->promote, __entry->max_pages)
);

/* One candidate region (PMD entry) handled by a tiering tick. */
TRACE_EVENT(fregion,

	TP_PROTO(int pid, unsigned long addr, bool promote, bool hint,
		 unsigned long nr_src, unsigned long nr_dst,
		 unsigned long nr_isolated, long nr_done),

	TP_ARGS(pid, addr, promote, hint, nr_src, nr_dst, nr_isolated,
		nr_done),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned long, addr)
		__field(bool, promote)
		__field(bool, hint)
		__field(unsigned long, nr_src)
		__field(unsigned long, nr_dst)
		__field(unsigned long, nr_isolated)
		__field(long, nr_done)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->addr = addr;
		__entry->promote = promote;
		__entry->hint = hint;
		__entry->nr_src = nr_src;
		__entry->nr_dst = nr_dst;
		__entry->nr_isolated = nr_isolated;
		__entry->nr_done = nr_done;
	),

	TP_printk("pid=%d, addr=%lx, promote=%d, hint=%d, src=%lu, dst=%lu,"
		  " isolated=%lu, done=%ld",
		  __entry->pid, __entry->addr, __entry->promote,
		  __entry->hint, __entry->nr_src, __entry->nr_dst,
		  __entry->nr_isolated, __entry->nr_done)
);

/* A tier measurement reported by a latency monitor. */
TRACE_EVENT(ftier_tier,

	TP_PROTO(u64 dram_lat, u64 cxl_lat, u64 dram_mbps, u64 cxl_mbps,
		 int promote_mb),

	TP_ARGS(dram_lat, cxl_lat, dram_mbps, cxl_mbps, promote_mb),

	TP_STRUCT__entry(
		__field(u64, dram_lat)
		__field(u64, cxl_lat)
		__field(u64, dram_mbps)
		__field(u64, cxl_mbps)
		__field(int, promote_mb)
	),

	TP_fast_assign(
		__entry->dram_lat = dram_lat;
		__entry->cxl_lat = cxl_lat;
		__entry->dram_mbps = dram_mbps;
		__entry->cxl_mbps = cxl_mbps;
		__entry->promote_mb = promote_mb;
	),

	TP_printk("dram_lat=%llu, cxl_lat=%llu, dram_mbps=%llu,"
		  " cxl_mbps=%llu, promote_mb=%d",
		  __entry->dram_lat, __entry->cxl_lat, __entry->dram_mbps,
		  __entry->cxl_mbps, __entry->promote_mb)
);

/* Adaptation of the hotness level of migration candidates. */
TRACE_EVENT(flevel,

	TP_PROTO(unsigned int level_off, int gap_pm, int prev_gap_pm,
		 unsigned long moved_pct, int reason),

	TP_ARGS(level_off, gap_pm, prev_gap_pm, moved_pct, reason),

	TP_STRUCT__entry(
		__field(unsigned int, level_off)
		__field(int, gap_pm)
		__field(int, prev_gap_pm)
		__field(unsigned long, moved_pct)
		__field(int, reason)
	),

	TP_fast_assign(
		__entry->level_off = level_off;
		__entry->gap_pm = gap_pm;
		__entry->prev_gap_pm = prev_gap_pm;
		__entry->moved_pct = moved_pct;
		__entry->reason = reason;
	),

	TP_printk("level_off=%u, gap=%d, prev_gap=%d, moved=%lu%%, %s",
		  __entry->level_off, __entry->gap_pm, __entry->prev_gap_pm,
		  __entry->moved_pct,
		  __print_symbolic(__entry->reason, { 0, "keep" },
				   { 1, "overshoot" }, { 2, "sensitive" },
				   { 3, "slow" }))
);

/* Start of a hint-fault migration round. */
TRACE_EVENT(fround,

	TP_PROTO(u64 round, unsigned int regions, unsigned long pages,
		 u32 median_hot, int thresh_ms, unsigned int first_level),

	TP_ARGS(round, regions, pages, median_hot, thresh_ms, first_level),

	TP_STRUCT__entry(
		__field(u64, round)
		__field(unsigned int, regions)
		__field(unsigned long, pages)
		__field(u32, median_hot)
		__field(int, thresh_ms)
		__field(unsigned int, first_level)
	),

	TP_fast_assign(
		__entry->round = round;
		__entry->regions = regions;
		__entry->pages = pages;
		__entry->median_hot = median_hot;
		__entry->thresh_ms = thresh_ms;
		__entry->first_level = first_level;
	),

	TP_printk("round=%llu, regions=%u, pages=%lu, median_hot=%u,"
		  " thresh_ms=%d, first_level=%u",
		  __entry->round, __entry->regions, __entry->pages,
		  __entry->median_hot, __entry->thresh_ms,
		  __entry->first_level)
);

TRACE_EVENT(fhint,

	TP_PROTO(int ms, unsigned int x, unsigned int y),

	TP_ARGS(ms, x, y),

	TP_STRUCT__entry(
		__field(int, ms)
		__field(unsigned int, x)
		__field(unsigned int, y)
	),

	TP_fast_assign(
		__entry->ms = ms;
		__entry->x = x;
		__entry->y = y;
	),

	TP_printk("fault_latency_ms=%d, x=%u, y=%u",
			__entry->ms, __entry->x, __entry->y)
);

#endif /* _TRACE_FTIER_H */

#include <trace/define_trace.h>
