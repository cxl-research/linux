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
