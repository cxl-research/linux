/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ftier

#if !defined(_TRACE_FTIER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FTIER_H

#include <linux/types.h>
#include <linux/tracepoint.h>

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

TRACE_EVENT(fspin,

	TP_PROTO(int pid, unsigned long addr, unsigned int spins,
		unsigned int spin_period_final_us, unsigned int dur_sum_us,
		unsigned int hot, unsigned int mapped),

	TP_ARGS(pid, addr, spins, spin_period_final_us,
			dur_sum_us, hot, mapped),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(unsigned long, addr)
		__field(unsigned int, spins)
		__field(unsigned int, spin_period_final_us)
		__field(unsigned int, dur_sum_us)
		__field(unsigned int, hot)
		__field(unsigned int, mapped)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->addr = addr;
		__entry->spins = spins;
		__entry->spin_period_final_us = spin_period_final_us;
		__entry->dur_sum_us = dur_sum_us;
		__entry->hot = hot;
		__entry->mapped = mapped;
	),

	TP_printk("pid=%d, addr=%lx, spins=%u, spin_period_final=%u us,"
			" dur_sum=%u us, hot=%u, mapped=%u",
			__entry->pid, __entry->addr, __entry->spins,
			__entry->spin_period_final_us, __entry->dur_sum_us,
			__entry->hot, __entry->mapped)
);

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

TRACE_EVENT(fmigrate,

	TP_PROTO(int succ, int fail, int succpg, int failpg, int budget_us,
			int dur_us, unsigned int thresh, bool promote),

	TP_ARGS(succ, fail, succpg, failpg, budget_us, dur_us, thresh, promote),

	TP_STRUCT__entry(
		__field(int, succ)
		__field(int, fail)
		__field(int, succpg)
		__field(int, failpg)
		__field(int, budget_us)
		__field(int, dur_us)
		__field(unsigned int, thresh)
		__field(bool, promote)
	),

	TP_fast_assign(
		__entry->succ = succ;
		__entry->fail = fail;
		__entry->succpg = succpg;
		__entry->failpg = failpg;
		__entry->budget_us = budget_us;
		__entry->dur_us = dur_us;
		__entry->thresh = thresh;
		__entry->promote = promote;
	),

	TP_printk("succ=%d, fail=%d, succpg=%d, failpg=%d,"
						" budget_us=%d, dur_us=%d, thresh=%u, promote=%d",
			__entry->succ, __entry->fail, __entry->succpg,
			__entry->failpg, __entry->budget_us, __entry->dur_us,
			__entry->thresh, __entry->promote)
);

#endif /* _TRACE_FTIER_H */

#include <trace/define_trace.h>