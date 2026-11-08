// SPDX-License-Identifier: GPL-2.0
/*
 * FTier tier latency monitor for Intel Sapphire Rapids and Emerald Rapids.
 *
 * Measures the average load latency of the DRAM and CXL tiers of one
 * socket with the TOR occupancy and insert counters of its CHAs (Little's
 * law: latency = occupancy / inserts), and computes the promotion rate
 * with the Colloid balancing rule: bisect the share of requests served by
 * DRAM until both tiers see the same latency. The result is reported to
 * FTier through ftier_report_tier_state().
 *
 * In every group of 8 CHAs, CHA i counts the occupancy of one request
 * class (demand read, RFO and their prefetches, to DRAM or CXL), and CHAs
 * 2k and 2k + 1 both count the DRAM and CXL inserts of class k. The DRAM
 * filters also match CXL requests, so the CXL counts are subtracted.
 *
 * The monitor programs the CHA counters directly and so must not be used
 * together with perf uncore_cha events on the same socket.
 *
 * Based on the Colloid monitor (Vuppalapati and Agarwal, SOSP 2024).
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#define pr_fmt(fmt) "ftier_cha: " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/topology.h>
#include <linux/ftier.h>
#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>
#include <asm/msr.h>

#define CHA_MSR_BASE	0x2000U
#define CHA_MSR_STRIDE	16
#define CHA_CTRL(n)	(2 + (n))
#define CHA_CTR(n)	(8 + (n))
#define CHA_GROUP	8
#define CHA_MAX		64
#define CHA_CTR_MASK	GENMASK_ULL(47, 0)

#define MSRNUM(cha, off)	(CHA_MSR_BASE + (cha) * CHA_MSR_STRIDE + (off))

/* TOR occupancy (event 0x36) and inserts (0x35) with umask_ext filters. */
static const u64 cha_occ[CHA_GROUP] = {
	0x00C8168600000136ULL,	/* demand read, DRAM */
	0x10C8168200000136ULL,	/* demand read, CXL */
	0x00C806FE00000136ULL,	/* RFO, DRAM */
	0x10C806FA00000136ULL,	/* RFO, CXL */
	0x00C8968600000136ULL,	/* demand read prefetch, DRAM */
	0x10C8968200000136ULL,	/* demand read prefetch, CXL */
	0x00C886FE00000136ULL,	/* RFO prefetch, DRAM */
	0x10C886FA00000136ULL,	/* RFO prefetch, CXL */
};

static const u64 cha_ins_dram[CHA_GROUP / 2] = {
	0x00C8168600000135ULL, 0x00C806FE00000135ULL,
	0x00C8968600000135ULL, 0x00C886FE00000135ULL,
};

static const u64 cha_ins_cxl[CHA_GROUP / 2] = {
	0x10C8168200000135ULL, 0x10C806FA00000135ULL,
	0x10C8968200000135ULL, 0x10C886FA00000135ULL,
};

static unsigned int poll_ms = 100;
module_param(poll_ms, uint, 0644);
MODULE_PARM_DESC(poll_ms, "Polling period in ms (default 100)");

static int max_mb = 512;
module_param(max_mb, int, 0644);
MODULE_PARM_DESC(max_mb, "Migration rate at full imbalance, MB/s (default 512)");

static int delta_pc = 2;
module_param(delta_pc, int, 0644);
MODULE_PARM_DESC(delta_pc, "Latency difference ignored, % of DRAM latency (default 2)");

static int eps = 100;
module_param(eps, int, 0644);
MODULE_PARM_DESC(eps, "Bisection resolution of the DRAM share, 1/10000 (default 100; 0: proportional to the latency gap)");

static int dram_latency_offset;
module_param(dram_latency_offset, int, 0644);
MODULE_PARM_DESC(dram_latency_offset, "Cycles added to the DRAM latency (default 0)");

static unsigned int min_inserts = 1000;
module_param(min_inserts, uint, 0644);
MODULE_PARM_DESC(min_inserts, "Inserts per poll below which the tiers count as idle (default 1000)");

static int node = NUMA_NO_NODE;
module_param(node, int, 0444);
MODULE_PARM_DESC(node, "Node whose socket is monitored (default: first DRAM-tier node with CPUs)");

static unsigned int nr_cha;
module_param(nr_cha, uint, 0444);
MODULE_PARM_DESC(nr_cha, "CHAs per socket, a multiple of 8 (default: cores per package)");

static bool force;
module_param(force, bool, 0444);
MODULE_PARM_DESC(force, "Load on CPUs other than Sapphire/Emerald Rapids");

static bool verbose;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Log every sample");

static const struct x86_cpu_id cha_cpu_ids[] = {
	X86_MATCH_VFM(INTEL_SAPPHIRERAPIDS_X, NULL),
	X86_MATCH_VFM(INTEL_EMERALDRAPIDS_X, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, cha_cpu_ids);

struct cha_ctr {
	u64 prev, curr;
};

static struct cha_ctr ctrs[CHA_MAX][3];
static struct task_struct *cha_task;
static int mon_cpu;

/* Colloid bisection state: DRAM share bounds, in 1/10000. */
static int p_lo, p_hi = 10000;

static int pick_cpu(void)
{
	unsigned int cpu = cpumask_any_and(cpumask_of_node(node),
					   cpu_online_mask);

	return cpu < nr_cpu_ids ? cpu : -ENODEV;
}

static int program_chas(u64 (*val)(unsigned int cha, int ctr))
{
	unsigned int cha;
	int ctr, ret;

	for (cha = 0; cha < nr_cha; cha++)
		for (ctr = 0; ctr < 3; ctr++) {
			ret = wrmsrq_safe_on_cpu(mon_cpu,
						 MSRNUM(cha, CHA_CTRL(ctr)),
						 val(cha, ctr));
			if (ret)
				return ret;
		}
	return 0;
}

static u64 cha_event(unsigned int cha, int ctr)
{
	unsigned int i = cha % CHA_GROUP;

	switch (ctr) {
	case 0:
		return cha_occ[i];
	case 1:
		return cha_ins_dram[i / 2];
	default:
		return cha_ins_cxl[i / 2];
	}
}

static u64 cha_zero(unsigned int cha, int ctr)
{
	return 0;
}

static int read_chas(void)
{
	unsigned int cha;
	int ctr, ret;
	u64 v;

	for (cha = 0; cha < nr_cha; cha++)
		for (ctr = 0; ctr < 3; ctr++) {
			ret = rdmsrq_safe_on_cpu(mon_cpu,
						 MSRNUM(cha, CHA_CTR(ctr)), &v);
			if (ret)
				return ret;
			ctrs[cha][ctr].prev = ctrs[cha][ctr].curr;
			ctrs[cha][ctr].curr = v;
		}
	return 0;
}

/* Sum of the deltas of counter @ctr over the CHAs at @mask in each group. */
static u64 accumulate(u8 mask, int ctr)
{
	unsigned int cha;
	u64 sum = 0;

	for (cha = 0; cha < nr_cha; cha++)
		if (mask & BIT(cha % CHA_GROUP))
			sum += (ctrs[cha][ctr].curr - ctrs[cha][ctr].prev) &
			       CHA_CTR_MASK;
	return sum;
}

static int compute_rate(u64 dram_lat, u64 cxl_lat, u64 dram_ins, u64 cxl_ins)
{
	u64 diff, d;
	int p, target;

	dram_lat += dram_latency_offset;
	diff = dram_lat > cxl_lat ? dram_lat - cxl_lat : cxl_lat - dram_lat;

	if (dram_ins < min_inserts && cxl_ins < min_inserts)
		return 0;
	if (diff * 100 < (u64)delta_pc * dram_lat)
		return 0;

	if (!eps) {
		/* Full rate at a difference of 512 cycles. */
		d = min_t(u64, diff, 512);
		return (dram_lat < cxl_lat ? 1 : -1) * (int)(d * max_mb / 512);
	}

	p = div64_u64(10000 * dram_ins, dram_ins + cxl_ins);
	if (dram_lat > cxl_lat)
		p_hi = p;
	else
		p_lo = p;
	if (p_lo + eps > p_hi) {
		/* The bounds converged on a stale point: widen them. */
		if (dram_lat < cxl_lat)
			p_hi = 10000;
		else
			p_lo = 0;
	}
	target = (p_lo + p_hi) / 2;
	return (target - p) * max_mb / 10000;
}

static void sample(u64 period_ns)
{
	u64 occ[2] = {}, part[2] = {}, ins[2] = {};
	struct ftier_tier_sample s;
	int k;

	for (k = 0; k < CHA_GROUP / 2; k++) {
		u8 d = BIT(2 * k), c = BIT(2 * k + 1);
		/* One CHA in 8 counts each occupancy, two in 8 the inserts. */
		u64 occ_d = accumulate(d, 0) * 8, occ_c = accumulate(c, 0) * 8;
		u64 part_d = accumulate(d, 1) * 8, part_c = accumulate(c, 2) * 8;
		u64 ins_d = accumulate(d | c, 1) * 4;
		u64 ins_c = accumulate(d | c, 2) * 4;

		occ[0] += occ_d > occ_c ? occ_d - occ_c : 0;
		occ[1] += occ_c;
		part[0] += part_d > part_c ? part_d - part_c : 0;
		part[1] += part_c;
		ins[0] += ins_d > ins_c ? ins_d - ins_c : 0;
		ins[1] += ins_c;
	}

	s.dram_lat = div64_u64(occ[0], part[0] + 1);
	s.cxl_lat = div64_u64(occ[1], part[1] + 1);
	s.dram_mbps = div64_u64(ins[0] * 64 * NSEC_PER_SEC, period_ns << 20);
	s.cxl_mbps = div64_u64(ins[1] * 64 * NSEC_PER_SEC, period_ns << 20);
	s.promote_mb = compute_rate(s.dram_lat, s.cxl_lat, ins[0], ins[1]);
	ftier_report_tier_state(&s);

	if (verbose)
		pr_info("lat=(%llu,%llu) MB/s=(%llu,%llu) p=[%d,%d] promote_mb=%d\n",
			s.dram_lat, s.cxl_lat, s.dram_mbps, s.cxl_mbps,
			p_lo, p_hi, s.promote_mb);
}

static int cha_thread(void *data)
{
	u64 last = ktime_get_ns(), now;
	int cpu;

	read_chas();
	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(
			msecs_to_jiffies(max(READ_ONCE(poll_ms), 10U)));
		if (kthread_should_stop())
			break;
		now = ktime_get_ns();
		if (!read_chas()) {
			sample(now - last);
		} else {
			/* The monitoring CPU went offline: move and restart. */
			cpu = pick_cpu();
			if (cpu >= 0 && cpu != mon_cpu) {
				mon_cpu = cpu;
				if (!program_chas(cha_event))
					read_chas();
			}
		}
		last = now;
	}
	return 0;
}

static int __init cha_init(void)
{
	int ret;

	if (!x86_match_cpu(cha_cpu_ids) && !force)
		return -ENODEV;

	if (node == NUMA_NO_NODE) {
		for_each_node_mask(node, ftier_dram_nodes)
			if (cpumask_intersects(cpumask_of_node(node),
					       cpu_online_mask))
				break;
		if (node >= MAX_NUMNODES)
			return -ENODEV;
	}
	if (node < 0 || node >= nr_node_ids || !node_online(node))
		return -EINVAL;

	if (!nr_cha)
		nr_cha = topology_num_cores_per_package();
	nr_cha = min(rounddown(nr_cha, CHA_GROUP), (unsigned int)CHA_MAX);
	if (!nr_cha)
		return -EINVAL;

	mon_cpu = pick_cpu();
	if (mon_cpu < 0)
		return mon_cpu;

	ret = program_chas(cha_event);
	if (ret) {
		pr_err("cannot program CHA counters on CPU %d: %d\n",
		       mon_cpu, ret);
		goto err;
	}

	cha_task = kthread_run(cha_thread, NULL, "ftier_cha");
	if (IS_ERR(cha_task)) {
		ret = PTR_ERR(cha_task);
		goto err;
	}
	pr_info("monitoring node %d on CPU %d with %u CHAs every %u ms\n",
		node, mon_cpu, nr_cha, poll_ms);
	return 0;
err:
	program_chas(cha_zero);
	return ret;
}

static void __exit cha_exit(void)
{
	struct ftier_tier_sample idle = {};

	kthread_stop(cha_task);
	program_chas(cha_zero);
	/* Stop the migration requested by the last sample. */
	ftier_report_tier_state(&idle);
}

module_init(cha_init);
module_exit(cha_exit);
MODULE_AUTHOR("Alan Nair <alannair1000@gmail.com>");
MODULE_DESCRIPTION("FTier CHA tier latency monitor");
MODULE_LICENSE("GPL");
