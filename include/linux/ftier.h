/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FTier: memory tiering for bandwidth expansion.
 *
 * Interfaces exported to the rest of the kernel (fault path, memory
 * tiers) and to tier-latency monitor modules.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */
#ifndef _LINUX_FTIER_H
#define _LINUX_FTIER_H

#include <linux/nodemask.h>
#include <linux/types.h>

struct folio;
struct mm_struct;

/*
 * Kept for out-of-tree latency monitors that scale sysctl_promote_mb by
 * FTIER_TICK_MS / POLL_MS: sysctl_promote_mb is a rate in MB per second.
 */
#define FTIER_TICK_MS 1000

enum ftier_status {
	FTIER_STATUS_OFF,
	FTIER_STATUS_TRACK,
	FTIER_STATUS_TIER,
	NR_FTIER_STATUSES,
};

enum ftier_target_type {
	FTIER_TARGET_NONE,
	FTIER_TARGET_PID,
	FTIER_TARGET_CGROUP,
	NR_FTIER_TARGET_TYPES,
};

enum ftier_tiering_mode {
	DEMAND_MIGRATE,
	HINT_FAULT,
	NR_FTIER_TIERING_MODES,
};

/*
 * Target migration rate in MB/s requested by the tier latency monitor:
 * > 0 promotes (CXL -> DRAM), < 0 demotes (DRAM -> CXL), 0 idles.
 */
extern int sysctl_promote_mb;
extern enum ftier_tiering_mode sysctl_tiering_mode;

/**
 * struct ftier_tier_sample - one measurement of the memory tiers
 * @dram_lat: mean loaded access latency of the DRAM tier
 * @cxl_lat: mean loaded access latency of the CXL tier, same unit
 * @dram_mbps: DRAM tier bandwidth in MB/s, 0 if unknown
 * @cxl_mbps: CXL tier bandwidth in MB/s, 0 if unknown
 * @promote_mb: requested migration rate, as sysctl_promote_mb
 */
struct ftier_tier_sample {
	u64 dram_lat;
	u64 cxl_lat;
	u64 dram_mbps;
	u64 cxl_mbps;
	int promote_mb;
};

#ifdef CONFIG_FTIER
/* Tier membership; see /sys/kernel/mm/ftier/{dram,cxl}_nodes. */
extern nodemask_t ftier_dram_nodes;
extern nodemask_t ftier_cxl_nodes;

static inline bool ftier_node_is_dram(int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES && node_isset(nid, ftier_dram_nodes);
}

static inline bool ftier_node_is_cxl(int nid)
{
	return nid >= 0 && nid < MAX_NUMNODES && node_isset(nid, ftier_cxl_nodes);
}

bool ftier_mm_is_target(struct mm_struct *mm);
int ftier_hint_fault(struct folio *folio);
void ftier_report_tier_state(const struct ftier_tier_sample *sample);
#else
static inline bool ftier_node_is_dram(int nid)
{
	return false;
}

static inline bool ftier_node_is_cxl(int nid)
{
	return false;
}

static inline bool ftier_mm_is_target(struct mm_struct *mm)
{
	return false;
}

static inline int ftier_hint_fault(struct folio *folio)
{
	return NUMA_NO_NODE;
}

static inline void ftier_report_tier_state(const struct ftier_tier_sample *s)
{
}
#endif

/* Pre-nodemask names, kept for out-of-tree users. */
#define DRAM_NID(nid)	ftier_node_is_dram(nid)
#define CXL_NID(nid)	ftier_node_is_cxl(nid)

#endif /* _LINUX_FTIER_H */
