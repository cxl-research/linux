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

#include <linux/types.h>

struct folio;
struct mm_struct;

/* Machine specific: DRAM node 1, CXL nodes 2 and 3 on the test server. */
#define CXL_NID(nid) ((nid) > 1)
#define DRAM_NID(nid) ((nid) == 1)
#define NR_NODES 4

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
extern int sysctl_pass_ratio_bp;

#ifdef CONFIG_FTIER
bool ftier_mm_is_target(struct mm_struct *mm);
#else
static inline bool ftier_mm_is_target(struct mm_struct *mm)
{
	return false;
}
#endif

#endif /* _LINUX_FTIER_H */
