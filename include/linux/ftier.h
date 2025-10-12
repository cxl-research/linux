// SPDX-License-Identifier: GPL-2.0

/*
 * FTier API
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/migrate.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/types.h>

/* Machine specific */
#define CXL_NID(nid) ((nid) > 1)
#define DRAM_NID(nid) ((nid) == 1)
#define NR_NODES 4

#define pudp_clear_young_notify(__mm, __addr, __pudp)										\
({																																			\
	int __young;																													\
	__young = pudp_test_and_clear_young(NULL, __addr, __pudp);						\
	__young |= mmu_notifier_clear_young(__mm, __addr, __addr + PUD_SIZE);	\
	__young;																															\
})

enum ftier_status {
	FTIER_STATUS_OFF,
	FTIER_STATUS_TRACK,
	FTIER_STATUS_TIER,
	NR_FTIER_STATUSES,
};

enum ftier_target_type {
	FTIER_TARGET_PID, /* default */
	FTIER_TARGET_CGROUP,
	NR_FTIER_TARGET_TYPES,
};

enum ftier_tiering_mode {
	DEMAND_MIGRATE,
	HINT_FAULT,
	NR_FTIER_TIERING_MODES,
};

struct fhot_meta_gb {
	pid_t pid;
	unsigned long address;
	unsigned int fspin_period_us;
	unsigned int nr_mapped;
	struct list_head siblings;
	unsigned char spins[512];
	unsigned char oldspins[512];
	unsigned long cxlmap[8];
};

#define MAX_SPINS 255 /* max(unsigned char) */
#define FTIER_TICK_MS 1000
#define TICK_BUDGET_MS ((FTIER_TICK_MS) * 9 / 10) /* 90% of tick */
#define MIN_TIER_BUDGET_MS 100

struct ftier_target {
	pid_t pid;
	struct cgroup *cg;
	enum ftier_target_type type;
	struct list_head fhot_list;
	unsigned int nr_fhot;
	struct workqueue_struct *wq;
};

struct ftier_ctx {
	struct task_struct *task;
	struct ftier_target target;
};

extern int sysctl_fscan_period_ms;
extern int sysctl_fspin_ms;
extern int sysctl_min_pmds_per_fscan;
extern int sysctl_max_fhot_pc;
extern int sysctl_migrate_batch;
extern int sysctl_hint_fault_latency_threshold_ms;
extern int sysctl_promote_mb;
extern enum ftier_tiering_mode sysctl_tiering_mode;

int ftier_temptrack_start(void);
int ftier_temptrack_stop(void);
void ftier_tiering_start(void);
void ftier_tiering_stop(void);
void ftier_tier_memory(struct ftier_target *t,
		int promote_mb, int budget_us, bool hist_update);

struct ftier_target *get_target(void);
int set_target_pid(pid_t pid);
int set_target_cgroup(const char *path);
