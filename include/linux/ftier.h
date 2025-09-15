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

struct fhot_meta_gb {
	pud_t *pud;
	unsigned long address;
	unsigned int fspin_period_us;
	unsigned int nr_mapped;
	struct list_head siblings;
	// unsigned char accesses[512];
};

struct ftier_target {
	pid_t pid;
	struct list_head fhot_list;
	unsigned int nr_fhot;
};

struct ftier_ctx {
	struct task_struct *task;
	struct ftier_target target;
};

extern unsigned int sysctl_fscan_period_ms;

int ftier_temptrack_start(void);
int ftier_temptrack_stop(void);
void ftier_tiering_start(void);
void ftier_tiering_stop(void);

struct ftier_target *get_target(void);
int set_target_pid(pid_t pid);