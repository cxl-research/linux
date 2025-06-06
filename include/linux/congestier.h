// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier API
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/types.h>

#define CONGESTIER_BUF_SHIFT(order) ((1U << (order + 11)) - 1)
#define CONGESTIER_PEBS_BUFSZ_NZ(order) \
		(((1UL << ((order) - 1)) + 1) * PAGE_SIZE)
#define CONGESTIER_PEBS_BUFSZ(order) \
		((order) ? CONGESTIER_PEBS_BUFSZ_NZ(order) : 0UL)

#define MAX_PGTEMP_TARGETS			64
#define NR_TEMPERATURE_CLASSES	64

/* CXPHIRE specific */
#define CXLNID(nid) ((nid) > 1)
#define DRAM_NID_MASK 4 // 0100
#define CXL_NID_MASK 3	// 0011

enum tiering_mode {
	TIERING_MODE_OFF,
	TIERING_MODE_ON,
	NR_TIERING_MODES,
};

enum tiering_interleave_mode {
	TIM_HALF,
	TIM_GSTEP,
	TIM_HSTEP,
	NR_TIERING_INTERLEAVE_MODES,
};

enum blk_tiering_state {
	NOT_TIERED,
	TIERING_CANDIDATE,
	TIERED,
	NR_TIER_STATES,
};

struct pg_temp_block {
	uint64_t ld_temp;
	uint64_t period_sum_this_epoch_ld;
	uint64_t nr_samples_this_epoch_ld;
	uint64_t last_updated_epoch;
	uint64_t blocknum;
	int pid;
	struct list_head temper_class;

	/* for use in tiering */
	int demotion_level;
	enum blk_tiering_state tiering_state;
	uint64_t tiering_epoch;
};

struct temperature_class {
	struct list_head blocks;
	struct mutex templock;
	int nr_blocks, tmp_cls_idx;
};

extern int sysctl_promote_pg_epoch;
extern int sysctl_epoch_usecs;
extern int sysctl_dirty_latency_threshold_usecs;
extern int sysctl_tiering_epoch_usecs;
extern enum tiering_mode sysctl_tiering_mode;

extern int tier_frame_pg_order;
extern enum tiering_interleave_mode tiering_interleave_mode;

int tiering_start(void);
int tiering_stop(void);
void reset_tiering_ctx(void);

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

enum pg_temp_pebs_state {
	TRACK_HOTNESS_OFF,
	TRACK_HOTNESS_ON,
	NR_TRACK_STATES,
};

extern int pgtemp_granularity_order;
extern int pebs_buf_pg_order;
extern void *pebs_sample_buf;

int pebs_tracking_start(void);
int pebs_tracking_stop(void);
int pebs_track_epoch_work(int epoch_id);
void pebs_track_init(void);
struct temperature_class *get_temp_cls(int idx);
void reset_pebs_tracking(void);

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */