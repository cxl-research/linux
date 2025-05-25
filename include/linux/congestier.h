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

enum tiering_mode {
	TIERING_MODE_OFF,
	TIERING_MODE_ON,
	NR_TIERING_MODES,
};

extern int promote_pg_sec;
extern int epoch_usecs;

int tiering_start(void);
int tiering_stop(void);

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

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */