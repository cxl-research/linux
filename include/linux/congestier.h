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

extern int promote_pg_sec;

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

enum pg_temp_pebs_state {
	TRACK_HOTNESS_OFF,
	TRACK_HOTNESS_ON,
	NR_TRACK_STATES,
};

extern int pgtemp_granularity_order;
extern int pebs_buf_pg_order;
extern int pebs_epoch_usecs;
extern void *pebs_sample_buf;

int pebs_tracking_start(void);
int pebs_tracking_stop(void);

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */