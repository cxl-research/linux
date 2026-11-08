/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FTier internal definitions.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */
#ifndef _MM_FTIER_INTERNAL_H
#define _MM_FTIER_INTERNAL_H

#include <linux/ftier.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pgtable.h>
#include <linux/spinlock.h>
#include <linux/timerqueue.h>
#include <linux/wait.h>
#include <linux/xarray.h>

#define FTIER_NR_PMD		PTRS_PER_PMD
#define FTIER_HOT_LEVELS	32
#define FTIER_MAX_SCANNERS	64

struct cgroup;
struct pid;
struct task_struct;
struct ftier_pud;

/*
 * Tunables. Written by sysfs under ftier_lock, read locklessly with
 * READ_ONCE() by the FTier threads. See Documentation/admin-guide/mm/ftier.rst.
 */
struct ftier_config {
	unsigned int tick_ms;		/* main loop period */
	unsigned int interval_ms;	/* AFS measurement interval */
	unsigned int fscan_period_ms;	/* PUD-level scan period */
	unsigned int pud_idle_scans;	/* inactive fscans before untracking */
	unsigned int scans_per_interval; /* S: per-PMD-page scan budget */
	unsigned int init_period_us;	/* initial PMD-page scan period */
	unsigned int min_period_us;
	unsigned int max_period_us;
	unsigned int low_wm;		/* accessed entries/scan to slow down */
	unsigned int high_wm_pct;	/* % of mapped entries to speed up */
	unsigned int slack_us;		/* scanner timer slack */
	unsigned int cool_ms;		/* Hotlist cooling period */
	unsigned int nr_scanners;	/* AFS scanner threads */
	bool track_thp;			/* count PMD-mapped THPs */
	bool notify_secondary;		/* query secondary MMUs (KVM) */
	unsigned int migrate_batch;
	unsigned int max_migrate_mbps;	/* global migration-rate cap */
};

extern struct ftier_config ftier_cfg;
#define FTIER_CFG(field)	READ_ONCE(ftier_cfg.field)

/* Hotlist entry: one tracked PMD entry, i.e. a 2MB region. 32 bytes. */
struct ftier_hot {
	struct list_head link;		/* in a Hotlist bucket */
	struct ftier_pud *pud;
	u32 hotness;			/* stored hotness, valid at @epoch */
	u16 epoch;			/* Hotlist epoch of @hotness, mod 2^16 */
	u16 idx:9;			/* PMD index within @pud */
	u16 flags:7;
};

/* ftier_hot.flags */
#define FTIER_HOT_NO_DRAM	0x01	/* last walk found no pages on DRAM */
#define FTIER_HOT_NO_CXL	0x02	/* last walk found no pages on CXL */

/*
 * Circular array of logarithmic hotness buckets. A bucket at array
 * position p holds entries of level (p - epoch) mod FTIER_HOT_LEVELS,
 * where level = ilog2(effective hotness). Cooling increments the epoch,
 * which halves the effective hotness of every entry without touching it.
 */
struct ftier_hotlist {
	struct list_head bucket[FTIER_HOT_LEVELS];
	unsigned int nr[FTIER_HOT_LEVELS];
	u32 epoch;
	unsigned long nr_entries;
	u64 nr_inserted;
	u64 nr_discarded;
};

/* A tracked address space. */
struct ftier_space {
	struct list_head link;		/* ftier_ctx.spaces */
	struct hlist_node hnode;	/* RCU hash keyed by @mm */
	struct mm_struct *mm;		/* mmgrab() reference */
	pid_t tgid;			/* for reporting only */
	struct xarray puds;		/* PUD index -> struct ftier_pud */
	unsigned int nr_puds;
	u64 seen_gen;			/* last fscan generation that found it */
	struct rcu_head rcu;
};

/* AFS state of one page of PMD entries, i.e. one valid PUD entry (1GB). */
struct ftier_pud {
	struct timerqueue_node tq;	/* next scan deadline */
	struct ftier_space *space;
	struct ftier_scanner *scanner;
	unsigned long addr;		/* PUD_SIZE aligned */

	/* Owned by the scanner while @scanning, else under scanner->lock. */
	u32 period_us;
	u32 nr_scans;			/* in the current interval */
	u64 throttled_ns;		/* when S was reached, 0 if not */
	u64 scan_ns;			/* time spent scanning this interval */
	u32 nr_lock_miss;		/* mmap_lock trylock failures */
	u16 nr_mapped;			/* entries mapping a table or THP */
	u8 cur;				/* counts[] buffer being filled */
	bool scanning;
	bool dead;

	/* Owned by the main thread. */
	u64 born_ns;			/* tracking started */
	u32 idle_fscans;
	u64 seen_gen;
	u64 total_scans;
	u16 counts[2][FTIER_NR_PMD];	/* 16-bit access counters */
	struct ftier_hot **hot;		/* Hotlist lookup table, 4KB */
};

struct ftier_scanner {
	struct task_struct *task;
	spinlock_t lock;
	struct timerqueue_head queue;
	wait_queue_head_t idle_wq;	/* a PUD scan finished */
	unsigned int nr_puds;
	int id;
	/* statistics */
	u64 nr_scans;
	u64 busy_ns;
};

struct ftier_stats {
	u64 nr_fscans;
	u64 fscan_ns;
	u64 nr_intervals;
	u64 collect_ns;
	u64 nr_pud_added;
	u64 nr_pud_removed;
	u64 nr_throttled;		/* PUD-intervals that hit S */
	u64 nr_lock_miss;
	u64 nr_space_added;
	u64 nr_space_removed;
	u64 nr_cool;
	u64 nr_tier_ticks;
	u64 tier_ns;
	u64 nr_promoted;		/* pages */
	u64 nr_demoted;			/* pages */
	u64 nr_migrate_fail;		/* pages */
	u64 nr_protected;		/* PTEs made PROT_NONE */
	u64 nr_overrun;			/* ticks exceeding tick_ms */
};

struct ftier_ctx {
	struct task_struct *task;	/* main thread */
	struct ftier_scanner *scanners;
	unsigned int nr_scanners;

	/* target, protected by ftier_lock */
	enum ftier_target_type type;
	struct pid *pid;
	struct cgroup *cgrp;

	struct list_head spaces;
	unsigned int nr_spaces;
	u64 gen;			/* fscan generation */
	struct ftier_hotlist hotlist;

	/* scheduling of the main thread */
	u64 next_fscan_ns;
	u64 next_cool_ns;
	u64 ival_start_ns;		/* current interval, read by scanners */
	u64 ival_end_ns;
	bool tiering;

	struct ftier_stats stats;
};

extern struct ftier_ctx ftier_ctx;
extern struct mutex ftier_lock;
extern struct mutex ftier_state_lock;
extern enum ftier_status sysctl_ftier_status;

/* core.c */
int ftier_start(void);
void ftier_stop(void);
void ftier_set_tiering(bool on);
int ftier_set_target_pid(pid_t nr);
int ftier_set_target_cgroup(const char *path);
void ftier_kick(void);

/* afs.c */
int ftier_scanners_start(unsigned int nr);
void ftier_scanners_stop(void);
struct ftier_pud *ftier_pud_alloc(struct ftier_space *space,
				  unsigned long addr);
void ftier_pud_enqueue(struct ftier_pud *pud);
void ftier_pud_dequeue(struct ftier_pud *pud);
void ftier_pud_free(struct ftier_pud *pud);
void ftier_afs_collect(struct ftier_pud *pud, u64 now, u64 cfg_ns);

/* hotlist.c */
void ftier_hotlist_init(struct ftier_hotlist *hl);
void ftier_hotlist_add(struct ftier_hotlist *hl, struct ftier_pud *pud,
		       unsigned int idx, u32 count);
void ftier_hotlist_remove(struct ftier_hotlist *hl, struct ftier_hot *hot);
void ftier_hotlist_cool(struct ftier_hotlist *hl);
void ftier_hotlist_destroy(struct ftier_hotlist *hl);
u32 ftier_hot_effective(const struct ftier_hotlist *hl,
			const struct ftier_hot *hot);
unsigned int ftier_hot_level(const struct ftier_hotlist *hl,
			     const struct ftier_hot *hot);
int ftier_hotlist_cache_init(void);

static inline unsigned int ftier_hotlist_pos(const struct ftier_hotlist *hl,
					     unsigned int level)
{
	return (level + hl->epoch) % FTIER_HOT_LEVELS;
}

#define ftier_for_each_hot(hl, level, hot)				\
	for (level = FTIER_HOT_LEVELS; level-- > 0; )			\
		list_for_each_entry(hot,				\
			&(hl)->bucket[ftier_hotlist_pos(hl, level)], link)

static inline unsigned long ftier_hot_addr(const struct ftier_hot *hot)
{
	return hot->pud->addr + ((unsigned long)hot->idx << PMD_SHIFT);
}

/* tiering.c */
void ftier_tier_tick(unsigned int tick_ms, u64 budget_ns);

#endif /* _MM_FTIER_INTERNAL_H */
