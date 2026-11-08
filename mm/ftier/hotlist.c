// SPDX-License-Identifier: GPL-2.0
/*
 * FTier Hotlist: hotness metadata of tracked PMD entries.
 *
 * The Hotlist is a circular array of FTIER_HOT_LEVELS doubly-linked
 * lists. An entry with effective hotness H lives in the bucket of level
 * ilog2(H). Cooling halves every entry's hotness by advancing the
 * epoch, which rotates the meaning of the array positions by one level:
 * only the coldest bucket is touched (its entries are discarded), so the
 * cost of cooling is independent of the number of tracked entries.
 *
 * Entries are found from AFS reports through the per-PUD lookup table
 * (struct ftier_pud::hot), one pointer per PMD entry: 4KB per GB.
 *
 * All functions here are called with ftier_lock held.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/log2.h>
#include <linux/slab.h>

#include "internal.h"

static struct kmem_cache *ftier_hot_cache;

static_assert(sizeof(struct ftier_hot) == 32);
static_assert(FTIER_NR_PMD <= (1 << 9));
/* epoch is stored mod 2^16; positions must be stable under that wrap */
static_assert((1 << 16) % FTIER_HOT_LEVELS == 0);

int ftier_hotlist_cache_init(void)
{
	if (ftier_hot_cache)
		return 0;
	ftier_hot_cache = KMEM_CACHE(ftier_hot, 0);
	return ftier_hot_cache ? 0 : -ENOMEM;
}

void ftier_hotlist_init(struct ftier_hotlist *hl)
{
	int i;

	for (i = 0; i < FTIER_HOT_LEVELS; i++) {
		INIT_LIST_HEAD(&hl->bucket[i]);
		hl->nr[i] = 0;
	}
	hl->epoch = 0;
	hl->nr_entries = 0;
	hl->nr_inserted = 0;
	hl->nr_discarded = 0;
}

u32 ftier_hot_effective(const struct ftier_hotlist *hl,
			const struct ftier_hot *hot)
{
	u16 age = (u16)hl->epoch - hot->epoch;

	return age >= 32 ? 0 : hot->hotness >> age;
}

unsigned int ftier_hot_level(const struct ftier_hotlist *hl,
			     const struct ftier_hot *hot)
{
	u32 h = ftier_hot_effective(hl, hot);

	return h ? ilog2(h) : 0;
}

/* Array position of a linked entry; constant until it is re-added. */
static unsigned int hot_pos(const struct ftier_hot *hot)
{
	return (ilog2(hot->hotness) + hot->epoch) % FTIER_HOT_LEVELS;
}

static void hot_unlink(struct ftier_hotlist *hl, struct ftier_hot *hot)
{
	list_del(&hot->link);
	hl->nr[hot_pos(hot)]--;
}

/**
 * ftier_hotlist_add - account an AFS report to a PMD entry
 * @hl: the Hotlist
 * @pud: AFS state of the PMD page holding the entry
 * @idx: index of the PMD entry in its page
 * @count: access count reported for the last interval (scaled)
 *
 * Adds @count to the effective hotness of the entry, creating it if it
 * is not tracked yet, and moves it to the tail of the bucket of its new
 * level. An entry staying at its level keeps its place in the bucket.
 */
void ftier_hotlist_add(struct ftier_hotlist *hl, struct ftier_pud *pud,
		       unsigned int idx, u32 count)
{
	struct ftier_hot *hot = pud->hot[idx];
	unsigned int pos, old_pos = FTIER_HOT_LEVELS;
	u32 h = 0;

	if (!count)
		return;

	if (!hot) {
		hot = kmem_cache_zalloc(ftier_hot_cache, GFP_KERNEL);
		if (!hot)
			return;
		hot->pud = pud;
		hot->idx = idx;
		pud->hot[idx] = hot;
		hl->nr_entries++;
		hl->nr_inserted++;
	} else {
		h = ftier_hot_effective(hl, hot);
		old_pos = hot_pos(hot);
	}

	hot->hotness = h > U32_MAX - count ? U32_MAX : h + count;
	hot->epoch = (u16)hl->epoch;
	pos = hot_pos(hot);
	if (pos == old_pos)
		return;
	if (old_pos < FTIER_HOT_LEVELS) {
		list_del(&hot->link);
		hl->nr[old_pos]--;
	}
	list_add_tail(&hot->link, &hl->bucket[pos]);
	hl->nr[pos]++;
}

/* Move @hot behind the other entries of its level. */
void ftier_hotlist_rotate(struct ftier_hotlist *hl, struct ftier_hot *hot)
{
	list_move_tail(&hot->link, &hl->bucket[hot_pos(hot)]);
}

void ftier_hotlist_remove(struct ftier_hotlist *hl, struct ftier_hot *hot)
{
	hot_unlink(hl, hot);
	hot->pud->hot[hot->idx] = NULL;
	hl->nr_entries--;
	kmem_cache_free(ftier_hot_cache, hot);
}

/**
 * ftier_hotlist_cool - halve the hotness of all entries
 * @hl: the Hotlist
 *
 * Entries of level 0 would drop to zero and are discarded; all others
 * implicitly move one level down as the epoch advances.
 */
void ftier_hotlist_cool(struct ftier_hotlist *hl)
{
	unsigned int pos = ftier_hotlist_pos(hl, 0);
	struct ftier_hot *hot, *tmp;

	list_for_each_entry_safe(hot, tmp, &hl->bucket[pos], link) {
		hot->pud->hot[hot->idx] = NULL;
		kmem_cache_free(ftier_hot_cache, hot);
		hl->nr_entries--;
		hl->nr_discarded++;
	}
	INIT_LIST_HEAD(&hl->bucket[pos]);
	hl->nr[pos] = 0;
	hl->epoch++;
}

void ftier_hotlist_destroy(struct ftier_hotlist *hl)
{
	struct ftier_hot *hot, *tmp;
	int i;

	for (i = 0; i < FTIER_HOT_LEVELS; i++) {
		list_for_each_entry_safe(hot, tmp, &hl->bucket[i], link) {
			hot->pud->hot[hot->idx] = NULL;
			kmem_cache_free(ftier_hot_cache, hot);
		}
	}
	ftier_hotlist_init(hl);
}
