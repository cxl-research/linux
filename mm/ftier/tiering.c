// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier Memory Tiering
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>

#include <trace/events/ftier.h>

static void compute_histogram(struct ftier_target *t)
{
	struct fhot_meta_gb *meta;
	unsigned int *histogram;
	unsigned int idx, spins, period;

	histogram = kzalloc(sizeof(unsigned int) * MAX_SPINS, GFP_KERNEL);
	if (!histogram)
		return;

	list_for_each_entry(meta, &t->fhot_list, siblings) {
		period = meta->fspin_period_us;
		for (idx = 0; idx < 512; ++idx) {
			spins = meta->spins[idx];
			if (period < 20000)
				spins *= (20000 / period);
			if (spins <= MAX_SPINS)
				histogram[(spins - 1)]++;
			else
				histogram[MAX_SPINS - 1]++;
		}
	}

	for (idx = 0; idx < MAX_SPINS; ++idx) {
		if (histogram[idx])
			trace_fhist(t->pid, idx + 1, 2 * histogram[idx]);
	}

	kfree(histogram);
}

void ftier_tier_memory(struct ftier_target *t)
{
	compute_histogram(t);
}
