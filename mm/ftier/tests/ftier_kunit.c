// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for the FTier Hotlist, candidate selection, hint-fault
 * threshold, hotness level adaptation, tier signal and hint credit.
 *
 * Included from tiering.c to reach its static functions. The tests use
 * a private Hotlist and save and restore the global state they touch;
 * they are skipped while FTier runs.
 *
 * Copyright (c) 2026 Alan Nair <alannair1000@gmail.com>
 */

#include <kunit/test.h>

struct ftier_test {
	struct ftier_hotlist hl;
	struct ftier_pud *pud;
	/* saved global state */
	struct ftier_config cfg;
	struct ftier_stats stats;
	unsigned int level_off;
	int gap_prev;
	u64 level_next_ns;
	unsigned long level_pages;
	struct ftier_tier_sample sample;
	u64 sample_ns;
	int promote_mb;
	long credit;
};

static int ftier_test_init(struct kunit *test)
{
	struct ftier_test *t;

	if (READ_ONCE(sysctl_ftier_status) != FTIER_STATUS_OFF)
		kunit_skip(test, "FTier is running");
	if (ftier_hotlist_cache_init())
		return -ENOMEM;

	t = kunit_kzalloc(test, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;
	t->pud = kunit_kzalloc(test, sizeof(*t->pud), GFP_KERNEL);
	if (!t->pud)
		return -ENOMEM;
	t->pud->hot = kunit_kcalloc(test, FTIER_NR_PMD, sizeof(*t->pud->hot),
				    GFP_KERNEL);
	if (!t->pud->hot)
		return -ENOMEM;
	ftier_hotlist_init(&t->hl);

	t->cfg = ftier_cfg;
	t->stats = ftier_ctx.stats;
	t->level_off = ftier_ctx.level_off;
	t->gap_prev = ftier_ctx.gap_prev;
	t->level_next_ns = ftier_ctx.level_next_ns;
	t->level_pages = ftier_ctx.level_pages;
	t->sample = ftier_tier.sample;
	t->sample_ns = ftier_tier.time_ns;
	t->promote_mb = sysctl_promote_mb;
	t->credit = atomic_long_read(&ftier_hint.credit);
	test->priv = t;
	return 0;
}

static void ftier_test_exit(struct kunit *test)
{
	struct ftier_test *t = test->priv;

	if (!t)
		return;
	ftier_hotlist_destroy(&t->hl);
	ftier_cfg = t->cfg;
	ftier_ctx.stats = t->stats;
	ftier_ctx.level_off = t->level_off;
	ftier_ctx.gap_prev = t->gap_prev;
	ftier_ctx.level_next_ns = t->level_next_ns;
	ftier_ctx.level_pages = t->level_pages;
	ftier_tier.sample = t->sample;
	ftier_tier.time_ns = t->sample_ns;
	sysctl_promote_mb = t->promote_mb;
	atomic_long_set(&ftier_hint.credit, t->credit);
}

static void add(struct ftier_test *t, unsigned int idx, u32 count)
{
	ftier_hotlist_add(&t->hl, t->pud, idx, count);
}

static struct ftier_hot *hot(struct ftier_test *t, unsigned int idx)
{
	return t->pud->hot[idx];
}

static unsigned int nr_at(struct ftier_test *t, unsigned int level)
{
	return t->hl.nr[ftier_hotlist_pos(&t->hl, level)];
}

/* Indices of the entries of @level in bucket order, as "a,b,c". */
static const char *order(struct kunit *test, unsigned int level)
{
	struct ftier_test *t = test->priv;
	char *buf = kunit_kzalloc(test, 128, GFP_KERNEL);
	struct ftier_hot *h;
	int len = 0;

	if (!buf)
		return "";
	list_for_each_entry(h, &t->hl.bucket[ftier_hotlist_pos(&t->hl, level)],
			    link)
		len += scnprintf(buf + len, 128 - len, "%s%u", len ? "," : "",
				 h->idx);
	return buf;
}

static void hotlist_add_test(struct kunit *test)
{
	struct ftier_test *t = test->priv;

	add(t, 3, 5);
	KUNIT_ASSERT_NOT_NULL(test, hot(t, 3));
	KUNIT_EXPECT_EQ(test, t->hl.nr_entries, 1UL);
	KUNIT_EXPECT_EQ(test, ftier_hot_level(&t->hl, hot(t, 3)), 2U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 2), 1U);

	add(t, 3, 4);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 3)), 9U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 2), 0U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 3), 1U);

	/* A zero count neither creates nor changes an entry. */
	add(t, 3, 0);
	add(t, 9, 0);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 3)), 9U);
	KUNIT_EXPECT_NULL(test, hot(t, 9));
	KUNIT_EXPECT_EQ(test, t->hl.nr_entries, 1UL);

	/* Hotness saturates. */
	add(t, 4, U32_MAX);
	add(t, 4, 10);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 4)), U32_MAX);
	KUNIT_EXPECT_EQ(test, ftier_hot_level(&t->hl, hot(t, 4)), 31U);
	KUNIT_EXPECT_EQ(test, t->hl.nr_inserted, 2ULL);
}

static void hotlist_order_test(struct kunit *test)
{
	struct ftier_test *t = test->priv;

	add(t, 1, 4);
	add(t, 2, 4);
	add(t, 3, 4);
	KUNIT_EXPECT_STREQ(test, order(test, 2), "1,2,3");

	/* Staying at the same level keeps the place in the bucket. */
	add(t, 1, 1);
	KUNIT_EXPECT_STREQ(test, order(test, 2), "1,2,3");

	ftier_hotlist_rotate(&t->hl, hot(t, 1));
	KUNIT_EXPECT_STREQ(test, order(test, 2), "2,3,1");

	add(t, 2, 4);
	KUNIT_EXPECT_STREQ(test, order(test, 2), "3,1");
	KUNIT_EXPECT_STREQ(test, order(test, 3), "2");

	ftier_hotlist_remove(&t->hl, hot(t, 3));
	KUNIT_EXPECT_NULL(test, hot(t, 3));
	KUNIT_EXPECT_STREQ(test, order(test, 2), "1");
	KUNIT_EXPECT_EQ(test, t->hl.nr_entries, 2UL);
	KUNIT_EXPECT_EQ(test, nr_at(t, 2), 1U);
}

static void hotlist_cool_test(struct kunit *test)
{
	struct ftier_test *t = test->priv;
	unsigned int level;

	add(t, 7, 8);
	for (level = 3; level-- > 0; ) {
		ftier_hotlist_cool(&t->hl);
		KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 7)),
				1U << level);
		KUNIT_EXPECT_EQ(test, ftier_hot_level(&t->hl, hot(t, 7)), level);
		KUNIT_EXPECT_EQ(test, nr_at(t, level), 1U);
		KUNIT_EXPECT_STREQ(test, order(test, level), "7");
	}
	/* Level 0 entries are discarded by the next cooling. */
	ftier_hotlist_cool(&t->hl);
	KUNIT_EXPECT_NULL(test, hot(t, 7));
	KUNIT_EXPECT_EQ(test, t->hl.nr_entries, 0UL);
	KUNIT_EXPECT_EQ(test, t->hl.nr_discarded, 1ULL);

	/* Counts add to the cooled hotness. */
	add(t, 8, 8);
	ftier_hotlist_cool(&t->hl);
	add(t, 8, 4);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 8)), 8U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 3), 1U);
}

static void hotlist_epoch_wrap_test(struct kunit *test)
{
	struct ftier_test *t = test->priv;
	int i;

	/* Entry epochs are 16 bits: cross the wrap. */
	t->hl.epoch = 65534;
	add(t, 9, 16);
	for (i = 0; i < 3; i++)
		ftier_hotlist_cool(&t->hl);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 9)), 2U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 1), 1U);
	KUNIT_EXPECT_STREQ(test, order(test, 1), "9");

	add(t, 9, 2);
	KUNIT_EXPECT_EQ(test, ftier_hot_effective(&t->hl, hot(t, 9)), 4U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 2), 1U);
	KUNIT_EXPECT_EQ(test, nr_at(t, 1), 0U);
}

static unsigned int collect_idx(struct kunit *test, bool promote,
				unsigned int max, unsigned int *first,
				const char **idx)
{
	struct ftier_test *t = test->priv;
	char *buf = kunit_kzalloc(test, 128, GFP_KERNEL);
	unsigned int i, n;
	int len = 0;

	n = collect_candidates(&t->hl, promote, max, first);
	for (i = 0; buf && i < n; i++)
		len += scnprintf(buf + len, 128 - len, "%s%u", i ? "," : "",
				 cands[i]->idx);
	*idx = buf ? buf : "";
	return n;
}

static void candidates_test(struct kunit *test)
{
	struct ftier_test *t = test->priv;
	unsigned int first, n;
	const char *idx;

	add(t, 1, 32);
	add(t, 2, 32);
	add(t, 3, 8);
	add(t, 4, 2);
	WRITE_ONCE(ftier_cfg.residency_epochs, 8);

	ftier_ctx.level_off = 0;
	n = collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_EQ(test, n, 4U);
	KUNIT_EXPECT_EQ(test, first, 5U);
	KUNIT_EXPECT_STREQ(test, idx, "1,2,3,4");
	KUNIT_EXPECT_EQ(test, cand_hot[0], 32U);
	KUNIT_EXPECT_EQ(test, cand_hot[3], 2U);

	n = collect_idx(test, true, 2, &first, &idx);
	KUNIT_EXPECT_STREQ(test, idx, "1,2");

	/* level_off starts selection below the hottest level. */
	ftier_ctx.level_off = 2;
	n = collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_EQ(test, first, 3U);
	KUNIT_EXPECT_STREQ(test, idx, "3,4");
	ftier_ctx.level_off = 10;
	n = collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_EQ(test, first, 0U);
	KUNIT_EXPECT_EQ(test, n, 0U);
	ftier_ctx.level_off = 0;

	/* Residency flags skip regions with nothing to move that way. */
	set_residency(&t->hl, hot(t, 2), false, true);
	collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_STREQ(test, idx, "1,3,4");
	collect_idx(test, false, 16, &first, &idx);
	KUNIT_EXPECT_STREQ(test, idx, "1,2,3,4");

	/* ... until they expire. */
	hot(t, 2)->flags = ((hot_stamp(&t->hl) - 2) & 0x1f) <<
			   FTIER_HOT_STAMP_SHIFT | FTIER_HOT_NO_CXL;
	WRITE_ONCE(ftier_cfg.residency_epochs, 1);
	collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_STREQ(test, idx, "1,2,3,4");
	WRITE_ONCE(ftier_cfg.residency_epochs, 2);
	collect_idx(test, true, 16, &first, &idx);
	KUNIT_EXPECT_STREQ(test, idx, "1,3,4");
}

static void threshold_test(struct kunit *test)
{
	u32 h3[] = { 30, 10, 20 }, h4[] = { 80, 10, 40, 20 };
	u32 one[] = { 1 }, huge[] = { 1000000 }, h20[] = { 20 };

	WRITE_ONCE(ftier_cfg.cool_ms, 2000);
	WRITE_ONCE(ftier_cfg.hint_min_ms, 1);
	WRITE_ONCE(ftier_cfg.hint_max_ms, 1000);
	WRITE_ONCE(ftier_cfg.hint_mode, FTIER_HINT_MEDIAN);

	/* 3 * cool_ms / (2 * median) */
	KUNIT_EXPECT_EQ(test, round_threshold_ms(h3, 3), 150);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(h4, 4), 75);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(one, 1), 1000);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(huge, 1), 1);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(NULL, 0), 1000);

	WRITE_ONCE(ftier_cfg.hint_min_ms, 200);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(h3, 3), 200);

	WRITE_ONCE(ftier_cfg.hint_mode, FTIER_HINT_FIXED);
	KUNIT_EXPECT_EQ(test, round_threshold_ms(h20, 1), 1000);
}

static void level_case(struct kunit *test, int prev, int gap,
		       unsigned long pages, unsigned long cap,
		       unsigned int off_before, unsigned int off_after)
{
	ftier_ctx.level_off = off_before;
	ftier_ctx.gap_prev = prev;
	ftier_ctx.level_pages = pages;
	ftier_ctx.level_next_ns = 0;
	adapt_level(1, gap, cap);
	KUNIT_EXPECT_EQ_MSG(test, ftier_ctx.level_off, off_after,
			    "prev=%d gap=%d pages=%lu cap=%lu", prev, gap,
			    pages, cap);
	KUNIT_EXPECT_EQ(test, ftier_ctx.gap_prev, gap);
	KUNIT_EXPECT_EQ(test, ftier_ctx.level_pages, 0UL);
}

static void level_test(struct kunit *test)
{
	u64 colder, hotter;

	WRITE_ONCE(ftier_cfg.level_adapt, true);
	WRITE_ONCE(ftier_cfg.level_period_ms, 1000);
	WRITE_ONCE(ftier_cfg.level_small_pct, 25);
	WRITE_ONCE(ftier_cfg.level_full_pct, 90);
	WRITE_ONCE(ftier_cfg.level_jump_pct, 50);
	WRITE_ONCE(ftier_cfg.level_progress_pct, 10);
	WRITE_ONCE(ftier_cfg.level_deadband_pm, 20);
	colder = ftier_ctx.stats.nr_level_colder;
	hotter = ftier_ctx.stats.nr_level_hotter;

	/* Overshoot: the gap changed sign. */
	level_case(test, 500, -500, 500, 1000, 0, 1);
	KUNIT_EXPECT_EQ(test, ftier_ctx.stats.nr_level_colder, colder + 1);
	KUNIT_EXPECT_EQ(test, ftier_ctx.level_next_ns, 1 + NSEC_PER_SEC);

	/* Not due before the end of the period. */
	ftier_ctx.gap_prev = -500;
	adapt_level(2, 500, 1000);
	KUNIT_EXPECT_EQ(test, ftier_ctx.level_off, 1U);
	KUNIT_EXPECT_EQ(test, ftier_ctx.gap_prev, -500);

	/* Sensitive: a large change from a small volume. */
	level_case(test, 500, 100, 100, 1000, 1, 2);
	/* ... but not if nothing moved. */
	level_case(test, 500, 100, 0, 1000, 2, 2);
	/* ... nor from a large volume. */
	level_case(test, 500, 100, 500, 1000, 2, 2);

	/* Slow: near the cap, little progress. */
	level_case(test, 500, 480, 950, 1000, 2, 1);
	KUNIT_EXPECT_EQ(test, ftier_ctx.stats.nr_level_hotter, hotter + 1);
	/* Sufficient progress keeps the level. */
	level_case(test, 500, 300, 950, 1000, 1, 1);
	/* No level hotter than the hottest. */
	level_case(test, 500, 480, 950, 1000, 0, 0);
	KUNIT_EXPECT_EQ(test, ftier_ctx.stats.nr_level_hotter, hotter + 1);

	/* Within the deadband the tiers are balanced. */
	level_case(test, 10, -10, 500, 1000, 1, 1);
	level_case(test, 15, 500, 950, 1000, 1, 0);

	/* No level colder than the coldest. */
	level_case(test, 500, -500, 0, 1000, FTIER_HOT_LEVELS - 1,
		   FTIER_HOT_LEVELS - 1);
	/* A zero cap counts as no movement. */
	level_case(test, 500, 480, 950, 0, 1, 1);

	WRITE_ONCE(ftier_cfg.level_adapt, false);
	ftier_ctx.level_off = 3;
	adapt_level(1, 500, 1000);
	KUNIT_EXPECT_EQ(test, ftier_ctx.level_off, 0U);
}

static void signal_test(struct kunit *test)
{
	struct ftier_tier_sample s = { .dram_lat = 100, .cxl_lat = 150,
				       .promote_mb = 256 };
	u64 stale, t0;
	int gap, rate;

	WRITE_ONCE(ftier_cfg.level_period_ms, 1000);
	WRITE_ONCE(ftier_cfg.monitor_timeout_ms, 0);
	WRITE_ONCE(ftier_cfg.max_migrate_mbps, 1024);

	/* Without a report, the requested rate stands in for the gap. */
	ftier_tier.time_ns = 0;
	WRITE_ONCE(sysctl_promote_mb, 512);
	rate = tier_signal(ktime_get_ns(), &gap);
	KUNIT_EXPECT_EQ(test, rate, 512);
	KUNIT_EXPECT_EQ(test, gap, 500);

	ftier_report_tier_state(&s);
	t0 = ftier_tier.time_ns;
	KUNIT_EXPECT_EQ(test, READ_ONCE(sysctl_promote_mb), 256);
	rate = tier_signal(t0 + 1, &gap);
	KUNIT_EXPECT_EQ(test, rate, 256);
	KUNIT_EXPECT_EQ(test, gap, 500);

	s.dram_lat = 200;
	s.cxl_lat = 100;
	ftier_report_tier_state(&s);
	tier_signal(ftier_tier.time_ns, &gap);
	KUNIT_EXPECT_EQ(test, gap, -500);

	s.dram_lat = 1;
	s.cxl_lat = 1000;
	ftier_report_tier_state(&s);
	t0 = ftier_tier.time_ns;
	tier_signal(t0, &gap);
	KUNIT_EXPECT_EQ(test, gap, 10000);

	/* Reports older than two periods fall back to the rate. */
	tier_signal(t0 + 3 * NSEC_PER_SEC, &gap);
	KUNIT_EXPECT_EQ(test, gap, 250);

	/* A stale monitor stops migration. */
	WRITE_ONCE(ftier_cfg.monitor_timeout_ms, 1000);
	stale = ftier_ctx.stats.nr_monitor_stale;
	rate = tier_signal(t0 + 2 * NSEC_PER_SEC, &gap);
	KUNIT_EXPECT_EQ(test, rate, 0);
	KUNIT_EXPECT_EQ(test, gap, 0);
	KUNIT_EXPECT_EQ(test, ftier_ctx.stats.nr_monitor_stale, stale + 1);
	rate = tier_signal(t0 + NSEC_PER_SEC / 2, &gap);
	KUNIT_EXPECT_EQ(test, rate, 256);
}

static void hint_credit_test(struct kunit *test)
{
	atomic_long_set(&ftier_hint.credit, 0);
	ftier_hint_refill(100, 1000);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&ftier_hint.credit), 100L);
	ftier_hint_refill(2000, 1000);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&ftier_hint.credit), 1000L);
	ftier_hint_refill(-5000, 1000);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&ftier_hint.credit), 0L);
	/* A lowered cap clamps the credit. */
	ftier_hint_refill(800, 1000);
	ftier_hint_refill(0, 300);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&ftier_hint.credit), 300L);
}

static struct kunit_case ftier_test_cases[] = {
	KUNIT_CASE(hotlist_add_test),
	KUNIT_CASE(hotlist_order_test),
	KUNIT_CASE(hotlist_cool_test),
	KUNIT_CASE(hotlist_epoch_wrap_test),
	KUNIT_CASE(candidates_test),
	KUNIT_CASE(threshold_test),
	KUNIT_CASE(level_test),
	KUNIT_CASE(signal_test),
	KUNIT_CASE(hint_credit_test),
	{}
};

static struct kunit_suite ftier_test_suite = {
	.name = "ftier",
	.init = ftier_test_init,
	.exit = ftier_test_exit,
	.test_cases = ftier_test_cases,
};
kunit_test_suite(ftier_test_suite);
