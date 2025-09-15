// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier Memory Temperature Tracking
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>

struct ftier_ctx __ctx = {
	.task = NULL,
	.target = {
		.pid = -1,
		.fhot_list = LIST_HEAD_INIT(__ctx.target.fhot_list),
		.nr_fhot = 0,
	},
};

const unsigned int fspin_period_us_array[] = {
	50, 100, 250, 500, 800,
	1000, 2500, 5000, 8000,
	10000, 25000, 50000, 80000,
	100000, 250000, 500000,
};

#define MIN_FSPIN_PERIOD_US (fspin_period_us_array[0])
#define MAX_FSPIN_PERIOD_US \
		(fspin_period_us_array[ARRAY_SIZE(fspin_period_us_array) - 1])

static inline int incr_ftier_period_us(unsigned int us)
{
	int idx, len = ARRAY_SIZE(fspin_period_us_array);
	for (idx = 0; idx < len; ++idx) {
		if (fspin_period_us_array[idx] > us)
			return fspin_period_us_array[idx];
	}
	return MAX_FSPIN_PERIOD_US;
}

static inline int decr_ftier_period_us(unsigned int us)
{
	int idx, len = ARRAY_SIZE(fspin_period_us_array);
	for (idx = len - 1; idx >= 0; --idx) {
		if (fspin_period_us_array[idx] < us)
			return fspin_period_us_array[idx];
	}
	return MIN_FSPIN_PERIOD_US;
}

static bool tiering_on = false;

struct ftier_target *get_target(void)
{
	return &__ctx.target;
}

int set_target_pid(pid_t pid)
{
	struct task_struct *task;

	if (pid == __ctx.target.pid)
		return 0;

	if (pid > 0) {
		task = find_get_task_by_vpid(pid);
		if (!task)
			return -ESRCH;
	}

	if (__ctx.target.pid > 0) {
		task = find_task_by_vpid(__ctx.target.pid);
		if (task)
			put_task_struct(task);
	}

	__ctx.target.pid = pid;
	return 0;
}

static void ftier_delay_us(unsigned long us)
{
	if (us < 1000)
		udelay(us);
	else if (us < 20000)
		usleep_range(max(us - 1000, 1000UL), us);
	else
		msleep_interruptible(us / 1000);
}

static struct mm_struct *get_target_mm(void)
{
	struct task_struct *task;
	struct mm_struct *mm = NULL;

	if (__ctx.target.pid < 0)
		return NULL;

	task = find_task_by_vpid(__ctx.target.pid);
	if (!task)
		return NULL;
	mm = get_task_mm(task);

	return mm;
}

static struct fhot_meta_gb * find_fhot_meta(unsigned long addr)
{
	struct fhot_meta_gb *meta;
	list_for_each_entry(meta, &__ctx.target.fhot_list, siblings) {
		if (meta->address == (addr & PUD_MASK))
			return meta;
	}
	return NULL;
}

static void alloc_fhot_meta(pud_t *pud, unsigned long addr)
{
	struct fhot_meta_gb *meta;

	meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return;

	meta->pud = pud;
	meta->address = addr & PUD_MASK;
	meta->fspin_period_us = 10000; /* 10ms */
	meta->nr_mapped = 0;
	INIT_LIST_HEAD(&meta->siblings);
	list_add(&meta->siblings, &__ctx.target.fhot_list);
	__ctx.target.nr_fhot++;
}

static void destroy_fhot_meta(struct fhot_meta_gb *meta)
{
	list_del(&meta->siblings);
	kfree(meta);
	__ctx.target.nr_fhot--;
}

struct ftier_walk_private {
	unsigned long count;
	unsigned long pudmap[8];
};

static int fscan(pud_t *pud, unsigned long addr,
		     unsigned long end, struct mm_walk *walk)
{
	struct ftier_walk_private *priv = walk->private;
	struct fhot_meta_gb *meta;
	unsigned long mask;
	unsigned int index;

	if (pud_young(*pud)) {
		pudp_clear_young_notify(walk->mm, addr, pud);
		index = pud_index(addr);
		mask = 1UL << (index & 0x3f);
		if (!(priv->pudmap[(index >> 6)] & mask)) {
			priv->count++;
			priv->pudmap[(index >> 6)] |= mask;
			if (!find_fhot_meta(addr))
				alloc_fhot_meta(pud, addr);
		}
	} else if (!(priv->pudmap[(index >> 6)] & mask)) {
		meta = find_fhot_meta(addr);
		if (meta)
			destroy_fhot_meta(meta);
	}

	walk->action = ACTION_CONTINUE;
	return 0;
}

static const struct mm_walk_ops ftier_walk_ops = {
	.pud_entry = fscan,
	.walk_lock = PGWALK_RDLOCK,
};

static void fscan_page_tables(struct mm_struct *mm)
{
	unsigned long start = 0, end = 0x7fffffffffffUL;
	struct ftier_walk_private priv = { .count = 0, .pudmap = {0} };
	uint64_t start_ns, end_ns;

	start_ns = ktime_get_ns();
	mmap_read_lock(mm);
	walk_page_range(mm, start, end, &ftier_walk_ops, &priv);
	mmap_read_unlock(mm);
	end_ns = ktime_get_ns();

	pr_info("ftier: %lu 1GB pages (hot=%u) accessed in %llu ns:\t"
					"%lx %lx %lx %lx %lx %lx %lx %lx\n",
			priv.count, __ctx.target.nr_fhot, (end_ns - start_ns),
			priv.pudmap[0], priv.pudmap[1], priv.pudmap[2], priv.pudmap[3],
			priv.pudmap[4], priv.pudmap[5], priv.pudmap[6], priv.pudmap[7]);
}

static void count_mapped_entries(struct mm_struct *mm,
			struct fhot_meta_gb *meta)
{
	pud_t *pud = meta->pud;
	pmd_t *pmd;
	unsigned long addr, next, end;
	unsigned int nr_mapped = 0;

	addr = meta->address;
	end = addr + PUD_SIZE;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_present(*pmd))
			nr_mapped++;
		addr = next;
		pmd++;
	} while (pmd++, addr = next, addr < end);

	meta->nr_mapped = nr_mapped;
}

static void tune_fspin_period(struct mm_struct *mm,
			struct fhot_meta_gb *meta)
{
	pud_t *pud = meta->pud;
	pmd_t *pmd;
	unsigned long addr, next, end;
	uint64_t start_ns, end_ns;
	unsigned int fspin_period_us, dur_us, remaining_tries = 5;
	unsigned int min_hot, max_hot, nr_hot;
	bool first_iter = true, incr_period = false, decr_period = false;

	if (meta->nr_mapped < 5)
		return;

	fspin_period_us = meta->fspin_period_us;
	min_hot = 4 * meta->nr_mapped / 10;
	max_hot = 6 * meta->nr_mapped / 10;

	do {
		nr_hot = 0;
		addr = meta->address;
		end = addr + PUD_SIZE;
		pmd = pmd_offset(pud, addr);

		start_ns = ktime_get_ns();
		do {
			next = pmd_addr_end(addr, end);
			if (!pmd_present(*pmd))
				continue;

			if (pmdp_test_and_clear_young(NULL, addr, pmd))
				nr_hot++;
		} while (pmd++, addr = next, addr < end);
		end_ns = ktime_get_ns();

		dur_us = (end_ns - start_ns) / 1000;
		ftier_delay_us(fspin_period_us - dur_us);

		if (remaining_tries)
			--remaining_tries;

		if (first_iter) {
			first_iter = false;
			continue;
		}

		if (nr_hot < min_hot) {
			incr_period = true;
			fspin_period_us = incr_ftier_period_us(fspin_period_us);
		} else if (nr_hot > max_hot) {
			decr_period = true;
			fspin_period_us = decr_ftier_period_us(fspin_period_us);
		} else {
			/* within target range */
			break;
		}

		/* reached threshold */
		if ((decr_period && (fspin_period_us == MIN_FSPIN_PERIOD_US)) ||
				(incr_period && (fspin_period_us == MAX_FSPIN_PERIOD_US)))
			break;

		/* crossed the threshold once */
		if (!remaining_tries && incr_period && decr_period)
			break;

	} while (true);

	meta->fspin_period_us = fspin_period_us;
	pr_info("ftier: tune %lx fspin %u us, dur %u us, hot %u/%u\n",
			meta->address, fspin_period_us, dur_us, nr_hot, meta->nr_mapped);
}

static void prepare_fspin(struct mm_struct *mm)
{
	struct fhot_meta_gb *meta;

	list_for_each_entry(meta, &__ctx.target.fhot_list, siblings) {
		count_mapped_entries(mm, meta);
		tune_fspin_period(mm, meta);
	}
}

static int ftier_fn(void *data)
{
	struct mm_struct *mm;
	unsigned int fscan_period_ms, dur_ms;
	uint64_t start_ns, end_ns;

	while (!kthread_should_stop()) {
		start_ns = ktime_get_ns();
		fscan_period_ms = sysctl_fscan_period_ms;

		if (__ctx.target.pid < 0)
			goto end_iter;

		mm = get_target_mm();
		if (!mm) {
			/* target process has exited */
			set_target_pid(-1);
			goto end_iter;
		}

		fscan_page_tables(mm);

		prepare_fspin(mm);

		mmput(mm);
end_iter:
		end_ns = ktime_get_ns();
		dur_ms = (end_ns - start_ns) / 1000000;
		while (dur_ms >= fscan_period_ms)
			fscan_period_ms *= 2;
		ftier_delay_us((fscan_period_ms - dur_ms) * 1000);
	}

	return 0;
}

void ftier_tiering_start(void)
{
	tiering_on = true;
}

void ftier_tiering_stop(void)
{
	tiering_on = false;
}

int ftier_temptrack_start(void)
{
	int err = -EBUSY;

	if (!__ctx.task) {
		err = 0;
		__ctx.task = kthread_run(ftier_fn, NULL, "ftier");
		if (IS_ERR(__ctx.task)) {
			err = PTR_ERR(__ctx.task);
			__ctx.task = NULL;
		}
		__ctx.target.pid = -1;
		__ctx.target.nr_fhot = 0;
	}

	return err;
}

int ftier_temptrack_stop(void)
{
	int err = -EPERM;
	struct fhot_meta_gb *meta;

	if (__ctx.task) {
		kthread_stop(__ctx.task);
		err = 0;
		__ctx.task = NULL;
		__ctx.target.pid = -1;
		__ctx.target.nr_fhot = 0;
		while (!list_empty(&__ctx.target.fhot_list)) {
			meta = list_first_entry(&__ctx.target.fhot_list,
					struct fhot_meta_gb, siblings);
			destroy_fhot_meta(meta);
		}
	}

	return err;
}