// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier Memory Temperature Tracking
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>

struct ftier_ctx __ctx = {
	.task = NULL,
	.target = {
		.pid = -1,
	},
};

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

struct ftier_walk_private {
	unsigned long count;
	unsigned long pudmap[8];
};

static int fscan_1gb(pud_t *pud, unsigned long addr,
		     unsigned long end, struct mm_walk *walk)
{
	struct ftier_walk_private *priv = walk->private;
	unsigned long mask;
	unsigned int index;

	if (pud_young(*pud)) {
		pudp_clear_young_notify(walk->mm, addr, pud);
		index = pud_index(addr);
		mask = 1UL << (index & 0x3f);
		if (!(priv->pudmap[(index >> 6)] & mask)) {
			priv->count++;
			priv->pudmap[(index >> 6)] |= mask;
		}
	}

	walk->action = ACTION_CONTINUE;
	return 0;
}

static const struct mm_walk_ops ftier_walk_ops = {
	.pud_entry = fscan_1gb,
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

	pr_info("ftier: %lu 1GB pages accessed in %llu ns:\t"
					"%lx %lx %lx %lx %lx %lx %lx %lx\n",
			priv.count, (end_ns - start_ns), 
			priv.pudmap[0], priv.pudmap[1], priv.pudmap[2], priv.pudmap[3],
			priv.pudmap[4], priv.pudmap[5], priv.pudmap[6], priv.pudmap[7]);
}

static int ftier_fn(void *data)
{
	struct mm_struct *mm;
	unsigned int fscan_period_ms;

	while (!kthread_should_stop()) {
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

		mmput(mm);
end_iter:
		msleep_interruptible(fscan_period_ms);
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
	}

	return err;
}

int ftier_temptrack_stop(void)
{
	int err = -EPERM;

	if (__ctx.task) {
		kthread_stop(__ctx.task);
		err = 0;
		__ctx.task = NULL;
		__ctx.target.pid = -1;
	}

	return err;
}