// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Core Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>

struct tiering_ctx {
	struct task_struct *task;
} __tierctx;

int promote_pg_sec = 0;

static bool tiering_need_stop(void)
{
	if (kthread_should_stop())
		return true;
	return false;
}

static void congestier_usleep(unsigned long us)
{
	if (us >= USLEEP_RANGE_UPPER_BOUND)
		schedule_timeout_idle(usecs_to_jiffies(us));
	else
		usleep_range_idle(us, us + 1);
}

static int tiering_fn(void *data);

int tiering_start(void)
{
	int err = -EBUSY;

	if (!__tierctx.task) {
		__tierctx.task = kthread_run(tiering_fn, NULL, "tiering");
		if (IS_ERR(__tierctx.task)) {
			err = PTR_ERR(__tierctx.task);
			__tierctx.task = NULL;
		}
	}

	printk(KERN_INFO "START Tiering returned %d\n", err);
	return err;
}

int tiering_stop(void)
{
	if (__tierctx.task) {
		get_task_struct(__tierctx.task);
		kthread_stop_put(__tierctx.task);
		__tierctx.task = NULL;
		printk(KERN_INFO "Tiering stopped\n");
		return 0;
	}

	printk(KERN_ERR "STOP failed\n");
	return -EPERM;
}

static int tiering_fn(void *data)
{
	while (!tiering_need_stop()) {
		// Placeholder for tiering logic
		congestier_usleep(epoch_usecs);
	}

	return 0;
}