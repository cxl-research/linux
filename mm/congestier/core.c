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

static int epochid = 0;

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

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

int pebs_tracking_start(void)
{
	int err = -EBUSY;

	if (!__tierctx.task) {
		err = 0;
		__tierctx.task = kthread_run(tiering_fn, NULL, "tiering");
		if (IS_ERR(__tierctx.task)) {
			err = PTR_ERR(__tierctx.task);
			__tierctx.task = NULL;
		}
	}

	printk(KERN_INFO "START returned %d\n", err);
	return err;
}

int pebs_tracking_stop(void)
{
	if (__tierctx.task) {
		get_task_struct(__tierctx.task);
		kthread_stop_put(__tierctx.task);
		__tierctx.task = NULL;
		printk(KERN_INFO "PGTemp PEBS tracking stopped\n");
		return 0;
	}

	printk(KERN_INFO "STOP failed\n");
	return -EPERM;
}

int tiering_start(void) { return 0; }
int tiering_stop(void) { return 0; }

static void pgtemp_track_init(void)
{
	pebs_track_init();
}

static int pgtemp_track_epoch_work(int epoch_id)
{
	return pebs_track_epoch_work(epoch_id);
}

#else /* CONFIG_CONGESTIER_PGTEMP_PEBS */

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

static void pgtemp_track_init(void) {}
static int pgtemp_track_epoch_work(int epoch_id) { return 0; }

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */

static int tiering_fn(void *data)
{
	uint64_t start, end, dur_usecs;

	pgtemp_track_init();

	while (!tiering_need_stop()) {
		start = ktime_get_ns();

		pgtemp_track_epoch_work(epochid);

		if (READ_ONCE(tiering_mode) == TIERING_MODE_OFF)
			goto end_epoch;

end_epoch:
		end = ktime_get_ns();
		dur_usecs = (end - start) / 1000;
		printk(KERN_INFO "Tiering epoch %d took %llu usecs\n", epochid, dur_usecs);
		++epochid;

		if (dur_usecs < epoch_usecs) {
			end = ktime_get_ns();
			dur_usecs = (end - start) / 1000;
			congestier_usleep(epoch_usecs - dur_usecs);
		} else {
			printk(KERN_WARNING "Tiering took too long: %llu usecs\n", dur_usecs);
			congestier_usleep(epoch_usecs);
		}
	}

	return 0;
}