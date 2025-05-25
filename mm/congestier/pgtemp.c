// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Core Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

#include <linux/congestier.h>

#define MAX_PGTEMP_TARGETS			64
#define NR_TEMPERATURE_CLASSES	64

struct pheader {
	uint64_t head;
	uint64_t tail;
	uint64_t tail_start;
};

struct psample {
	uint64_t addr;
	uint64_t period;
	uint32_t time_ms, is_store;
	uint32_t cpu, pid;
};

struct pg_temp_block {
	uint64_t ld_temp;
	uint64_t period_sum_this_epoch_ld;
	uint64_t nr_samples_this_epoch_ld;
	uint64_t last_updated_epoch;
	uint64_t blocknum;
	int target_idx;
	struct list_head temper_class;
};

struct pg_temp_target {
	struct xarray blocks;
	pid_t pid;
	int nr_blocks;
	int epoch_created;
};

struct temperature_class {
	struct list_head blocks;
	struct mutex templock;
	int nr_blocks, tmp_cls_idx;
};

struct pebs_track_ctx {
	struct task_struct *task;
} __tempctx;

static struct pg_temp_target targets[MAX_PGTEMP_TARGETS];
static int nr_targets = 0;
// static int epochid = 0;

static struct temperature_class tmpcls[NR_TEMPERATURE_CLASSES + 1];
#define NEW_BLK_CLS (NR_TEMPERATURE_CLASSES)

// static int pebs_track_fn(void *data);

static void init_temperature_classes(void)
{
	for (int i = 0; i < NR_TEMPERATURE_CLASSES + 1; ++i) {
		INIT_LIST_HEAD(&tmpcls[i].blocks);
		mutex_init(&tmpcls[i].templock);
		tmpcls[i].nr_blocks = 0;
		tmpcls[i].tmp_cls_idx = i;
	}
}

static inline int temp_class(uint64_t temp)
{
	int i = 0;
	while (i < NR_TEMPERATURE_CLASSES && temp > 0) {
		temp >>= 1;
		i++;
	}
	return i;
}

static inline int target_idx_from_pid(pid_t pid)
{
	for (int i = 0; i < nr_targets; ++i) {
		if (targets[i].pid == pid)
			return i;
	}
	return -EINVAL;
}

// static inline int new_target_idx(pid_t pid)
// {
// 	if (nr_targets >= MAX_PGTEMP_TARGETS)
// 		return -ENOMEM;

// 	targets[nr_targets].pid = pid;
// 	targets[nr_targets].nr_blocks = 0;
// 	xa_init_flags(&(targets[nr_targets].blocks), XA_FLAGS_LOCK_BH);
// 	targets[nr_targets].epoch_created = epochid;

// 	return nr_targets++;
// }

static inline int new_target_idx(pid_t pid, int epoch_id)
{
	if (nr_targets >= MAX_PGTEMP_TARGETS)
		return -ENOMEM;

	targets[nr_targets].pid = pid;
	targets[nr_targets].nr_blocks = 0;
	xa_init_flags(&(targets[nr_targets].blocks), XA_FLAGS_LOCK_BH);
	targets[nr_targets].epoch_created = epoch_id;

	return nr_targets++;
}
	

// static bool pebs_track_need_stop(void)
// {
// 	if (kthread_should_stop())
// 		return true;
// 	return false;
// }

// static void congestier_usleep(unsigned long us)
// {
// 	if (us >= USLEEP_RANGE_UPPER_BOUND)
// 		schedule_timeout_idle(usecs_to_jiffies(us));
// 	else
// 		usleep_range_idle(us, us + 1);
// }

// int pebs_tracking_start(void)
// {
// 	int err = -EBUSY;

// 	if (!__tempctx.task) {
// 		err = 0;
// 		__tempctx.task = kthread_run(pebs_track_fn, NULL, "pebs_track");
// 		if (IS_ERR(__tempctx.task)) {
// 			err = PTR_ERR(__tempctx.task);
// 			__tempctx.task = NULL;
// 		}
// 	}

// 	printk(KERN_INFO "START returned %d\n", err);
// 	return err;
// }

// int pebs_tracking_stop(void)
// {
// 	if (__tempctx.task) {
// 		get_task_struct(__tempctx.task);
// 		kthread_stop_put(__tempctx.task);
// 		__tempctx.task = NULL;
// 		printk(KERN_INFO "PGTemp PEBS tracking stopped\n");
// 		return 0;
// 	}

// 	printk(KERN_INFO "STOP failed\n");
// 	return -EPERM;
// }

static void debug_print_temperature_classes(void)
{
	char *buf = kzalloc(1024, GFP_KERNEL);

	strcpy(buf, "TMPCLS ");
	for (int i = 0; i <= NR_TEMPERATURE_CLASSES; ++i)
	{
		struct temperature_class *cls = &tmpcls[i];
		int nr_blocks = cls->nr_blocks;
		if (nr_blocks > 0) {
			sprintf(buf + strlen(buf), "%d:%d ", i, nr_blocks);
		}
	}

	printk(KERN_INFO "%s\n", buf);
	kfree(buf);
}

// static void scrub_temperature_class(int clsidx)
// {
// 	struct pg_temp_block *blk;
// 	struct temperature_class *cls = &tmpcls[clsidx];
// 	struct list_head *pos, *n;
// 	uint64_t epochs_passed;
// 	int newclsidx;

// 	mutex_lock(&cls->templock);
// 	list_for_each_safe(pos, n, &cls->blocks) {
// 		blk = list_entry(pos, struct pg_temp_block, temper_class);

// 		epochs_passed = epochid - blk->last_updated_epoch;
// 		blk->ld_temp += blk->period_sum_this_epoch_ld;

// 		if (epochs_passed < NR_TEMPERATURE_CLASSES)
// 			blk->ld_temp >>= epochs_passed;
// 		else
// 			blk->ld_temp = 0;

// 		newclsidx = temp_class(blk->ld_temp);
// 		blk->period_sum_this_epoch_ld = 0; /* reset for next epoch */
// 		blk->nr_samples_this_epoch_ld = 0;
// 		blk->last_updated_epoch = epochid;

// 		if (newclsidx != clsidx) {
// 			list_del(pos);
// 			cls->nr_blocks--;
// 			mutex_lock(&tmpcls[newclsidx].templock);
// 			list_add(&blk->temper_class, &tmpcls[newclsidx].blocks);
// 			tmpcls[newclsidx].nr_blocks++;
// 			mutex_unlock(&tmpcls[newclsidx].templock);
// 		}
// 	}
// 	mutex_unlock(&cls->templock);
// }

/* update each entry and make consistent */
static void scrub_temperature_class(int clsidx, int epoch_id)
{
	struct pg_temp_block *blk;
	struct temperature_class *cls = &tmpcls[clsidx];
	struct list_head *pos, *n;
	uint64_t epochs_passed;
	int newclsidx;

	mutex_lock(&cls->templock);
	list_for_each_safe(pos, n, &cls->blocks) {
		blk = list_entry(pos, struct pg_temp_block, temper_class);

		epochs_passed = epoch_id - blk->last_updated_epoch;
		blk->ld_temp += blk->period_sum_this_epoch_ld;

		if (epochs_passed < NR_TEMPERATURE_CLASSES)
			blk->ld_temp >>= epochs_passed;
		else
			blk->ld_temp = 0;

		newclsidx = temp_class(blk->ld_temp);
		blk->period_sum_this_epoch_ld = 0; /* reset for next epoch */
		blk->nr_samples_this_epoch_ld = 0;
		blk->last_updated_epoch = epoch_id;

		if (newclsidx != clsidx) {
			list_del(pos);
			cls->nr_blocks--;
			mutex_lock(&tmpcls[newclsidx].templock);
			list_add(&blk->temper_class, &tmpcls[newclsidx].blocks);
			tmpcls[newclsidx].nr_blocks++;
			mutex_unlock(&tmpcls[newclsidx].templock);
		}
	}
	mutex_unlock(&cls->templock);
}

/* Release all blocks of this class - class must be scrubbed first */
static void free_temperature_class(int clsidx, int epoch_id)
{
	struct pg_temp_block *blk;
	struct temperature_class *cls = &tmpcls[clsidx];
	struct list_head *pos, *n;

	scrub_temperature_class(clsidx, epoch_id);
	if (cls->nr_blocks == 0)
		return; /* nothing to free */

	mutex_lock(&cls->templock);
	list_for_each_safe(pos, n, &cls->blocks) {
		blk = list_entry(pos, struct pg_temp_block, temper_class);
		list_del(pos);
		cls->nr_blocks--;
		xa_erase(&(targets[blk->target_idx].blocks), blk->blocknum);
		kfree(blk);
	}
	mutex_unlock(&cls->templock);
	cls->nr_blocks = 0;
}

void pebs_track_init(void)
{
	init_temperature_classes();
}

int pebs_track_epoch_work(int epoch_id)
{
	char *pebs_buffer_data = (char*)pebs_sample_buf + PAGE_SIZE;
	struct pheader *hdr = (struct pheader *)pebs_sample_buf;
	struct psample *smp;
	struct pg_temp_block *blk;
	uint64_t head, tail, offset;
	uint64_t blocknum, period, epspassed, temper;
	int pid, blockshift, targetidx, err, oldcls, newcls;
	int newblks = 0, minor_update_blks = 0, major_update_blks = 0;

	blockshift = PAGE_SHIFT + pgtemp_granularity_order;

	head = READ_ONCE(hdr->head);
	tail = max(READ_ONCE(hdr->tail), READ_ONCE(hdr->tail_start));

	while (tail < head) {
		offset = tail * sizeof(struct psample);
		offset &= CONGESTIER_BUF_SHIFT(pebs_buf_pg_order);
		smp = (struct psample *)(pebs_buffer_data + offset);

		if (smp->is_store)
			goto skip_this_sample;

		blocknum = smp->addr >> blockshift;
		pid = smp->pid;
		period = smp->period;

		targetidx = target_idx_from_pid(pid);
		if (targetidx < 0) {
			targetidx = new_target_idx(pid, epoch_id);
			if (targetidx < 0)
				goto skip_this_sample;
		}

		blk = xa_load(&(targets[targetidx].blocks), blocknum);
		if (!blk) {
			blk = kmalloc(sizeof(*blk), GFP_KERNEL);
			if (!blk)
				goto skip_this_sample;

			blk->ld_temp = 0;
			blk->period_sum_this_epoch_ld = period;
			blk->nr_samples_this_epoch_ld = 1;
			blk->last_updated_epoch = epoch_id;
			blk->blocknum = blocknum;
			blk->target_idx = targetidx;
			INIT_LIST_HEAD(&(blk->temper_class));

			xa_lock_bh(&(targets[targetidx].blocks));
			err = xa_err(__xa_store(&(targets[targetidx].blocks), 
						blocknum, blk, GFP_KERNEL));
			xa_unlock_bh(&(targets[targetidx].blocks));
			if (err) {
				kfree(blk);
				goto skip_this_sample;
			}
			++targets[targetidx].nr_blocks;
			++newblks;

			mutex_lock(&tmpcls[NEW_BLK_CLS].templock);
			list_add(&blk->temper_class, &tmpcls[NEW_BLK_CLS].blocks);
			tmpcls[NEW_BLK_CLS].nr_blocks++;
			mutex_unlock(&tmpcls[NEW_BLK_CLS].templock);
		} else if (blk->last_updated_epoch == epoch_id) {
			blk->period_sum_this_epoch_ld += period;
			blk->nr_samples_this_epoch_ld++;
			++minor_update_blks;
		} else {
			epspassed = epoch_id - blk->last_updated_epoch;					
			oldcls = temp_class(blk->ld_temp);
			temper = blk->ld_temp + blk->period_sum_this_epoch_ld;

			if (epspassed >= NR_TEMPERATURE_CLASSES)
				blk->ld_temp = 0;
			else
				blk->ld_temp = (temper >> epspassed);

			newcls = temp_class(blk->ld_temp);
			blk->period_sum_this_epoch_ld = period;
			blk->nr_samples_this_epoch_ld = 1;
			blk->last_updated_epoch = epoch_id;
			++major_update_blks;

			/* move to new temperature class */
			if (oldcls != newcls) {
				mutex_lock(&tmpcls[oldcls].templock);
				list_del(&blk->temper_class);
				tmpcls[oldcls].nr_blocks--;
				mutex_unlock(&tmpcls[oldcls].templock);

				mutex_lock(&tmpcls[newcls].templock);
				list_add(&blk->temper_class, &tmpcls[newcls].blocks);
				tmpcls[newcls].nr_blocks++;
				mutex_unlock(&tmpcls[newcls].templock);
			}
		}
skip_this_sample:
		++tail;
	}

	WRITE_ONCE(hdr->tail, tail);
	for (int tc = NR_TEMPERATURE_CLASSES; tc >= 0; --tc)
		scrub_temperature_class(tc, epoch_id);
	debug_print_temperature_classes();
	printk(KERN_INFO "PEBS epoch %d: (%llu %llu) (%d,%d,%d)\n", 
				epoch_id, head, tail, newblks,
				minor_update_blks, major_update_blks);

	return 0;
}

// static int pebs_track_fn(void *data)
// {
// 	char *pebs_buffer_data = (char*)pebs_sample_buf + PAGE_SIZE;
// 	struct pheader *hdr;
// 	struct psample *smp;
// 	struct pg_temp_block *blk;
// 	uint64_t head, tail, offset;
// 	uint64_t blocknum, period, epspassed, temper, dur_usecs;
// 	uint64_t start, end, scrub_start, scrub_end, scrub_usecs;
// 	int pid, blockshift, targetidx, err, oldcls, newcls;
// 	int newblks, minor_update_blks, major_update_blks;

// 	printk(KERN_INFO "PEBS Page Temperature Tracking started\n");

// 	hdr = (struct pheader *)pebs_sample_buf;
// 	blockshift = PAGE_SHIFT + pgtemp_granularity_order;
// 	newblks = minor_update_blks = major_update_blks = 0;
// 	init_temperature_classes();

// 	while (!pebs_track_need_stop()) {
// 		start = ktime_get_ns();
// 		head = READ_ONCE(hdr->head);
// 		tail = max(READ_ONCE(hdr->tail), READ_ONCE(hdr->tail_start));

// 		while (tail < head) {
// 			offset = tail * sizeof(struct psample);
// 			offset &= CONGESTIER_BUF_SHIFT(pebs_buf_pg_order);
// 			smp = (struct psample *)(pebs_buffer_data + offset);

// 			if (smp->is_store)
// 				goto skip_this_sample;

// 			blocknum = smp->addr >> blockshift;
// 			pid = smp->pid;
// 			period = smp->period;

// 			targetidx = target_idx_from_pid(pid);
// 			if (targetidx < 0) {
// 				targetidx = new_target_idx(pid);
// 				if (targetidx < 0)
// 					goto out;
// 			}

// 			blk = xa_load(&(targets[targetidx].blocks), blocknum);
// 			if (!blk) {
// 				blk = kmalloc(sizeof(*blk), GFP_KERNEL);
// 				if (!blk)
// 					goto skip_this_sample;

// 				blk->ld_temp = 0;
// 				blk->period_sum_this_epoch_ld = period;
// 				blk->nr_samples_this_epoch_ld = 1;
// 				blk->last_updated_epoch = epochid;
// 				blk->blocknum = blocknum;
// 				blk->target_idx = targetidx;
// 				INIT_LIST_HEAD(&(blk->temper_class));

// 				xa_lock_bh(&(targets[targetidx].blocks));
// 				err = xa_err(__xa_store(&(targets[targetidx].blocks), 
// 							blocknum, blk, GFP_KERNEL));
// 				xa_unlock_bh(&(targets[targetidx].blocks));
// 				if (err) {
// 					kfree(blk);
// 					goto skip_this_sample;
// 				}
// 				++targets[targetidx].nr_blocks;
// 				++newblks;

// 				/* add to temperature class NEW_BLK_CLS */
// 				mutex_lock(&tmpcls[NEW_BLK_CLS].templock);
// 				list_add(&blk->temper_class, &tmpcls[NEW_BLK_CLS].blocks);
// 				tmpcls[NEW_BLK_CLS].nr_blocks++;
// 				mutex_unlock(&tmpcls[NEW_BLK_CLS].templock);
// 			} else if (blk->last_updated_epoch == epochid) {
// 				blk->period_sum_this_epoch_ld += period;
// 				blk->nr_samples_this_epoch_ld++;
// 				++minor_update_blks;
// 			} else {
// 				epspassed = epochid - blk->last_updated_epoch;					
// 				oldcls = temp_class(blk->ld_temp);
// 				temper = blk->ld_temp + blk->period_sum_this_epoch_ld;

// 				if (epspassed >= NR_TEMPERATURE_CLASSES)
// 					blk->ld_temp = 0;
// 				else
// 					blk->ld_temp = (temper >> epspassed);

// 				newcls = temp_class(blk->ld_temp);
// 				blk->period_sum_this_epoch_ld = period;
// 				blk->nr_samples_this_epoch_ld = 1;
// 				blk->last_updated_epoch = epochid;
// 				++major_update_blks;

// 				/* move to new temperature class */
// 				if (oldcls != newcls) {
// 					mutex_lock(&tmpcls[oldcls].templock);
// 					list_del(&blk->temper_class);
// 					tmpcls[oldcls].nr_blocks--;
// 					mutex_unlock(&tmpcls[oldcls].templock);

// 					mutex_lock(&tmpcls[newcls].templock);
// 					list_add(&blk->temper_class, &tmpcls[newcls].blocks);
// 					tmpcls[newcls].nr_blocks++;
// 					mutex_unlock(&tmpcls[newcls].templock);
// 				}
// 			}
// skip_this_sample:
// 			++tail;
// 		}

// 		scrub_start = ktime_get_ns();
// 		for (int tc = NR_TEMPERATURE_CLASSES; tc >= 0; --tc)
// 			scrub_temperature_class(tc);
// 		scrub_end = ktime_get_ns();
// 		scrub_usecs = (scrub_end - scrub_start) / 1000;
// 		debug_print_temperature_classes();

// 		WRITE_ONCE(hdr->tail, tail);
// 		++epochid;
// 		end = ktime_get_ns();
// 		dur_usecs = (end - start) / 1000;
// 		printk(KERN_INFO "PEBS %llu(scr=%llu) usecs: (%llu %llu) (%d,%d,%d)\n", 
// 				dur_usecs, scrub_usecs, head, tail,
// 				newblks, minor_update_blks, major_update_blks);
// 		end = ktime_get_ns();
// 		dur_usecs = (end - start) / 1000;

// 		if (dur_usecs < epoch_usecs)
// 			congestier_usleep(epoch_usecs - dur_usecs);
// 		else {
// 			printk(KERN_WARNING "PEBS tracking took too long: %llu usecs\n", dur_usecs);
// 			congestier_usleep(epoch_usecs);
// 		}
// 	}

// 	return 0;
// out:
// 	printk(KERN_ERR "PEBS tracking failed: %d\n", targetidx);
// 	return -1;
// }

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */