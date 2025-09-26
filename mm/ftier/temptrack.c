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

#define CREATE_TRACE_POINTS
#include <trace/events/ftier.h>

struct ftier_ctx __ctx = {
	.task = NULL,
	.target = {
		.pid = -1,
		.cg = NULL,
		.type = FTIER_TARGET_PID,
		.fhot_list = LIST_HEAD_INIT(__ctx.target.fhot_list),
		.nr_fhot = 0,
		.wq = NULL,
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
static bool fspinning = false;

struct ftier_target *get_target(void)
{
	return &__ctx.target;
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

static inline void reset_spins(struct fhot_meta_gb *meta)
{
	memset(meta->spins, 0, sizeof(meta->spins));
}

static struct fhot_meta_gb * find_fhot_meta(struct mm_struct *mm,
		pid_t pid, unsigned long addr)
{
	struct fhot_meta_gb *meta;
	list_for_each_entry(meta, &__ctx.target.fhot_list, siblings) {
		if ((meta->address == (addr & PUD_MASK)) &&
				(meta->mm == mm) && (meta->pid == pid))
			return meta;
	}
	return NULL;
}

static void alloc_fhot_meta(struct mm_struct *mm,
		pud_t *pud, pid_t pid, unsigned long addr)
{
	struct fhot_meta_gb *meta;

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return;

	meta->pid = pid;
	meta->mm = mm;
	meta->pud = pud;
	meta->address = addr & PUD_MASK;
	meta->fspin_period_us = 20000; /* 20ms */

	INIT_LIST_HEAD(&meta->siblings);
	list_add(&meta->siblings, &__ctx.target.fhot_list);
	__ctx.target.nr_fhot++;
}

static void destroy_fhot_meta(struct fhot_meta_gb *meta, bool force)
{
	unsigned long mapsum = 0;
	int idx;

	/* dont destroy if we may lose CXL mapping info */
	if (!force) {
		for (idx = 0; idx < 8; ++idx)
			mapsum |= meta->cxlmap[idx];
	}

	if (mapsum)
		return;

	list_del(&meta->siblings);
	kfree(meta);
	__ctx.target.nr_fhot--;
}

int set_target_cgroup(const char *path)
{
	struct cgroup *cgrp;

	if (!path && !__ctx.target.cg)
		return 0;

	if (__ctx.target.cg) {
		cgroup_put(__ctx.target.cg);
		cgrp = NULL;

		fspinning = false;
		destroy_workqueue(__ctx.target.wq);
		while (!list_empty(&__ctx.target.fhot_list)) {
			struct fhot_meta_gb *meta;
			meta = list_first_entry(&__ctx.target.fhot_list,
					struct fhot_meta_gb, siblings);
			destroy_fhot_meta(meta, true);
		}
		__ctx.target.wq = NULL;
	}

	if (path) {
		cgrp = cgroup_get_from_path(path);
		if (IS_ERR(cgrp))
			return PTR_ERR(cgrp);

		__ctx.target.wq = alloc_workqueue("ftier_wq",
				WQ_UNBOUND|WQ_HIGHPRI|WQ_CPU_INTENSIVE, 0);
		if (!__ctx.target.wq) {
			cgroup_put(cgrp);
			return -ENOMEM;
		}
	}

	__ctx.target.cg = cgrp;
	__ctx.target.type = FTIER_TARGET_CGROUP;
	__ctx.target.nr_fhot = 0;
	return 0;
}

int set_target_pid(pid_t pid)
{
	struct task_struct *task;
	struct fhot_meta_gb *meta;

	if (pid == __ctx.target.pid)
		return 0;

	if (__ctx.target.pid > 0) {
		task = find_task_by_vpid(__ctx.target.pid);
		if (task)
			put_task_struct(task);

		fspinning = false;
		destroy_workqueue(__ctx.target.wq);
		while (!list_empty(&__ctx.target.fhot_list)) {
			meta = list_first_entry(&__ctx.target.fhot_list,
					struct fhot_meta_gb, siblings);
			destroy_fhot_meta(meta, true);
		}
		__ctx.target.wq = NULL;
	}

	if (pid > 0) {
		task = find_get_task_by_vpid(pid);
		if (!task)
			return -ESRCH;

		__ctx.target.wq = alloc_workqueue("ftier_wq",
				WQ_UNBOUND|WQ_HIGHPRI|WQ_CPU_INTENSIVE, 0);
		if (!__ctx.target.wq) {
			put_task_struct(task);
			return -ENOMEM;
		}
	}

	__ctx.target.nr_fhot = 0;
	__ctx.target.pid = pid;
	__ctx.target.type = FTIER_TARGET_PID;
	return 0;
}

struct ftier_walk_private {
	unsigned long count;
	pid_t pid;
};

static int fscan(pud_t *pud, unsigned long addr,
		     unsigned long end, struct mm_walk *walk)
{
	struct ftier_walk_private *priv = walk->private;
	pid_t pid = priv->pid;
	struct fhot_meta_gb *meta;
	static unsigned long last_addr = 0;

	if (last_addr == (addr & PUD_MASK))
		goto endscan;

	if (pud_young(*pud)) {
		pudp_clear_young_notify(walk->mm, addr, pud);
		priv->count++;
		meta = find_fhot_meta(walk->mm, pid, addr);
		if (!meta)
			alloc_fhot_meta(walk->mm, pud, pid, addr);
		else
			reset_spins(meta);
	} else {
		meta = find_fhot_meta(walk->mm, pid, addr);
		if (meta)
			destroy_fhot_meta(meta, false);
	}

	last_addr = addr & PUD_MASK;
endscan:
	walk->action = ACTION_CONTINUE;
	return 0;
}

static const struct mm_walk_ops ftier_walk_ops = {
	.pud_entry = fscan,
	.walk_lock = PGWALK_RDLOCK,
};

static void fscan_page_tables_mm(struct mm_struct *mm, pid_t pid)
{
	unsigned long start = 0, end = 0x7fffffffffffUL;
	struct ftier_walk_private priv = { .count = 0, .pid = pid };
	uint64_t start_ns, end_ns;

	start_ns = ktime_get_ns();
	mmap_read_lock(mm);
	walk_page_range(mm, start, end, &ftier_walk_ops, &priv);
	mmap_read_unlock(mm);
	end_ns = ktime_get_ns();

	trace_fscan(pid, __ctx.target.nr_fhot, (end_ns - start_ns) / 1000);
}

static void fscan_page_tables(void)
{
	struct mm_struct *mm;
	struct task_struct *task;
	struct cgroup *cg;
	struct css_task_iter it;

	if (__ctx.target.type == FTIER_TARGET_PID) {
		if (__ctx.target.pid < 0)
			return;

		task = find_task_by_vpid(__ctx.target.pid);
		if (!task)
			return;

		mm = get_task_mm(task);
		if (mm) {
			fscan_page_tables_mm(mm, __ctx.target.pid);
			mmput(mm);
		}
	} else {
		cg = __ctx.target.cg;
		if (!cg)
			return;

		css_task_iter_start(&cg->self, CSS_TASK_ITER_PROCS, &it);
		while ((task = css_task_iter_next(&it))) {
			mm = get_task_mm(task);
			if (mm) {
				fscan_page_tables_mm(mm, task->pid);
				mmput(mm);
			}
		}
		css_task_iter_end(&it);
	}
}

static void count_mapped_entries(struct fhot_meta_gb *meta)
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

struct fspin_args {
	struct work_struct work;
	struct fhot_meta_gb *meta;
};

static void fspin(struct work_struct *work_args)
{
	pud_t *pud;
	pmd_t *pmd;
	struct mm_struct *mm;
	struct fhot_meta_gb *meta;
	struct fspin_args *args;
	unsigned long addr, next, end, pmd_idx;
	uint64_t start_ns, end_ns;
	unsigned int min_hot, max_hot, dur_us, dur_sum_us;
	int remain_spin_us, fspin_period_us, nr_spins, nr_hot, sum_hot;

	args = container_of(work_args, struct fspin_args, work);
	meta = args->meta;
	mm = meta->mm;

	if (!mm)
		goto free_out;

	pud = meta->pud;
	min_hot = sysctl_min_pmds_per_fscan;
	max_hot = sysctl_max_fhot_pc * meta->nr_mapped / 100;
	remain_spin_us = sysctl_fspin_ms * 1000;
	fspin_period_us = meta->fspin_period_us;
	dur_sum_us = 0;
	nr_spins = 0;
	sum_hot = 0;

	mmget(mm);
	do {
		nr_hot = 0;
		addr = meta->address;
		end = addr + PUD_SIZE;
		pmd = pmd_offset(pud, addr);

		if (!fspinning)
			break;

		start_ns = ktime_get_ns();
		do {
			next = pmd_addr_end(addr, end);
			if (!pmd_present(*pmd))
				continue;

			if (pmdp_test_and_clear_young(NULL, addr, pmd)) {
				nr_hot++;
				pmd_idx = pmd_index(addr);
				meta->spins[pmd_idx]++;
			}
		} while (pmd++, addr = next, addr < end);
		end_ns = ktime_get_ns();

		dur_us = (end_ns - start_ns) / 1000;
		dur_sum_us += dur_us;
		sum_hot += nr_hot;
		nr_spins++;

		if (nr_hot < min_hot) {
			fspin_period_us = incr_ftier_period_us(fspin_period_us);
		} else if (nr_hot > max_hot) {
			fspin_period_us = decr_ftier_period_us(fspin_period_us);
		}

		while ((dur_us + 10) > fspin_period_us)
			fspin_period_us = incr_ftier_period_us(fspin_period_us);

		ftier_delay_us(fspin_period_us - dur_us);
		remain_spin_us -= fspin_period_us;
	} while ((remain_spin_us > 0) && (nr_spins < MAX_SPINS));

	meta->fspin_period_us = fspin_period_us;
	mmput(mm);
free_out:
	kfree(args);

	trace_fspin(meta->pid, meta->address, nr_spins,
			fspin_period_us, dur_sum_us, sum_hot, meta->nr_mapped);
}

static void do_fspin(void)
{
	struct fhot_meta_gb *meta, *next;
	struct fspin_args *args;

	list_for_each_entry_safe(meta, next, &__ctx.target.fhot_list, siblings) {
		count_mapped_entries(meta);
		if (meta->nr_mapped < 5) {
			destroy_fhot_meta(meta, false);
		} else {
			args = kzalloc(sizeof(*args), GFP_KERNEL);
			if (!args)
				return;

			INIT_WORK(&args->work, fspin);
			args->meta = meta;
			queue_work(__ctx.target.wq, &args->work);
		}
	}
}

static bool target_alive(void)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct css_task_iter it;
	struct cgroup *cg;
	bool is_alive = false;

	if (__ctx.target.type == FTIER_TARGET_PID) {
		if (__ctx.target.pid < 0)
			return false;

		task = find_task_by_vpid(__ctx.target.pid);
		if (!task)
			return false;

		mm = get_task_mm(task);
		if (!mm) {
			set_target_pid(-1);
			return false;
		}
		mmput(mm);
		is_alive = true;
	} else {
		/* there exists at least one task in the cgroup ? */
		cg = __ctx.target.cg;
		if (!cg)
			return false;

		css_task_iter_start(&cg->self, CSS_TASK_ITER_PROCS, &it);
		while ((task = css_task_iter_next(&it))) {
			mm = get_task_mm(task);
			if (mm) {
				is_alive = true;
				mmput(mm);
				break;
			}
		}
		css_task_iter_end(&it);
	}

	return is_alive;
}

static int ftier_fn(void *data)
{
	unsigned int fscan_period_ms, fspin_ms, dur_ms;
	uint64_t start_ns, end_ns;

	while (!kthread_should_stop()) {
		start_ns = ktime_get_ns();
		fscan_period_ms = sysctl_fscan_period_ms;
		fspin_ms = sysctl_fspin_ms;

		if (!target_alive())
			goto end_iter;

		fscan_page_tables();

		fspinning = true;
		do_fspin();
		ftier_delay_us(fspin_ms * 1000);

		fspinning = false;
		flush_workqueue(__ctx.target.wq);

		if (tiering_on && !kthread_should_stop())
			ftier_tier_memory(&__ctx.target);

end_iter:
		end_ns = ktime_get_ns();
		dur_ms = (end_ns - start_ns) / 1000000;
		while (dur_ms >= fscan_period_ms)
			fscan_period_ms *= 2;
		if (fscan_period_ms > sysctl_fscan_period_ms)
			pr_info("fscan took too long (%u ms). period increased to %u ms\n",
					dur_ms, fscan_period_ms);
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
		__ctx.target.wq = alloc_workqueue("ftier_wq",
				WQ_UNBOUND|WQ_HIGHPRI|WQ_CPU_INTENSIVE, 0);
		if (!__ctx.target.wq)
			err = -ENOMEM;
	}

	return err;
}

int ftier_temptrack_stop(void)
{
	int err = -EPERM;
	struct fhot_meta_gb *meta;

	if (__ctx.task) {
		kthread_stop(__ctx.task);
		fspinning = false;
		err = 0;
		__ctx.task = NULL;
		__ctx.target.pid = -1;
		__ctx.target.nr_fhot = 0;
		if (__ctx.target.wq)
			destroy_workqueue(__ctx.target.wq);
		while (!list_empty(&__ctx.target.fhot_list)) {
			meta = list_first_entry(&__ctx.target.fhot_list,
					struct fhot_meta_gb, siblings);
			destroy_fhot_meta(meta, true);
		}
	}

	return err;
}
