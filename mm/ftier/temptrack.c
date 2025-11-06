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
static bool begin_fspin = false;
static bool fspin_ended = false;
static bool update_histogram = false;

static int FSCAN_PERIOD_MS;
static int FSPIN_PERIOD_MS;
static int PROMOTE_MB_TICK;
static int MIN_PMDS_FSPIN;
static int MAX_FHOT_PC;

static int ms_to_next_fscan = 0;
static int ms_to_fspin_end = 0;

static int fscans_completed = 0;
static int fspins_completed = 0;
static int ticks_completed = 0;

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

static void get_policy_nodemask(struct mempolicy *pol, nodemask_t *nodes)
{
	nodes_clear(*nodes);

	switch (pol->mode) {
	case MPOL_BIND:
	case MPOL_INTERLEAVE:
	case MPOL_PREFERRED:
	case MPOL_PREFERRED_MANY:
	case MPOL_WEIGHTED_INTERLEAVE:
		*nodes = pol->nodes;
		break;
	case MPOL_LOCAL:
		/* return empty node mask for local allocation */
		break;
	default:
		BUG();
	}
}

static inline void reset_spins(struct fhot_meta_gb *meta)
{
	memset(meta->spins, 0, sizeof(meta->spins));
}

static struct fhot_meta_gb * find_fhot_meta(pid_t pid, unsigned long addr)
{
	struct fhot_meta_gb *meta;
	list_for_each_entry(meta, &__ctx.target.fhot_list, siblings) {
		if ((meta->address == (addr & PUD_MASK)) && (meta->pid == pid))
			return meta;
	}
	return NULL;
}

static void alloc_fhot_meta(pid_t pid, unsigned long addr)
{
	struct task_struct *task = find_task_by_vpid(pid);
	struct fhot_meta_gb *meta;
	struct mempolicy *pol;
	nodemask_t nodemask;
	int idx;

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return;

	meta->pid = pid;
	meta->address = addr & PUD_MASK;
	meta->fspin_period_us = 20000; /* 20ms */

	pol = task->mempolicy;
	if (pol && pol->mode == MPOL_BIND) {
		get_policy_nodemask(pol, &nodemask);
		if (node_isset(2, nodemask) || node_isset(3, nodemask)) {
			for (idx = 0; idx < 8; ++idx)
				meta->cxlmap[idx] = ~0UL;
		}
	}

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

static void destroy_all_meta(pid_t pid)
{
	struct fhot_meta_gb *meta, *tmp;
	list_for_each_entry_safe(meta, tmp, &__ctx.target.fhot_list, siblings) {
		if (meta->pid == pid)
			destroy_fhot_meta(meta, true);
	}
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
		meta = find_fhot_meta(pid, addr);
		if (!meta)
			alloc_fhot_meta(pid, addr);
		else
			reset_spins(meta);
	} else {
		meta = find_fhot_meta(pid, addr);
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
			} else {
				destroy_all_meta(task->pid);
			}
		}
		css_task_iter_end(&it);
	}
}

static void count_mapped_entries(struct fhot_meta_gb *meta)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, _pmd;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long addr, next, end;
	unsigned int nr_mapped = 0;

	addr = meta->address;
	end = addr + PUD_SIZE;

	task = find_task_by_vpid(meta->pid);
	if (!task || task->flags & PF_EXITING)
		goto exit_destroy_meta;

	mm = get_task_mm(task);
	if (!mm)
		goto exit_destroy_meta;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto unlock;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto unlock;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto unlock;

	pmd = pmd_offset(pud, addr);

	do {
		next = pmd_addr_end(addr, end);

		if (pmd_none(*pmd))
			continue;

		_pmd = pmdp_get_lockless(pmd);
		if (is_swap_pmd(_pmd) || pmd_trans_huge(_pmd) || pmd_devmap(_pmd))
			continue;

		nr_mapped++;
	} while (pmd++, addr = next, addr < end);
unlock:
	mmput(mm);
	meta->nr_mapped = nr_mapped;
	return;
exit_destroy_meta:
	destroy_fhot_meta(meta, true);
}

struct fspin_args {
	struct work_struct work;
	struct fhot_meta_gb *meta;
};

static void fspin(struct work_struct *work_args)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, _pmd;
	struct task_struct *task;
	struct mm_struct *mm;
	struct fhot_meta_gb *meta;
	struct fspin_args *args;
	unsigned long addr, next, end, pmd_idx;
	uint64_t start_ns, end_ns;
	unsigned int min_hot, max_hot, dur_us, dur_sum_us;
	int remain_spin_us, fspin_period_us, nr_spins, nr_hot, sum_hot;

	args = container_of(work_args, struct fspin_args, work);
	meta = args->meta;

	task = find_task_by_vpid(meta->pid);
	if (!task || task->flags & PF_EXITING)
		goto free_out;

	min_hot = MIN_PMDS_FSPIN;
	max_hot = MAX_FHOT_PC * meta->nr_mapped / 100;
	remain_spin_us = FSPIN_PERIOD_MS * 1000;
	fspin_period_us = meta->fspin_period_us;
	dur_sum_us = 0;
	nr_spins = 0;
	sum_hot = 0;

	do {
		nr_hot = 0;
		addr = meta->address;
		end = addr + PUD_SIZE;

		if (task->flags & PF_EXITING)
			break;

		if (!fspinning)
			break;

		mm = get_task_mm(task);
		if (!mm)
			break;

		start_ns = ktime_get_ns();

		pgd = pgd_offset(mm, addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			goto unlock;

		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			goto unlock;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			goto unlock;

		pmd = pmd_offset(pud, addr);

		do {
			next = pmd_addr_end(addr, end);

			if (pmd_none(*pmd))
				continue;

			_pmd = pmdp_get_lockless(pmd);
			if (is_swap_pmd(_pmd) || pmd_trans_huge(_pmd) || pmd_devmap(_pmd))
				continue;

			if (pmdp_test_and_clear_young(NULL, addr, pmd)) {
				nr_hot++;
				pmd_idx = pmd_index(addr);
				meta->spins[pmd_idx]++;
			}
		} while (pmd++, addr = next, addr < end);
unlock:
		mmput(mm);

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
	memcpy(meta->oldspins, meta->spins, sizeof(meta->spins));
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

static void commit_sysctl_vals(void)
{
	FSCAN_PERIOD_MS = sysctl_fscan_period_ms;
	FSPIN_PERIOD_MS = sysctl_fspin_ms;
	PROMOTE_MB_TICK = sysctl_promote_mb;
	MIN_PMDS_FSPIN = sysctl_min_pmds_per_fscan;
	MAX_FHOT_PC = sysctl_max_fhot_pc;
}

static void FSCAN(void)
{
	if (ms_to_next_fscan <= 0) {
		fspin_ended = false;
		ms_to_next_fscan += FSCAN_PERIOD_MS;
		fscan_page_tables();
		begin_fspin = true;
		fscans_completed++;
	}
}

static void FSPIN_START(void)
{
	if (begin_fspin) {
		begin_fspin = false;
		do_fspin();
		fspinning = true;
		ms_to_fspin_end = FSPIN_PERIOD_MS;
	}
}

static void FSPIN_END(void)
{
	if (fspinning && ms_to_fspin_end <= 0) {
		fspinning = false;
		flush_workqueue(__ctx.target.wq);
		ms_to_fspin_end = 0;
		fspin_ended = true;
		update_histogram = true;
		fspins_completed++;
	}
}

static void TIER_MEMORY(int budget_ms)
{
	if (budget_ms < MIN_TIER_BUDGET_MS)
		return;

	if (tiering_on && fspins_completed) {
		ftier_tier_memory(&__ctx.target, PROMOTE_MB_TICK,
				(budget_ms * 1000), update_histogram);
		update_histogram = false;
	}
}

static int ftier_fn(void *data)
{
	unsigned int dur_ms;
	int budget_ms;
	uint64_t start_ns, end_ns;

	while (!kthread_should_stop()) {
		start_ns = ktime_get_ns();
		commit_sysctl_vals();

		if (!target_alive())
			goto end_iter;

		FSCAN();

		FSPIN_START();

		FSPIN_END();

		end_ns = ktime_get_ns();
		dur_ms = (end_ns - start_ns) / 1000000;
		budget_ms = TICK_BUDGET_MS - dur_ms;
		TIER_MEMORY(budget_ms);

		ms_to_next_fscan -= FTIER_TICK_MS;
		if (fspinning)
			ms_to_fspin_end -= FTIER_TICK_MS;

end_iter:
		end_ns = ktime_get_ns();
		dur_ms = (end_ns - start_ns) / 1000000;

		if (dur_ms > FTIER_TICK_MS) {
			pr_warn("ftier tick overrun (%u > %u ms)\n", dur_ms, FTIER_TICK_MS);
			continue;
		}
		ticks_completed++;
		ftier_delay_us((FTIER_TICK_MS - dur_ms) * 1000);
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
