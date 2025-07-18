// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Migrate Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>

static inline int total_blocks_live(void)
{
	int total_blocks = 0;
	struct pg_temp_target *target;
	for (int i = 0; i < MAX_PGTEMP_TARGETS; ++i) {
		target = get_targets_ptr(i);
		if (target->pid == 0)
			continue;
		total_blocks += target->nr_blocks;
	}
	return total_blocks;
}

#ifdef CONFIG_NUMA_BALANCING

static void set_interleaving(unsigned long start, unsigned long end,
			unsigned long *newstart, unsigned long *newend, int scan_level)
{
	/* Just numa_fault the first half of [start,end) */
	*newstart = start;
	*newend = end;
}

static bool vma_is_accessed(struct task_struct *p, struct mm_struct *mm, struct vm_area_struct *vma)
{
	unsigned long pids;

	/* Allow unconditional access first 2 times */
	if ((READ_ONCE(mm->numa_scan_seq) - vma->numab_state->start_scan_seq) < 2)
		return true;

	pids = vma->numab_state->pids_active[0] | vma->numab_state->pids_active[1];
	if (test_bit(hash_32(p->pid, ilog2(BITS_PER_LONG)), &pids))
		return true;

	if (mm->numa_scan_offset > vma->vm_start)
		return true;

	if (READ_ONCE(mm->numa_scan_seq) >
			(vma->numab_state->prev_scan_seq + get_nr_threads(p)))
		return true;

	return false;
}

static int scan_migrate(struct pg_temp_target *target, 
								int pages_target, int target_nid_mask)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct vma_iterator vmi;
	unsigned long start, end, s, e;
	unsigned long nr_updates, migrate_time, total_updates = 0;
	int ret = 0, vpages_left = 8 * pages_target, pages = 0;
	static int target_mask_old = 0;
	bool vma_pids_skipped = false, vma_pids_forced = false;

	task = find_task_by_vpid(target->pid);
	if (!task || !pid_alive(task))
		return -1;

	if (task->flags & PF_EXITING)
		return 0;

	mm = get_task_mm(task);
	if (!mm)
		return -2;

	if (!mm->numa_next_scan)
		mm->numa_next_scan =
				jiffies + usecs_to_jiffies(sysctl_tiering_epoch_usecs);

	migrate_time = mm->numa_next_scan;
	if (time_before(jiffies, migrate_time))
		return 0;

	if (!mmap_read_trylock(mm))
		return -3;

retry:
	start = mm->numa_scan_offset;
	vma_iter_init(&vmi, mm, start);
	vma = vma_next(&vmi);
	if (!vma || target_mask_old != target_nid_mask) {
		start = 0;
		WRITE_ONCE(mm->numa_scan_seq, READ_ONCE(mm->numa_scan_seq) + 1);
		mm->numa_scan_offset = 0;
		vma_iter_set(&vmi, start);
		vma = vma_next(&vmi);
		target_mask_old = target_nid_mask;
	}

	for (; vma; vma = vma_next(&vmi)) {
		if (!vma_migratable(vma) || !vma_policy_mof(vma) || !vma_is_accessible(vma) ||
				is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_MIXEDMAP))
			continue;

		/*
		 * Shared library pages mapped by multiple processes are not
		 * migrated as it is expected they are cache replicated. Avoid
		 * hinting faults in read-only file-backed mappings or the vDSO
		 * as migrating the pages will be of marginal benefit.
		 */
		if (!vma->vm_mm ||
		    (vma->vm_file && (vma->vm_flags & (VM_READ|VM_WRITE)) == (VM_READ)))
			continue;

		if (!vma->numab_state) {
			struct vma_numab_state *ptr;

			ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
			if (!ptr)
				continue;
			if (cmpxchg(&vma->numab_state, NULL, ptr)) {
				kfree(ptr);
				continue;
			}

			vma->numab_state->start_scan_seq = mm->numa_scan_seq;
			vma->numab_state->next_scan = jiffies + \
				usecs_to_jiffies(sysctl_tiering_epoch_usecs);
			vma->numab_state->pids_active_reset = vma->numab_state->next_scan + \
							(4 * usecs_to_jiffies(sysctl_tiering_epoch_usecs));
			vma->numab_state->prev_scan_seq = mm->numa_scan_seq - 1;
		}

		/* Delay scan for newly-created VMAs */
		if (mm->numa_scan_seq && time_before(jiffies, vma->numab_state->next_scan))
			continue;

		/* Reset access PIDs for old VMAs */
		if (mm->numa_scan_seq &&
				time_after(jiffies, vma->numab_state->pids_active_reset)) {
			vma->numab_state->pids_active_reset += \
					(4 * usecs_to_jiffies(sysctl_tiering_epoch_usecs));
			vma->numab_state->pids_active[0] = READ_ONCE(vma->numab_state->pids_active[1]);
			vma->numab_state->pids_active[1] = 0;
		}

		/* Do not rescan VMAs twice within the same sequence. */
		if (vma->numab_state->prev_scan_seq == mm->numa_scan_seq) {
			mm->numa_scan_offset = vma->vm_end;
			continue;
		}

		/* Try our best not to scan VMA that task has not accessed */
		if (!vma_pids_forced && !vma_is_accessed(task, mm, vma)) {
			vma_pids_skipped = true;
			continue;
		}

		do {
			start = max(start, vma->vm_start);
			end = min3(start + HPAGE_SIZE,
				   start + (pages_target << PAGE_SHIFT),
				   vma->vm_end);
			set_interleaving(start, end, &s, &e,
					 target->fallscan_pg_per_block);
			nr_updates = change_prot_numa(vma, s, e);

			if (nr_updates)
				pages += (end - start) >> PAGE_SHIFT;
			vpages_left -= (end - start) >> PAGE_SHIFT;
			total_updates += nr_updates;

			start = end;
			ret = pages;
			if (pages_target <= pages || vpages_left <= 0)
				goto out;
		} while (end != vma->vm_end);

		vma->numab_state->prev_scan_seq = mm->numa_scan_seq;
		if (vma_pids_forced)
			break;
	}

	if (!vma && !vma_pids_forced && vma_pids_skipped) {
		vma_pids_forced = true;
		goto retry;
	}

out:
	printk(KERN_INFO "scan_migrate: pid=%d, pg_target=%d scanned=%d vpages=%d upd=%lu\n",
						target->pid, pages_target, pages, vpages_left, total_updates);

	if (vma) {
		mm->numa_scan_offset = start;
	} else {
		WRITE_ONCE(mm->numa_scan_seq, READ_ONCE(mm->numa_scan_seq) + 1);
		mm->numa_scan_offset = 0;
	}

	mmap_read_unlock(mm);
	mmput(mm);
	return ret;
}
#else /* CONFIG_NUMA_BALANCING */
int scan_migrate(struct pg_temp_target *target, int pages_target, int target_nid_mask) {}
#endif /* CONFIG_NUMA_BALANCING */

int fallback_migration(int pages_to_migrate, int nid_mask)
{
	int total_blocks = total_blocks_live();
	int pages_target, scanned = 0, scan_target;
	struct pg_temp_target *target;

	for (int targetidx = 0; targetidx < MAX_PGTEMP_TARGETS; ++targetidx) {
		target = get_targets_ptr(targetidx);
		if (!target || target->pid == 0 || target->nr_blocks < 20 || total_blocks < 100)
			continue;
		pages_target = pages_to_migrate * target->nr_blocks / total_blocks;
		scan_target = scan_migrate(target, pages_target, nid_mask);
		if (scan_target < 0) {
			printk(KERN_ERR "Fallback Migration failed for pid=%d (err=%d)\n",
							target->pid, scan_target);
			continue;
		}
		printk(KERN_INFO "fallback: scanned %d\n", scan_target);
		scanned += scan_target;
	}

	return scanned;
}