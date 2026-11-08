// SPDX-License-Identifier: GPL-2.0
/*
 * FTier sysfs interface: /sys/kernel/mm/ftier/
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */

#include <linux/cgroup.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "internal.h"

enum ftier_status sysctl_ftier_status = FTIER_STATUS_OFF;
enum ftier_tiering_mode sysctl_tiering_mode = DEMAND_MIGRATE;
int sysctl_promote_mb;
EXPORT_SYMBOL_GPL(sysctl_promote_mb);

static const char * const ftier_status_strs[] = {
	[FTIER_STATUS_OFF] = "off",
	[FTIER_STATUS_TRACK] = "tracking",
	[FTIER_STATUS_TIER] = "tiering",
};

static const char * const ftier_tiering_mode_strs[] = {
	[DEMAND_MIGRATE] = "demand_migrate",
	[HINT_FAULT] = "hint_fault",
};

static int update_ftier_status(enum ftier_status old_status,
			       enum ftier_status new_status)
{
	int err = 0;

	if (old_status == FTIER_STATUS_OFF)
		err = ftier_start();
	if (err)
		return err;

	switch (new_status) {
	case FTIER_STATUS_OFF:
		ftier_stop();
		break;
	case FTIER_STATUS_TRACK:
		ftier_set_tiering(false);
		break;
	case FTIER_STATUS_TIER:
		ftier_set_tiering(true);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static ssize_t ftier_status_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  ftier_status_strs[READ_ONCE(sysctl_ftier_status)]);
}

static ssize_t ftier_status_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	enum ftier_status new_status, old_status;
	int err = 0;

	new_status = sysfs_match_string(ftier_status_strs, buf);
	if ((int)new_status < 0)
		return -EINVAL;

	mutex_lock(&ftier_state_lock);
	old_status = sysctl_ftier_status;
	if (new_status != old_status) {
		err = update_ftier_status(old_status, new_status);
		if (!err)
			WRITE_ONCE(sysctl_ftier_status, new_status);
	}
	mutex_unlock(&ftier_state_lock);

	return err ? err : count;
}
static struct kobj_attribute ftier_status_attr = __ATTR_RW(ftier_status);

static ssize_t ftier_tiering_mode_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
		ftier_tiering_mode_strs[READ_ONCE(sysctl_tiering_mode)]);
}

static ssize_t ftier_tiering_mode_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	int mode = sysfs_match_string(ftier_tiering_mode_strs, buf);

	if (mode < 0)
		return -EINVAL;
	mutex_lock(&ftier_state_lock);
	WRITE_ONCE(sysctl_tiering_mode, mode);
	mutex_unlock(&ftier_state_lock);
	return count;
}
static struct kobj_attribute ftier_tiering_mode_attr =
		__ATTR_RW(ftier_tiering_mode);

static ssize_t target_pid_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;

	mutex_lock(&ftier_lock);
	if (ftier_ctx.type == FTIER_TARGET_PID && ftier_ctx.pid)
		ret = sysfs_emit(buf, "pid:%d\n", pid_vnr(ftier_ctx.pid));
	else
		ret = sysfs_emit(buf, "no target pid set\n");
	mutex_unlock(&ftier_lock);
	return ret;
}

static ssize_t target_pid_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	pid_t pid;
	int err;

	if (sysfs_streq(buf, "none")) {
		pid = -1;
	} else {
		err = kstrtoint(buf, 10, &pid);
		if (err || pid <= 0)
			return -EINVAL;
	}

	mutex_lock(&ftier_state_lock);
	if (sysctl_ftier_status == FTIER_STATUS_OFF)
		err = -EPERM;
	else
		err = ftier_set_target_pid(pid);
	mutex_unlock(&ftier_state_lock);

	return err ? err : count;
}
static struct kobj_attribute target_pid_attr = __ATTR_RW(target_pid);

static ssize_t target_cgroup_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	char *path;
	ssize_t ret;

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	mutex_lock(&ftier_lock);
	if (ftier_ctx.type != FTIER_TARGET_CGROUP || !ftier_ctx.cgrp) {
		ret = sysfs_emit(buf, "no target cgroup set\n");
	} else {
		ret = cgroup_path(ftier_ctx.cgrp, path, PATH_MAX);
		if (ret >= 0)
			ret = sysfs_emit(buf, "cgroup:%s\n", path);
	}
	mutex_unlock(&ftier_lock);
	kfree(path);
	return ret;
}

static ssize_t target_cgroup_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	char *path;
	int err;

	path = kstrndup(buf, count, GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	strim(path);
	if (!*path) {
		kfree(path);
		return -EINVAL;
	}

	mutex_lock(&ftier_state_lock);
	if (sysctl_ftier_status == FTIER_STATUS_OFF)
		err = -EPERM;
	else if (!strcmp(path, "none"))
		err = ftier_set_target_cgroup(NULL);
	else
		err = ftier_set_target_cgroup(path);
	mutex_unlock(&ftier_state_lock);

	kfree(path);
	return err ? err : count;
}
static struct kobj_attribute target_cgroup_attr = __ATTR_RW(target_cgroup);

/* Signed legacy knobs. */
#define FTIER_INT_ATTR(_name, _var, _min, _max)				\
static ssize_t _name##_show(struct kobject *kobj,			\
			    struct kobj_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%d\n", READ_ONCE(_var));		\
}									\
static ssize_t _name##_store(struct kobject *kobj,			\
			     struct kobj_attribute *attr,		\
			     const char *buf, size_t count)		\
{									\
	int val, err;							\
									\
	err = kstrtoint(buf, 10, &val);					\
	if (err || val < (_min) || val > (_max))			\
		return -EINVAL;						\
	WRITE_ONCE(_var, val);						\
	return count;							\
}									\
static struct kobj_attribute _name##_attr = __ATTR_RW(_name)

FTIER_INT_ATTR(promote_mb, sysctl_promote_mb, -102400, 102400);

static int ftier_cfg_validate(const struct ftier_config *c)
{
	if (c->min_period_us > c->max_period_us ||
	    c->init_period_us < c->min_period_us ||
	    c->init_period_us > c->max_period_us)
		return -EINVAL;
	if (c->tick_ms > c->interval_ms)
		return -EINVAL;
	if (c->hint_min_ms > c->hint_max_ms)
		return -EINVAL;
	return 0;
}

/*
 * Unsigned tunables in ftier_cfg. @_live is false for those that can
 * only change while FTier is off.
 */
#define FTIER_CFG_ATTR(_name, _field, _min, _max, _live)		\
static ssize_t _name##_show(struct kobject *kobj,			\
			    struct kobj_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%u\n", (unsigned int)FTIER_CFG(_field));\
}									\
static ssize_t _name##_store(struct kobject *kobj,			\
			     struct kobj_attribute *attr,		\
			     const char *buf, size_t count)		\
{									\
	struct ftier_config c;						\
	unsigned int val;						\
	int err;							\
									\
	err = kstrtouint(buf, 0, &val);					\
	if (err)							\
		return err;						\
	if (val < (_min) || val > (_max))				\
		return -EINVAL;						\
	mutex_lock(&ftier_state_lock);					\
	if (!(_live) && sysctl_ftier_status != FTIER_STATUS_OFF) {	\
		err = -EBUSY;						\
		goto out;						\
	}								\
	c = ftier_cfg;							\
	c._field = val;							\
	err = ftier_cfg_validate(&c);					\
	if (!err)							\
		WRITE_ONCE(ftier_cfg._field, val);			\
out:									\
	mutex_unlock(&ftier_state_lock);				\
	return err ? err : count;					\
}									\
static struct kobj_attribute _name##_attr = __ATTR_RW(_name)

#define FTIER_BOOL_ATTR(_name, _field)					\
static ssize_t _name##_show(struct kobject *kobj,			\
			    struct kobj_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, "%d\n", FTIER_CFG(_field));		\
}									\
static ssize_t _name##_store(struct kobject *kobj,			\
			     struct kobj_attribute *attr,		\
			     const char *buf, size_t count)		\
{									\
	bool val;							\
									\
	if (kstrtobool(buf, &val))					\
		return -EINVAL;						\
	WRITE_ONCE(ftier_cfg._field, val);				\
	return count;							\
}									\
static struct kobj_attribute _name##_attr = __ATTR_RW(_name)

FTIER_CFG_ATTR(tick_ms, tick_ms, 10, 1000, true);
FTIER_CFG_ATTR(interval_ms, interval_ms, 100, 60000, true);
FTIER_CFG_ATTR(fscan_period_ms, fscan_period_ms, 1000, 300000, true);
FTIER_CFG_ATTR(pud_idle_scans, pud_idle_scans, 0, 1000, true);
FTIER_CFG_ATTR(scans_per_interval, scans_per_interval, 1, U16_MAX, true);
FTIER_CFG_ATTR(init_period_us, init_period_us, 10, 10000000, true);
FTIER_CFG_ATTR(min_period_us, min_period_us, 10, 10000000, true);
FTIER_CFG_ATTR(max_period_us, max_period_us, 10, 10000000, true);
FTIER_CFG_ATTR(low_wm, low_wm, 0, FTIER_NR_PMD, true);
FTIER_CFG_ATTR(high_wm_pct, high_wm_pct, 1, 100, true);
FTIER_CFG_ATTR(slack_us, slack_us, 0, 100000, true);
FTIER_CFG_ATTR(cool_ms, cool_ms, 100, 600000, true);
FTIER_CFG_ATTR(nr_scanners, nr_scanners, 1, FTIER_MAX_SCANNERS, false);
FTIER_CFG_ATTR(migrate_batch, migrate_batch, 1, 512, true);
FTIER_CFG_ATTR(max_migrate_mbps, max_migrate_mbps, 0, 102400, true);
/* Pre-AFS-rework names of the scan watermarks. */
FTIER_CFG_ATTR(min_pmds_per_fscan, low_wm, 0, FTIER_NR_PMD, true);
FTIER_CFG_ATTR(max_fhot_pc, high_wm_pct, 1, 100, true);
FTIER_BOOL_ATTR(track_thp, track_thp);
FTIER_BOOL_ATTR(notify_secondary, notify_secondary);
FTIER_CFG_ATTR(flush_tlb, flush_tlb, 0, FTIER_FLUSH_MAX, true);
FTIER_CFG_ATTR(max_candidates, max_candidates, 1, FTIER_MAX_CANDIDATES, true);
FTIER_CFG_ATTR(hint_min_ms, hint_min_ms, 1, 60000, true);
FTIER_CFG_ATTR(hint_max_ms, hint_max_ms, 1, 60000, true);
FTIER_CFG_ATTR(hint_pass_bp, hint_pass_bp, 0, 10000, true);
/* Pre-rework names of the hint-fault threshold and pass ratio. */
FTIER_CFG_ATTR(hint_fault_latency_threshold_ms, hint_max_ms, 1, 60000, true);
FTIER_CFG_ATTR(hf_pass_ratio_bp, hint_pass_bp, 0, 10000, true);
FTIER_BOOL_ATTR(level_adapt, level_adapt);
FTIER_CFG_ATTR(level_period_ms, level_period_ms, 100, 60000, true);
FTIER_CFG_ATTR(level_small_pct, level_small_pct, 0, 100, true);
FTIER_CFG_ATTR(level_full_pct, level_full_pct, 1, 100, true);
FTIER_CFG_ATTR(level_jump_pct, level_jump_pct, 1, 1000, true);
FTIER_CFG_ATTR(level_progress_pct, level_progress_pct, 0, 100, true);
FTIER_CFG_ATTR(level_deadband_pm, level_deadband_pm, 0, 10000, true);
FTIER_CFG_ATTR(monitor_timeout_ms, monitor_timeout_ms, 0, 600000, true);

static const char * const ftier_hint_mode_strs[] = {
	[FTIER_HINT_MEDIAN] = "median",
	[FTIER_HINT_FIXED] = "fixed",
	[FTIER_HINT_HISTOGRAM] = "histogram",
};

static ssize_t hint_mode_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
			  ftier_hint_mode_strs[FTIER_CFG(hint_mode)]);
}

static ssize_t hint_mode_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	int mode = sysfs_match_string(ftier_hint_mode_strs, buf);

	if (mode < 0)
		return -EINVAL;
	WRITE_ONCE(ftier_cfg.hint_mode, mode);
	return count;
}
static struct kobj_attribute hint_mode_attr = __ATTR_RW(hint_mode);

static ssize_t hint_thresh_ms_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", READ_ONCE(ftier_hint.thresh_ms));
}
static struct kobj_attribute hint_thresh_ms_attr = __ATTR_RO(hint_thresh_ms);

/*
 * "dram_lat cxl_lat dram_mbps cxl_mbps promote_mb": a tier measurement
 * from a user space monitor, as ftier_report_tier_state().
 */
static ssize_t tier_report_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct ftier_tier_sample s;

	if (sscanf(buf, "%llu %llu %llu %llu %d", &s.dram_lat, &s.cxl_lat,
		   &s.dram_mbps, &s.cxl_mbps, &s.promote_mb) != 5)
		return -EINVAL;
	if (s.promote_mb < -102400 || s.promote_mb > 102400)
		return -EINVAL;
	ftier_report_tier_state(&s);
	return count;
}
static struct kobj_attribute tier_report_attr = __ATTR_WO(tier_report);

static ssize_t level_off_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", READ_ONCE(ftier_ctx.level_off));
}
static struct kobj_attribute level_off_attr = __ATTR_RO(level_off);

/*
 * Tier membership. Both tiers must be non-empty sets of memory nodes and
 * disjoint. The fault path reads the masks locklessly, so a concurrent
 * update can briefly misclassify a node; nothing worse happens.
 */
static ssize_t nodes_store(nodemask_t *mask, const nodemask_t *other,
			   const char *buf, size_t count)
{
	nodemask_t new;
	int err;

	err = nodelist_parse(buf, new);
	if (err)
		return err;
	if (nodes_empty(new) || !nodes_subset(new, node_states[N_MEMORY]) ||
	    nodes_intersects(new, *other))
		return -EINVAL;
	mutex_lock(&ftier_state_lock);
	mutex_lock(&ftier_lock);
	*mask = new;
	mutex_unlock(&ftier_lock);
	mutex_unlock(&ftier_state_lock);
	return count;
}

static ssize_t dram_nodes_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%*pbl\n", nodemask_pr_args(&ftier_dram_nodes));
}

static ssize_t dram_nodes_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	return nodes_store(&ftier_dram_nodes, &ftier_cxl_nodes, buf, count);
}
static struct kobj_attribute dram_nodes_attr = __ATTR_RW(dram_nodes);

static ssize_t cxl_nodes_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%*pbl\n", nodemask_pr_args(&ftier_cxl_nodes));
}

static ssize_t cxl_nodes_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	return nodes_store(&ftier_cxl_nodes, &ftier_dram_nodes, buf, count);
}
static struct kobj_attribute cxl_nodes_attr = __ATTR_RW(cxl_nodes);

/* Scanning is continuous since the AFS rework: kept for compatibility. */
static int sysctl_fspin_ms = 5000;
FTIER_INT_ATTR(fspin_ms, sysctl_fspin_ms, 1000, 60000);

static ssize_t stats_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	struct ftier_stats st;
	u64 nr_scans = 0, busy_ns = 0, nr_flush = 0;
	unsigned long nr_spaces, nr_puds = 0, nr_hot;
	struct ftier_space *sp;
	unsigned int i;
	int len = 0;

	mutex_lock(&ftier_lock);
	st = ftier_ctx.stats;
	nr_spaces = ftier_ctx.nr_spaces;
	nr_hot = ftier_ctx.hotlist.nr_entries;
	list_for_each_entry(sp, &ftier_ctx.spaces, link)
		nr_puds += sp->nr_puds;
	for (i = 0; i < ftier_ctx.nr_scanners; i++) {
		nr_scans += READ_ONCE(ftier_ctx.scanners[i].nr_scans);
		busy_ns += READ_ONCE(ftier_ctx.scanners[i].busy_ns);
		nr_flush += READ_ONCE(ftier_ctx.scanners[i].nr_tlb_flush);
	}
	mutex_unlock(&ftier_lock);

#define S(name, val) len += sysfs_emit_at(buf, len, "%s %llu\n", name, \
					   (unsigned long long)(val))
	S("nr_spaces", nr_spaces);
	S("nr_puds", nr_puds);
	S("nr_hot_entries", nr_hot);
	S("nr_fscans", st.nr_fscans);
	S("fscan_us", div_u64(st.fscan_ns, NSEC_PER_USEC));
	S("nr_pmd_scans", nr_scans);
	S("pmd_scan_us", div_u64(busy_ns, NSEC_PER_USEC));
	S("nr_tlb_flush", nr_flush);
	S("nr_intervals", st.nr_intervals);
	S("collect_us", div_u64(st.collect_ns, NSEC_PER_USEC));
	S("nr_throttled", st.nr_throttled);
	S("nr_lock_miss", st.nr_lock_miss);
	S("nr_pud_added", st.nr_pud_added);
	S("nr_pud_removed", st.nr_pud_removed);
	S("nr_space_added", st.nr_space_added);
	S("nr_space_removed", st.nr_space_removed);
	S("nr_cool", st.nr_cool);
	S("nr_tier_ticks", st.nr_tier_ticks);
	S("tier_us", div_u64(st.tier_ns, NSEC_PER_USEC));
	S("nr_promoted", st.nr_promoted);
	S("nr_demoted", st.nr_demoted);
	S("nr_migrate_fail", st.nr_migrate_fail);
	S("nr_protected", st.nr_protected);
	S("nr_overrun", st.nr_overrun);
	S("nr_rounds", st.nr_rounds);
	S("nr_level_colder", st.nr_level_colder);
	S("nr_level_hotter", st.nr_level_hotter);
	S("nr_monitor_stale", st.nr_monitor_stale);
	S("nr_hint_faults", atomic_long_read(&ftier_hint.nr_faults));
	S("nr_hint_migrate", atomic_long_read(&ftier_hint.nr_migrate));
	S("nr_hint_reject_tier", atomic_long_read(&ftier_hint.nr_reject_tier));
	S("nr_hint_reject_lat", atomic_long_read(&ftier_hint.nr_reject_lat));
	S("nr_hint_reject_rate", atomic_long_read(&ftier_hint.nr_reject_rate));
#undef S
	return len;
}
static struct kobj_attribute stats_attr = __ATTR_RO(stats);

/* Per-level occupancy of the Hotlist: "<level> <entries> <MB>". */
static ssize_t hotlist_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct ftier_hotlist *hl = &ftier_ctx.hotlist;
	unsigned int level, nr;
	int len = 0;

	mutex_lock(&ftier_lock);
	len += sysfs_emit_at(buf, len, "epoch %u entries %lu discarded %llu\n",
			     hl->epoch, hl->nr_entries, hl->nr_discarded);
	for (level = FTIER_HOT_LEVELS; level-- > 0; ) {
		nr = hl->nr[ftier_hotlist_pos(hl, level)];
		if (nr)
			len += sysfs_emit_at(buf, len, "%u %u %lu\n", level, nr,
					     (unsigned long)nr * (PMD_SIZE >> 20));
	}
	mutex_unlock(&ftier_lock);
	return len;
}
static struct kobj_attribute hotlist_attr = __ATTR_RO(hotlist);

static struct attribute *ftier_sysfs_attrs[] = {
	&ftier_status_attr.attr,
	&ftier_tiering_mode_attr.attr,
	&target_pid_attr.attr,
	&target_cgroup_attr.attr,
	&promote_mb_attr.attr,
	&hint_fault_latency_threshold_ms_attr.attr,
	&hf_pass_ratio_bp_attr.attr,
	&tick_ms_attr.attr,
	&interval_ms_attr.attr,
	&fscan_period_ms_attr.attr,
	&fspin_ms_attr.attr,
	&pud_idle_scans_attr.attr,
	&scans_per_interval_attr.attr,
	&init_period_us_attr.attr,
	&min_period_us_attr.attr,
	&max_period_us_attr.attr,
	&low_wm_attr.attr,
	&high_wm_pct_attr.attr,
	&min_pmds_per_fscan_attr.attr,
	&max_fhot_pc_attr.attr,
	&slack_us_attr.attr,
	&cool_ms_attr.attr,
	&nr_scanners_attr.attr,
	&track_thp_attr.attr,
	&notify_secondary_attr.attr,
	&flush_tlb_attr.attr,
	&migrate_batch_attr.attr,
	&max_migrate_mbps_attr.attr,
	&max_candidates_attr.attr,
	&hint_mode_attr.attr,
	&hint_min_ms_attr.attr,
	&hint_max_ms_attr.attr,
	&hint_pass_bp_attr.attr,
	&hint_thresh_ms_attr.attr,
	&level_adapt_attr.attr,
	&level_period_ms_attr.attr,
	&level_small_pct_attr.attr,
	&level_full_pct_attr.attr,
	&level_jump_pct_attr.attr,
	&level_progress_pct_attr.attr,
	&level_deadband_pm_attr.attr,
	&level_off_attr.attr,
	&tier_report_attr.attr,
	&monitor_timeout_ms_attr.attr,
	&dram_nodes_attr.attr,
	&cxl_nodes_attr.attr,
	&stats_attr.attr,
	&hotlist_attr.attr,
	NULL,
};

static const struct attribute_group ftier_sysfs_group = {
	.attrs = ftier_sysfs_attrs,
};

static int __init ftier_sysfs_init(void)
{
	struct kobject *ftier_kobj;
	int err;

	ftier_nodes_init();

	ftier_kobj = kobject_create_and_add("ftier", mm_kobj);
	if (!ftier_kobj)
		return -ENOMEM;

	err = sysfs_create_group(ftier_kobj, &ftier_sysfs_group);
	if (err) {
		pr_err("ftier: failed to register sysfs group\n");
		kobject_put(ftier_kobj);
	}
	return err;
}
/* After the memory tiers are set up. */
late_initcall(ftier_sysfs_init);
