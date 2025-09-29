// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier sysfs Interface
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>
#include <linux/mutex.h>

enum ftier_status sysctl_ftier_status = FTIER_STATUS_OFF;
enum ftier_tiering_mode sysctl_tiering_mode = DEMAND_MIGRATE;
int sysctl_fscan_period_ms = 10000; /* 10s */
int sysctl_fspin_ms = 5000; /* 5s */
int sysctl_min_pmds_per_fscan = 3;
int sysctl_max_fhot_pc = 60;
int sysctl_migrate_batch = 512;
int sysctl_hint_fault_latency_threshold_ms = 1000; /* 1s */
int sysctl_promote_mb = 0;
EXPORT_SYMBOL_GPL(sysctl_promote_mb);

static DEFINE_MUTEX(ftier_sysctl_lock);
static const char *ftier_status_strs[] = {
	[FTIER_STATUS_OFF] = "off",
	[FTIER_STATUS_TRACK] = "tracking",
	[FTIER_STATUS_TIER] = "tiering",
};
static const char *ftier_tiering_mode_strs[] = {
	[DEMAND_MIGRATE] = "demand_migrate",
	[HINT_FAULT] = "hint_fault",
};

static int update_ftier_status(enum ftier_status old_status,
		enum ftier_status new_status)
{
	int err = 0;

	switch (new_status) {
	case FTIER_STATUS_OFF:
		if (old_status == FTIER_STATUS_TIER)
			ftier_tiering_stop();
		err = ftier_temptrack_stop();
		break;

	case FTIER_STATUS_TRACK:
		if (old_status == FTIER_STATUS_TIER) {
			ftier_tiering_stop();
		} else {
			err = ftier_temptrack_start();
		}
		break;

	case FTIER_STATUS_TIER:
		if (old_status == FTIER_STATUS_OFF)
			err = ftier_temptrack_start();
		if (!err)
			ftier_tiering_start();
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

static ssize_t ftier_status_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	enum ftier_status status = sysctl_ftier_status;
	return sysfs_emit(buf, "%s\n", ftier_status_strs[status]);
}

static ssize_t ftier_status_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	enum ftier_status new_status, old_status;

	for (new_status = 0; new_status < NR_FTIER_STATUSES; new_status++) {
		if (sysfs_streq(buf, ftier_status_strs[new_status]))
			break;
	}

	if (new_status == NR_FTIER_STATUSES)
		return -EINVAL;

	old_status = sysctl_ftier_status;
	if (new_status == old_status)
		return count;

	mutex_lock(&ftier_sysctl_lock);
	if (update_ftier_status(old_status, new_status) == 0)
		sysctl_ftier_status = new_status;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute ftier_status_attr =
		__ATTR_RW(ftier_status);

static ssize_t ftier_tiering_mode_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	enum ftier_tiering_mode mode = sysctl_tiering_mode;
	return sysfs_emit(buf, "%s\n", ftier_tiering_mode_strs[mode]);
}

static ssize_t ftier_tiering_mode_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	enum ftier_tiering_mode new_mode;

	for (new_mode = 0; new_mode < NR_FTIER_TIERING_MODES; new_mode++) {
		if (sysfs_streq(buf, ftier_tiering_mode_strs[new_mode]))
			break;
	}

	if (new_mode == NR_FTIER_TIERING_MODES)
		return -EINVAL;

	if (new_mode == sysctl_tiering_mode)
		return count;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_tiering_mode = new_mode;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute ftier_tiering_mode_attr =
		__ATTR_RW(ftier_tiering_mode);

static ssize_t target_pid_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct ftier_target *target = get_target();
	pid_t pid = target->pid;

	if (pid < 0)
		return sysfs_emit(buf, "no target pid set\n");
	return sysfs_emit(buf, "pid:%d\n", pid);
}

static ssize_t target_pid_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	pid_t pid;
	int err;

	if (sysctl_ftier_status == FTIER_STATUS_OFF)
		return -EPERM;

	if (sysfs_streq(buf, "none")) {
		pid = -1;
	} else {
		err = kstrtoint(buf, 10, &pid);
		if (err || (pid < 0))
			return -EINVAL;
	}

	mutex_lock(&ftier_sysctl_lock);
	err = set_target_pid(pid);
	mutex_unlock(&ftier_sysctl_lock);

	return err ? err : count;
}

static struct kobj_attribute target_pid_attr =
		__ATTR_RW(target_pid);

static ssize_t target_cgroup_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct ftier_target *target = get_target();
	struct cgroup *cg = target->cg;
	char path[128];
	int len;

	if (!cg)
		return sysfs_emit(buf, "no target cgroup set\n");

	len = cgroup_path(cg, path, sizeof(path));
	if (len < 0)
		return len;

	return sysfs_emit(buf, "cgroup:%s\n", path);
}

static ssize_t target_cgroup_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char path[128];
	int err, len;

	if (sysctl_ftier_status == FTIER_STATUS_OFF)
		return -EPERM;

	len = count;
	if (count && (buf[count - 1] == '\n'))
		len--;

	memcpy(path, buf, len);
	path[len] = '\0';

	if (sysfs_streq(path, "none")) {
		mutex_lock(&ftier_sysctl_lock);
		err = set_target_cgroup(NULL);
		mutex_unlock(&ftier_sysctl_lock);
		return err ? err : count;
	}

	mutex_lock(&ftier_sysctl_lock);
	err = set_target_cgroup(path);
	mutex_unlock(&ftier_sysctl_lock);

	return err ? err : count;
}

static struct kobj_attribute target_cgroup_attr =
		__ATTR_RW(target_cgroup);

static ssize_t fscan_period_ms_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_fscan_period_ms);
}

static ssize_t fscan_period_ms_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int period, err;

	err = kstrtoint(buf, 10, &period);
	if (err || period < 1000 || period > 300000) /* 1s - 5min */
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_fscan_period_ms = period;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute fscan_period_ms_attr =
		__ATTR_RW(fscan_period_ms);

static ssize_t fspin_ms_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_fspin_ms);
}

static ssize_t fspin_ms_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int period, err;

	err = kstrtoint(buf, 10, &period);
	if (err || period < 1000 || period > 60000) /* 1s - 1min */
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_fspin_ms = period;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute fspin_ms_attr =
		__ATTR_RW(fspin_ms);

static ssize_t min_pmds_per_fscan_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_min_pmds_per_fscan);
}

static ssize_t min_pmds_per_fscan_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val, err;

	err = kstrtoint(buf, 10, &val);
	if (err || val < 1 || val > 100)
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_min_pmds_per_fscan = val;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute min_pmds_per_fscan_attr =
		__ATTR_RW(min_pmds_per_fscan);

static ssize_t max_fhot_pc_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_max_fhot_pc);
}

static ssize_t max_fhot_pc_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val, err;

	err = kstrtoint(buf, 10, &val);
	if (err || val < 1 || val > 100)
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_max_fhot_pc = val;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute max_fhot_pc_attr =
		__ATTR_RW(max_fhot_pc);

static ssize_t migrate_batch_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_migrate_batch);
}

static ssize_t migrate_batch_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val, err;

	err = kstrtoint(buf, 10, &val);
	if (err || val < 1 || val > 512)
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_migrate_batch = val;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute migrate_batch_attr =
		__ATTR_RW(migrate_batch);

static ssize_t hint_fault_latency_threshold_ms_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_hint_fault_latency_threshold_ms);
}

static ssize_t hint_fault_latency_threshold_ms_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val, err;

	err = kstrtoint(buf, 10, &val);
	if (err || val < 1 || val > 60000) /* 1ms - 1min */
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_hint_fault_latency_threshold_ms = val;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute hint_fault_latency_threshold_ms_attr =
		__ATTR_RW(hint_fault_latency_threshold_ms);

static ssize_t promote_mb_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_promote_mb);
}

static ssize_t promote_mb_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val, err;

	err = kstrtoint(buf, 10, &val);
	if (err || val > 102400 || val < -102400) /* max 100GB */
		return -EINVAL;

	mutex_lock(&ftier_sysctl_lock);
	sysctl_promote_mb = val;
	mutex_unlock(&ftier_sysctl_lock);

	return count;
}

static struct kobj_attribute promote_mb_attr =
		__ATTR_RW(promote_mb);

static struct attribute *ftier_sysfs_attrs[] = {
	&ftier_status_attr.attr,
	&ftier_tiering_mode_attr.attr,
	&target_pid_attr.attr,
	&target_cgroup_attr.attr,
	&fscan_period_ms_attr.attr,
	&fspin_ms_attr.attr,
	&min_pmds_per_fscan_attr.attr,
	&max_fhot_pc_attr.attr,
	&migrate_batch_attr.attr,
	&hint_fault_latency_threshold_ms_attr.attr,
	&promote_mb_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ftier_sysfs);

static const struct kobj_type ftier_sysfs_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = ftier_sysfs_groups,
};

static int __init ftier_sysfs_init(void)
{
	struct kobject *ftier_kobj;
	int err = 0;

	ftier_kobj = kobject_create_and_add("ftier", mm_kobj);
	if (!ftier_kobj)
		return -ENOMEM;

	err = sysfs_create_group(ftier_kobj, &ftier_sysfs_group);
	if (err) {
		pr_err("failed to register ftier group\n");
		kobject_put(ftier_kobj);
	}

	return err;
}

subsys_initcall(ftier_sysfs_init);
