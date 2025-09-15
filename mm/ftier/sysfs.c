// SPDX-License-Identifier: GPL-2.0

/*
 * Ftier sysfs Interface
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/ftier.h>
#include <linux/mutex.h>

enum ftier_status sysctl_ftier_status = FTIER_STATUS_OFF;
unsigned int sysctl_fscan_period_ms = 10000; /* 10s */
static DEFINE_MUTEX(ftier_sysctl_lock);

static const char *ftier_status_strs[] = {
	[FTIER_STATUS_OFF] = "off",
	[FTIER_STATUS_TRACK] = "tracking",
	[FTIER_STATUS_TIER] = "tiering",
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

static ssize_t ftier_target_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct ftier_target *target = get_target();
	pid_t pid = target->pid;

	if (pid < 0)
		return sysfs_emit(buf, "no target\n");
	return sysfs_emit(buf, "pid:%d\n", pid);
}

static ssize_t ftier_target_store(struct kobject *kobj,
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

	if (err)
		return err;

	return count;
}

static struct kobj_attribute ftier_target_attr =
		__ATTR_RW(ftier_target);

static ssize_t fscan_period_ms_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", sysctl_fscan_period_ms);
}

static ssize_t fscan_period_ms_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int period;
	int err;

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

static struct attribute *ftier_sysfs_attrs[] = {
	&ftier_status_attr.attr,
	&ftier_target_attr.attr,
	&fscan_period_ms_attr.attr,
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