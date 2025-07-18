// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier sysfs Interface
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>
#include <linux/kobject.h>
#include <linux/miscdevice.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

long sysctl_promote_pg_epoch = 0;
int sysctl_epoch_usecs = 1000000; /* 1 second by default */
int sysctl_tiering_epoch_usecs = 1000000; /* 1 second by default */
int sysctl_stale_usecs = 5000000; /* 5 seconds by default */
enum tiering_mode sysctl_tiering_mode = TIERING_MODE_OFF;
int sysctl_max_tier_tmpcls = 62;
int sysctl_min_tier_tmpcls = 1;

EXPORT_SYMBOL_GPL(sysctl_promote_pg_epoch);
EXPORT_SYMBOL_GPL(sysctl_epoch_usecs);
EXPORT_SYMBOL_GPL(sysctl_tiering_epoch_usecs);

static const char *tiering_mode_str[] = {
	[TIERING_MODE_OFF] = "off",
	[TIERING_MODE_ON] = "on",
	[TIERING_ON_FALLBACK_NB] = "fallback",
};

static const char *tiering_interleave_modestr[] = {
	[TIM_HALF] = "half",
	[TIM_GSTEP] = "agestep",
};

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

int pgtemp_granularity_order = 9; /* 2MB by default */
int pebs_buf_pg_order = 0;
void *pebs_sample_buf = NULL;
static enum pg_temp_pebs_state pebs_hottrack_state = TRACK_HOTNESS_OFF;

static const char *pebs_hottrack_state_str[] = {
	[TRACK_HOTNESS_OFF] = "off",
	[TRACK_HOTNESS_ON] = "on",
};

#endif

static ssize_t max_tier_tmpcls_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_max_tier_tmpcls);
}

static ssize_t max_tier_tmpcls_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, tempclass;

	err = kstrtoint(buf, 0, &tempclass);
	if (err)
		return err;

	if (tempclass < 1 || tempclass >= NR_TEMPERATURE_CLASSES)
		return -EINVAL;

	sysctl_max_tier_tmpcls = tempclass;
	if (sysctl_min_tier_tmpcls > sysctl_max_tier_tmpcls)
		sysctl_min_tier_tmpcls = sysctl_max_tier_tmpcls;

	return count;
}

static struct kobj_attribute max_tier_tmpcls_attr =
		__ATTR_RW(max_tier_tmpcls);

static ssize_t min_tier_tmpcls_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_min_tier_tmpcls);
}

static ssize_t min_tier_tmpcls_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, tempclass;

	err = kstrtoint(buf, 0, &tempclass);
	if (err)
		return err;

	if (tempclass < 1 || tempclass >= NR_TEMPERATURE_CLASSES)
		return -EINVAL;

	sysctl_min_tier_tmpcls = tempclass;
	if (sysctl_min_tier_tmpcls > sysctl_max_tier_tmpcls)
		sysctl_max_tier_tmpcls = sysctl_min_tier_tmpcls;

	return count;
}

static struct kobj_attribute min_tier_tmpcls_attr =
		__ATTR_RW(min_tier_tmpcls);

static ssize_t tiering_epoch_msecs_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_tiering_epoch_usecs / 1000);
}

static ssize_t tiering_epoch_msecs_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, msecs;

	err = kstrtoint(buf, 0, &msecs);
	if (err)
		return err;

	if (msecs < 1 || msecs > 1E5) /* 5 seconds max */
		return -EINVAL;

	sysctl_tiering_epoch_usecs = msecs * 1000;
	return count;
}

static struct kobj_attribute tiering_epoch_msecs_attr =
		__ATTR_RW(tiering_epoch_msecs);

static ssize_t staleness_msecs_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", sysctl_stale_usecs / 1000);
}

static ssize_t staleness_msecs_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, msecs;

	err = kstrtoint(buf, 0, &msecs);
	if (err)
		return err;

	if (msecs < 1 || msecs > 1E5)
		return -EINVAL;

	sysctl_stale_usecs = msecs * 1000;
	return count;
}

static struct kobj_attribute staleness_msecs_attr =
		__ATTR_RW(staleness_msecs);

static ssize_t tiering_interleave_mode_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	enum tiering_interleave_mode mode = READ_ONCE(tiering_interleave_mode);
	int len = strlen(tiering_interleave_modestr[mode]);
	sysfs_emit(buf, "%s", tiering_interleave_modestr[mode]);
	return len;
}

static ssize_t tiering_interleave_mode_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	for (int i = 0; i < NR_TIERING_INTERLEAVE_MODES; i++) {
		if (sysfs_streq(buf, tiering_interleave_modestr[i])) {
			tiering_interleave_mode = i;
			return count;
		}
	}

	printk(KERN_ERR "Invalid tiering interleave mode: %s\n", buf);
	return -EINVAL;
}

static struct kobj_attribute tiering_interleave_mode_attr =
	__ATTR_RW(tiering_interleave_mode);

static ssize_t tiering_mode_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	enum tiering_mode mode = READ_ONCE(sysctl_tiering_mode);
	int len = strlen(tiering_mode_str[mode]);
	sysfs_emit(buf, "%s", tiering_mode_str[mode]);
	return len;
}

static ssize_t tiering_mode_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err;
	enum tiering_mode oldmode, newmode;

	oldmode = READ_ONCE(sysctl_tiering_mode);

	if (!strncmp(buf, "off", 3)) {
		newmode = TIERING_MODE_OFF;

		if (oldmode == TIERING_MODE_OFF)
			return 3;

		if ((err = tiering_stop()))
			return err;
		WRITE_ONCE(sysctl_tiering_mode, newmode);
	} else if (!strncmp(buf, "on", 2)) {
		newmode = TIERING_MODE_ON;

		if (oldmode == TIERING_MODE_ON)
			return 2;

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS
		/* PGTemp Tracking must be turned ON */
		if (pebs_hottrack_state != TRACK_HOTNESS_ON) {
			printk(KERN_ERR "PGTemp PEBS tracking must be ON to enable tiering\n");
			return -EPERM;
		}
#endif
		if ((err = tiering_start()))
			return err;
		WRITE_ONCE(sysctl_tiering_mode, newmode);
	} else if (!strncmp(buf, "reset", 5)) {
		if (oldmode != TIERING_MODE_OFF) {
			printk(KERN_ERR "Turn tiering_mode OFF before resetting.\n");
			return -EPERM;
		}
		reset_tiering_ctx();
	} else if (!strncmp(buf, "fallback", 8)) {
		newmode = TIERING_ON_FALLBACK_NB;

		if (oldmode == TIERING_ON_FALLBACK_NB)
			return 2;

		if (oldmode == TIERING_MODE_OFF) {
			if ((err = tiering_start()))
				return err;
		}

		WRITE_ONCE(sysctl_tiering_mode, newmode);
	} else {
		return -EINVAL;
	}

	return count;
}

static struct kobj_attribute tiering_mode_attr =
		__ATTR_RW(tiering_mode);

static ssize_t epoch_msecs_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int usecs = READ_ONCE(sysctl_epoch_usecs);
	return sysfs_emit(buf, "%d\n", usecs / 1000);
}

static ssize_t epoch_msecs_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, msecs;

	err = kstrtoint(buf, 0, &msecs);
	if (err)
		return err;

	if (msecs < 1 || msecs > 1E5)
		return -EINVAL;

	WRITE_ONCE(sysctl_epoch_usecs, msecs * 1000);
	return count;
}

static struct kobj_attribute epoch_msecs_attr =
	__ATTR_RW(epoch_msecs);

static ssize_t promote_mbps_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	long pages_per_sec = (1000000 * sysctl_promote_pg_epoch) / \
				(sysctl_tiering_epoch_usecs * 256);
	return sysfs_emit(buf, "%ld\n", pages_per_sec);
}

static ssize_t promote_mbps_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, mbps;
	long pages_per_sec;

	err = kstrtoint(buf, 0, &mbps);
	if (err)
		return err;

	pages_per_sec = 256 * (((long)mbps * sysctl_tiering_epoch_usecs) / 1000000);
	WRITE_ONCE(sysctl_promote_pg_epoch, pages_per_sec);
	return count;
}

static struct kobj_attribute promote_mbps_attr = __ATTR_RW(promote_mbps);

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

static ssize_t pgtemp_granularity_order_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int order = READ_ONCE(pgtemp_granularity_order);
	return sysfs_emit(buf, "%d\n", order);
}

static ssize_t pgtemp_granularity_order_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, neworder;

	err = kstrtoint(buf, 0, &neworder);
	if (err)
		return err;

	if (neworder < 0 || neworder > 15)
		return -EINVAL;

	WRITE_ONCE(pgtemp_granularity_order, neworder);

	return count;
}

static struct kobj_attribute pgtemp_granularity_order_attr =
	__ATTR_RW(pgtemp_granularity_order);

static ssize_t pebs_hottrack_state_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	enum pg_temp_pebs_state state = READ_ONCE(pebs_hottrack_state);
	int len = strlen(pebs_hottrack_state_str[state]);
	sysfs_emit(buf, "%s", pebs_hottrack_state_str[state]);
	return len;
}

static ssize_t pebs_hottrack_state_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err;
	enum pg_temp_pebs_state oldstate, newstate;

	oldstate = READ_ONCE(pebs_hottrack_state);

	if (!strncmp(buf, "off", 3)) {
		newstate = TRACK_HOTNESS_OFF;

		if (oldstate == TRACK_HOTNESS_OFF)
			return 3;

		WRITE_ONCE(pebs_hottrack_state, newstate);
		if ((err = pebs_tracking_stop()))
			return err;
	} else if (!strncmp(buf, "on", 2)) {
		newstate = TRACK_HOTNESS_ON;

		if (oldstate == TRACK_HOTNESS_ON)
			return 2;

		if (!pebs_sample_buf) {
			printk(KERN_ERR "pebs_sample_buf is NULL\n");
			return -ENODATA;
		}

		if (pebs_buf_pg_order < 1 || pebs_buf_pg_order > 15) {
			printk(KERN_ERR "pebs buffer order (%d) out of range (1-15)\n", 
					pebs_buf_pg_order);
			return -ERANGE;
		}

		WRITE_ONCE(pebs_hottrack_state, newstate);
		if((err = pebs_tracking_start()))
			return err;
	} else if (!strncmp(buf, "reset", 5)) {
		if (oldstate == TRACK_HOTNESS_ON) {
			printk(KERN_ERR "Turn pebs_hottrack_state OFF before resetting.\n");
			return -EPERM;
		}
		reset_pebs_tracking();
	} else {
		return -EINVAL;
	}

	return count;
}

static struct kobj_attribute pebs_hottrack_state_attr =
	__ATTR_RW(pebs_hottrack_state);

static int pebs_buf_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	int order = READ_ONCE(pebs_buf_pg_order);
	unsigned long sz = CONGESTIER_PEBS_BUFSZ(order);

	if (size != sz) {
		return -EINVAL;
	}

	return remap_vmalloc_range(vma, pebs_sample_buf, 0);
}

static const struct file_operations pebs_buf_fops = {
	.owner = THIS_MODULE,
	.mmap = pebs_buf_mmap,
	.llseek = noop_llseek,
};

static struct miscdevice pebs_buf_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "congestier_pebs_buffer",
	.fops = &pebs_buf_fops,
	.mode = 0600,
};

static void adjust_pebs_bufsz(int order)
{
	unsigned long sz = CONGESTIER_PEBS_BUFSZ(order);

	if (pebs_sample_buf) {
		vfree(pebs_sample_buf);
		pebs_sample_buf = NULL;
	}

	if (!sz)
		return;

	pebs_sample_buf = vmalloc_user(sz);
}

static ssize_t pebs_buf_pg_order_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", pebs_buf_pg_order);
}

static ssize_t pebs_buf_pg_order_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, neworder;

	err = kstrtoint(buf, 0, &neworder);
	if (err)
		return err;

	if (neworder < 0 || neworder > 15)
		return -EINVAL;

	adjust_pebs_bufsz(neworder);
	WRITE_ONCE(pebs_buf_pg_order, neworder);
	return count;
}

static struct kobj_attribute pebs_buf_pg_order_attr =
	__ATTR_RW(pebs_buf_pg_order);

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */

static struct attribute *congestier_sysfs_attrs[] = {
	&promote_mbps_attr.attr,
	&tiering_mode_attr.attr,
	&epoch_msecs_attr.attr,
	&tiering_interleave_mode_attr.attr,
	&tiering_epoch_msecs_attr.attr,
	&staleness_msecs_attr.attr,
#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS
	&pebs_buf_pg_order_attr.attr,
	&pgtemp_granularity_order_attr.attr,
	&pebs_hottrack_state_attr.attr,
#endif
	&max_tier_tmpcls_attr.attr,
	&min_tier_tmpcls_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(congestier_sysfs);

static const struct kobj_type congestier_sysfs_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = congestier_sysfs_groups,
};

static int __init congestier_sysfs_init(void)
{
	struct kobject *congestier_sysfs_kobj;
	int err;

	congestier_sysfs_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
	if (!congestier_sysfs_kobj)
		return -ENOMEM;

	err = kobject_init_and_add(congestier_sysfs_kobj, 
			&congestier_sysfs_ktype, mm_kobj, "congestier");
	if (err)
		goto out_kobj_put;

	err = misc_register(&pebs_buf_dev);
	if (err)
		goto out_kobj_put;

	return 0;

out_kobj_put:
	kobject_put(congestier_sysfs_kobj);
	return err;
}
subsys_initcall(congestier_sysfs_init);