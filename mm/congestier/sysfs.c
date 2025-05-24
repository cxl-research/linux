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

static ssize_t prom_mbps_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", (promote_pg_sec) / 256);
}

static ssize_t prom_mbps_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, mbps;

	err = kstrtoint(buf, 0, &mbps);
	if (err)
		return err;

	WRITE_ONCE(promote_pg_sec, mbps * 256);
	return count;
}

static struct kobj_attribute prom_mbps_attr = __ATTR_RW(prom_mbps);

#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS

int pgtemp_granularity_order = 9; /* 2MB by default */
int pebs_buf_pg_order = 0;
void *pebs_sample_buf = NULL;
static enum pg_temp_pebs_state pebs_hottrack_state = TRACK_HOTNESS_OFF;
int pebs_epoch_usecs = 1E6; /* 1 second by default */

static const char *pebs_hottrack_state_str[] = {
	[TRACK_HOTNESS_OFF] = "off",
	[TRACK_HOTNESS_ON] = "on",
};

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

static ssize_t pebs_epoch_usecs_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int usecs = READ_ONCE(pebs_epoch_usecs);
	return sysfs_emit(buf, "%d\n", usecs);
}

static ssize_t pebs_epoch_usecs_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int err, usecs;

	err = kstrtoint(buf, 0, &usecs);
	if (err)
		return err;

	if (usecs < 1000 || usecs > 1E8)
		return -EINVAL;

	WRITE_ONCE(pebs_epoch_usecs, usecs);
	return count;
}

static struct kobj_attribute pebs_epoch_usecs_attr =
	__ATTR_RW(pebs_epoch_usecs);

#endif /* CONFIG_CONGESTIER_PGTEMP_PEBS */

static struct attribute *congestier_sysfs_attrs[] = {
	&prom_mbps_attr.attr,
#ifdef CONFIG_CONGESTIER_PGTEMP_PEBS
	&pebs_buf_pg_order_attr.attr,
	&pgtemp_granularity_order_attr.attr,
	&pebs_hottrack_state_attr.attr,
	&pebs_epoch_usecs_attr.attr,
#endif
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