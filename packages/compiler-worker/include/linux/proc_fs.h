#pragma once
#include <linux/fs.h>
struct proc_dir_entry;
struct proc_ops {
    unsigned int proc_flags;
    int (*proc_open)(void);
    ssize_t (*proc_read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*proc_write)(struct file *, const char __user *, size_t, loff_t *);
    loff_t (*proc_lseek)(void);
    int (*proc_release)(void);
};
struct proc_dir_entry *proc_create(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops);
struct proc_dir_entry *proc_create_data(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct proc_ops *proc_ops, void *data);
void remove_proc_entry(const char *name, struct proc_dir_entry *parent);
void proc_remove(struct proc_dir_entry *entry);
