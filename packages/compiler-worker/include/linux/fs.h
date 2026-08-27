#pragma once
#include <linux/types.h>
struct file;
struct inode;
struct file_operations {
    struct module *owner;
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter)(void);
    ssize_t (*write_iter)(void);
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
    long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
    int (*mmap)(struct file *, void *);
    int (*open)(struct inode *, struct file *);
    void (*flush)(void);
    int (*release)(struct inode *, struct file *);
    int (*fsync)(void);
    int (*poll)(void);
};
struct file {
    const struct file_operations *f_op;
    void *private_data;
    loff_t f_pos;
};
struct inode { int i_mode; };
int register_chrdev(unsigned int major, const char *name, const struct file_operations *fops);
int __register_chrdev(unsigned int major, unsigned int baseminor, unsigned int count, const char *name, const struct file_operations *fops);
void unregister_chrdev(unsigned int major, const char *name);
int nonseekable_open(struct inode *inode, struct file *filp);
