#pragma once
#include <linux/fs.h>
#include <linux/types.h>
typedef unsigned int dev_t;
struct cdev { void *ops; };
void cdev_init(struct cdev *cdev, const struct file_operations *fops);
int cdev_add(struct cdev *p, dev_t dev, unsigned count);
void cdev_del(struct cdev *p);
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count, const char *name);
void unregister_chrdev_region(dev_t from, unsigned count);
dev_t MKDEV(unsigned major, unsigned minor);
