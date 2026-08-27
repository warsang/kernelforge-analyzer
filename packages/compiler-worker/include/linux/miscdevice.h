#pragma once
#include <linux/fs.h>
struct miscdevice {
    int minor;
    const char *name;
    const struct file_operations *fops;
};
int misc_register(struct miscdevice *misc);
int misc_deregister(struct miscdevice *misc);
#define MISC_DYNAMIC_MINOR 255
