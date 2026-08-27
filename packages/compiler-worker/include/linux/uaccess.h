#pragma once
#include <linux/types.h>
#define __user
static inline int access_ok(const void __user *addr, unsigned long size) { (void)addr; (void)size; return 1; }
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n);
int get_user(unsigned long *val, const void __user *from);
int put_user(unsigned long val, void __user *to);
