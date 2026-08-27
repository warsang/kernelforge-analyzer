#pragma once
#include <linux/types.h>
#define GFP_KERNEL 0
void *kmalloc(size_t size, int flags);
void *kzalloc(size_t size, int flags);
void *__kmalloc(size_t size, int flags);
void kfree(const void *ptr);
void *vmalloc(unsigned long size);
void vfree(const void *addr);
