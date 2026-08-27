#pragma once
// Minimal linux/module.h for 6.6.18 emulation (browser LKM build)
#define __init
#define __exit
#define __user
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_VERSION(x)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
struct module;
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#define module_init(fn) int init_module(void) __attribute__((alias(#fn))); int (*__init_module_alias)(void) = fn
#define module_exit(fn) void cleanup_module(void) __attribute__((alias(#fn)))
int printk(const char *fmt, ...);
#define pr_info(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) printk(fmt, ##__VA_ARGS__)
