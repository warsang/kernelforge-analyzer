#pragma once
struct class;
struct device;
struct class *class_create(struct module *owner, const char *name);
struct device *device_create(struct class *cls, struct device *parent, unsigned int devt, void *drvdata, const char *fmt, ...);
void class_destroy(struct class *cls);
void device_destroy(struct class *cls, unsigned int devt);
