/*
 * ntstatus.h — NTSTATUS code values (subset students hit in labs).
 * Included by ntdef.h for convenience; can also be included directly.
 */
#pragma once

#include <ntdef.h>

#ifndef STATUS_SUCCESS_DEFINED
#define STATUS_SUCCESS_DEFINED
/* Values live in ntdef.h to avoid duplicate definitions; this header exists
 * so `#include <ntstatus.h>` in textbook code resolves. */
#endif

#define STATUS_ABANDONED_WAIT_0         ((NTSTATUS)0x00000080L)
#define STATUS_USER_APC                 ((NTSTATUS)0x000000C0L)
#define STATUS_TIMEOUT                  ((NTSTATUS)0x00000102L)
#define STATUS_IO_TIMEOUT               ((NTSTATUS)0xC00000B5L)
#define STATUS_CANCELLED                ((NTSTATUS)0xC0000120L)
#define STATUS_SHARING_VIOLATION        ((NTSTATUS)0xC0000043L)
#define STATUS_DEVICE_DOES_NOT_EXIST    ((NTSTATUS)0xC0000090L)
#define STATUS_DRIVER_ENTRYPOINT_NOT_FOUND ((NTSTATUS)0xC0000263L)
