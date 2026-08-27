/*
 * winapifamily.h — permissive stub.
 * The real WDK guards every declaration on WINAPI_FAMILY; student drivers
 * never care, so we define the "desktop" family unconditionally.
 */
#pragma once

#define WINAPI_FAMILY_DESKTOP_APP 100
#define WINAPI_FAMILY PCWINAPI_FAMILY_DESKTOP_APP
#ifndef WINAPI_FAMILY
#define WINAPI_FAMILY WINAPI_FAMILY_DESKTOP_APP
#endif
#define WINAPI_PARTITION_DESKTOP 1
