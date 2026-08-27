/*
 * ntddk.h -- the WDK kernel-mode driver header (teaching subset).
 *
 * Includes wdm.h (types + primitives) and declares the Zw/Ps/Mm/Io surface
 * ntsim implements. Signatures match the real WDK so tutorial code compiles
 * unmodified; semantics are ntsim's emulated kernel.
 */
#pragma once

#include <wdm.h>

/* --- process / thread (extended beyond wdm) --------------------------------- */

extern PEPROCESS PsInitialSystemProcess;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
    SystemProcessIdInformation = 0x50,
} SYSTEM_INFORMATION_CLASS;

/* ntsim-modeled handle entry (EX-style layout; see lesson m1.l2) */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    ULONG UniqueProcessId;
    ULONG HandleAttributes;
    ULONG GrantedAccess;
    USHORT HandleValue;
    USHORT CreatorBackTraceIndex;
    PVOID Object;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, unsigned int DesiredAccess,
                       POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS ZwWriteVirtualMemory(HANDLE ProcessHandle, void *BaseAddress,
                              const void *Buffer, unsigned long long NumberOfBytesToWrite,
                              unsigned long long *NumberOfBytesWritten);
NTSTATUS ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS ZwQuerySystemInformation(unsigned int SystemInformationClass,
                                  void *SystemInformation,
                                  unsigned long SystemInformationLength,
                                  ULONG *ReturnLength);

/* process access rights */
#define PROCESS_TERMINATE         0x0001
#define PROCESS_CREATE_THREAD     0x0002
#define PROCESS_VM_OPERATION      0x0008
#define PROCESS_VM_READ           0x0010
#define PROCESS_VM_WRITE          0x0020
#define PROCESS_DUP_HANDLE        0x0040
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_ALL_ACCESS        0x001F0FFF

/* --- memory management ------------------------------------------------------- */

NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess, const void *SourceAddress,
    PEPROCESS TargetProcess, void *TargetAddress,
    unsigned long long Size, KIRQL PreviousMode, unsigned long long *Returned);

void *MmGetSystemRoutineAddress(UNICODE_STRING *SystemRoutineName);
PVOID MmPageContiguousPlaceholder; /* removed below */

unsigned long long MmGetPhysicalAddressRaw(void *Va); /* ntsim helper */

#define PAGE_SIZE_KB 4

/* --- registry (subset used by driver-entry labs) ------------------------------ */

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyFullInformation = 2,
} KEY_INFORMATION_CLASS;

NTSTATUS ZwOpenKey(PHANDLE KeyHandle, unsigned int DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS ZwClose(HANDLE Handle);

#define KEY_READ  0x20019
#define KEY_WRITE 0x20006

/* --- driver support routines --------------------------------------------------- */

VOID IoCompleteRequestStub(void); /* removed below */

NTSTATUS ObReferenceObjectByNamePlaceholder(void);

/* KeServiceDescriptorTable-style export for SSDT labs (ntsim models this) */
extern void *KeServiceDescriptorTable;

/* --- Rtl string helpers (real signatures; implemented by ntsim) ------------------ */

VOID RtlInitUnicodeStringReal(PUNICODE_STRING DestinationString, const wchar_t *SourceString);

/* --- section/image APIs (manual-mapping labs) ------------------------------------ */

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

NTSTATUS ZwCreateSection(PHANDLE SectionHandle, unsigned int DesiredAccess,
                         POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
                         ULONG SectionPageProtection, ULONG AllocationAttributes,
                         HANDLE FileHandle);

#define SEC_COMMIT 0x8000000
#define SECTION_MAP_READ    0x0004
#define SECTION_MAP_WRITE   0x0002
#define SECTION_QUERY       0x0001

/* --- generic macros students expect ----------------------------------------------- */

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((unsigned long long)(&((type *)0)->field))
#endif
