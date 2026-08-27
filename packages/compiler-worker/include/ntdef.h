/*
 * ntdef.h — base types shared by wdm/ntddk (teaching subset).
 * Mirrors the real WDK closely enough that WDK-flavored tutorial code compiles
 * unmodified; x64 Windows ABI (LLP64: long = 4 bytes, pointers = 8 bytes).
 */
#pragma once

#include <winapifamily.h>
#include <stdarg.h>
#include <stddef.h>   /* wchar_t in freestanding/microsoft mode */

/* --- compiler attributes / macros ---------------------------------------- */

#define IN
#define OUT
#define OPTIONAL
#define UNREFERENCED_PARAMETER(P) (void)(P)
#define RESTRICTED_POINTER
#define ALLOCATE_DESCRIPTION(x)

/* WDK source-annotation macros (no-ops here; real WDK carries metadata) */
#define _In_
#define _In_opt_
#define _Inout_
#define _Inout_opt_
#define _Out_
#define _Out_opt_
#define _Return_type_success_(x)
#define _Must_inspect_result_

#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]

/* --- SAL annotations --------------------------------------------------------
 * No-op spellings of the WDK source annotations so tutorial driver code
 * compiles unmodified (_In_ PDRIVER_OBJECT etc.). The real WDK expands these
 * to rich metadata; for teaching they vanish. */
#endif

#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - (unsigned long long)(&((type *)0)->field)))

#define RTL_NUMBER_OF(A) (sizeof(A) / sizeof((A)[0]))
#define ARRAYSIZE(A) RTL_NUMBER_OF(A)

#define MAXUSHORT   0xffff
#define MAXLONG     0x7fffffff
#define ULONG_MAX   0xffffffffull

/* --- calling conventions / linkage --------------------------------------- */

#define NTAPI
#define WINAPI
#define CALLBACK
#define CDECL
#define FASTCALL
#define NTINLINE inline
#define FORCEINLINE inline

/* kernel-export linkage: real WDK expands to __declspec(dllimport); the ntsim
 * linker resolves these by name, so the empty spelling keeps WDK-flavored
 * forward declarations (`NTKERNELAPI HANDLE NTAPI PsGetProcessId(...)`)
 * compiling verbatim (issue #13) */
#define NTKERNELAPI

/* --- fundamental types --------------------------------------------------- */

typedef char                CHAR;
typedef char                CCHAR;      /* kernel-internal char (KeSetTargetProcessorDpc) */
typedef short               SHORT;
typedef long                LONG;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;

typedef unsigned char       UCHAR;
typedef unsigned short      USHORT;
typedef unsigned int        UINT;
typedef unsigned long       ULONG;
typedef unsigned long long  ULONGLONG;
typedef long long           LONGLONG;
/* full-width spellings the WDK ships and tutorial code expects */
typedef unsigned long long  ULONG64;
typedef unsigned long long  UINT64;
typedef long long           LONG64;
typedef long long           INT64;

typedef wchar_t             WCHAR;

typedef void                VOID;
typedef int                 BOOL;
typedef unsigned char       BOOLEAN;
#define TRUE  1
#define FALSE 0

#define CONST const
#define STATIC static

typedef UCHAR              *PUCHAR;
typedef USHORT             *PUSHORT;
typedef ULONG              *PULONG;
typedef LONG               *PLONG;
typedef CHAR               *PCHAR;
typedef WCHAR              *PWCHAR;
typedef WCHAR              *PWSTR;   /* WDK: PWSTR is WCHAR*, alias of PWCHAR */
typedef BOOL               *PBOOL;
typedef BOOLEAN            *PBOOLEAN;
typedef VOID               *PVOID;
typedef const VOID         *PCVOID;

typedef LONGLONG            *PLONGLONG;
typedef ULONGLONG           *PULONGLONG;

typedef unsigned long       SIZE_T, *PSIZE_T;
typedef long                SSIZE_T, *PSSIZE_T;
typedef unsigned long long  ULONG_PTR, *PULONG_PTR;
typedef long long           LONG_PTR, *PLONG_PTR;
typedef unsigned long long  DWORD_PTR, *PDWORD_PTR;
typedef unsigned long long  UINT_PTR, *PUINT_PTR;

typedef ULONG               DWORD;
typedef unsigned int        WORD;
typedef unsigned char       BYTE;
typedef DWORD              *LPDWORD;
typedef WORD               *LPWORD;
typedef BYTE               *LPBYTE;
typedef char               *LPSTR;
typedef const char         *LPCSTR;
typedef WCHAR              *LPWSTR;
typedef const WCHAR        *LPCWSTR;
typedef char               *PSTR;
typedef const char         *PCSZ;

/* handle type is void* on win64 (needed early: OBJECT_ATTRIBUTES etc.) */
typedef void *HANDLE;
typedef HANDLE *PHANDLE;

/* --- status / result codes ------------------------------------------------ */

typedef LONG    NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)      ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)          ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)            ((((ULONG)(Status)) >> 30) == 3)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_INVALID_PARAMETER_1       ((NTSTATUS)0xC000000EL)
#define STATUS_NO_MEMORY                 ((NTSTATUS)0xC0000017L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND     ((NTSTATUS)0xC000003AL)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_SUPPORTED             ((NTSTATUS)0xC00000BBL)
#define STATUS_PENDING                   ((NTSTATUS)0x00000103L)
#define STATUS_INVALID_IMAGE_HASH        ((NTSTATUS)0xC0000221L)
#define STATUS_INVALID_BUFFER_SIZE       ((NTSTATUS)0xC0000206L)

/* --- basic structures ----------------------------------------------------- */

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        ULONG LowPart;
        ULONG HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

/* string types ------------------------------------------------------------ */

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, ANSI_STRING, OEM_STRING;
typedef STRING *PSTRING, *PANSI_STRING, *POEM_STRING;
typedef const STRING *PCSTRING;
typedef const ANSI_STRING *PCANSI_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define DECLARE_UNICODE_STRING(_var, _string) \
    static WCHAR _var##Buffer[] = _string; \
    UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), _var##Buffer }

#define RtlInitUnicodeString(s, buf) do { \
    (s)->Length = (USHORT)(sizeof(L"") ? wcslen_ksz(buf) * sizeof(WCHAR) : 0); \
    (s)->MaximumLength = (USHORT)((s)->Length + sizeof(WCHAR)); \
    (s)->Buffer = (buf); \
} while (0)

static __inline unsigned long long wcslen_ksz(const wchar_t *s) {
    unsigned long long n = 0;
    while (s && s[n]) n++;
    return n;
}

/* object attributes ------------------------------------------------------- */

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = (r); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* handle typedef moved earlier (before OBJECT_ATTRIBUTES) */

/* interlocked primitives (single-core emulated kernel: plain stores suffice,
 * but keep the WDK surface so textbook code links) ------------------------- */

static __inline LONG InterlockedExchange(volatile LONG *Target, LONG Value) {
    LONG old = *Target; *Target = Value; return old;
}
static __inline LONG InterlockedIncrement(volatile LONG *Addend) {
    return ++*Addend;
}
static __inline LONG InterlockedDecrement(volatile LONG *Addend) {
    return --*Addend;
}

/* Rtl memory helpers students expect from the WDK ------------------------- */

static __inline void *RtlCopyMemory(void *dst, const void *src, unsigned long long n) {
    unsigned char *d = dst; const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}
static __inline void *RtlFillMemory(void *dst, unsigned long long n, unsigned char v) {
    unsigned char *d = dst; while (n--) *d++ = v; return dst;
}
static __inline void *RtlZeroMemory(void *dst, unsigned long long n) {
    return RtlFillMemory(dst, n, 0);
}
#define RtlEqualMemory(a, b, n) (RtlCompareMemory(a, b, n) == (n))

static __inline unsigned long long RtlCompareMemory(const void *a, const void *b, unsigned long long n) {
    const unsigned char *x = a, *y = b;
    unsigned long long i = 0;
    while (i < n && x[i] == y[i]) i++;
    return i;
}

/* list operations (mirrors nt!LIST_ENTRY semantics) ----------------------- */

static __inline void InitializeListHead(PLIST_ENTRY head) {
    head->Flink = head->Blink = head;
}
static __inline int IsListEmpty(PLIST_ENTRY head) {
    return head->Flink == head;
}
static __inline void InsertTailList(PLIST_ENTRY head, PLIST_ENTRY entry) {
    entry->Flink = head;
    entry->Blink = head->Blink;
    head->Blink->Flink = entry;
    head->Blink = entry;
}
static __inline void InsertHeadList(PLIST_ENTRY head, PLIST_ENTRY entry) {
    entry->Flink = head->Flink;
    entry->Blink = head;
    head->Flink->Blink = entry;
    head->Flink = entry;
}
static __inline int RemoveEntryList(PLIST_ENTRY entry) {
    PLIST_ENTRY blink = entry->Blink;
    PLIST_ENTRY flink = entry->Flink;
    blink->Flink = flink;
    flink->Blink = blink;
    return blink == flink;
}
