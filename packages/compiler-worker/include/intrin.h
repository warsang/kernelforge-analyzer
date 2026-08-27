/*
 * intrin.h — compiler-intrinsics shim (teaching subset).
 *
 * The clang resource dir ships a real <intrin.h> that declares __readcr0,
 * __writecr0, _disable, _enable ... as raw-encoding intrinsics. ntsim's
 * JS interpreter cannot decode MOV CRx / CLI / STI encodings, and the
 * function-like macros in <wdm.h> clash with those declarations depending
 * on inclusion order (issue #21). This shim shadows the platform header in
 * our include dir and simply defers to wdm.h's #undef-guarded modeled-thunk
 * macros, so either inclusion order compiles to the same traced calls.
 */
#pragma once

#include <ntdef.h>
#include <wdm.h>

/*
 * Anything else student code commonly pulls from <intrin.h>:
 * ByteSwap / BitScan-style helpers are provided as inline functions so
 * WDK-flavored snippets keep compiling without the platform header.
 */
static __inline unsigned short _byteswap_ushort(unsigned short v) {
    return (unsigned short)((v << 8) | (v >> 8));
}
static __inline unsigned long _byteswap_ulong(unsigned long v) {
    return ((v & 0x000000fful) << 24) | ((v & 0x0000ff00ul) << 8) |
           ((v & 0x00ff0000ul) >> 8) | ((v & 0xff000000ul) >> 24);
}
static __inline unsigned long long _byteswap_uint64(unsigned long long v) {
    unsigned long long r = 0;
    for (int i = 0; i < 8; i++) r = (r << 8) | ((v >> (i * 8)) & 0xffull);
    return r;
}
