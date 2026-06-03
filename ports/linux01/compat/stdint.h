/* compat/stdint.h — freestanding <stdint.h> for the linux-0.01 -nostdinc build.
 *
 * The ABI-FROZEN BBP core headers do `#include <stdint.h>`. linux-0.01 is built
 * -nostdinc -nostdlib, so this port-local shim satisfies that include. Two
 * worlds, like the tinalinux port:
 *
 *  - FREESTANDING TUs (osif.c, adapter.c, the core) provide the fixed-width
 *    types from the compiler's own predefined builtins (available even under
 *    -nostdinc). This is the linux-0.01 case: it has no <linux/types.h> with
 *    int8_t..uint64_t (the 1991 tree predates them).
 *  - If a future glue TU pulls a kernel header that defines these first, the
 *    _BBP_L01_HAVE_FIXED_TYPES guard below can be defined by that header's
 *    include path to defer — linux-0.01 has no such header today, so the
 *    builtins always win and there is no clash.
 *
 * IMPORTANT: linux-0.01 is a 32-bit i386 kernel. uintptr_t is therefore 32-bit
 * (__UINTPTR_TYPE__ resolves correctly under -m32), while uint64_t is 64-bit.
 * The BBP core stores all addresses as uint64_t (bbp_phys_t/bbp_virt_t); on a
 * 32-bit identity-mapped kernel a physical fits in 32 bits, so the
 * uint64_t->uintptr_t narrowing in phys_to_virt is value-preserving here.
 *
 * ports/linux01 only; the core is never edited.
 */
#ifndef BBP_COMPAT_STDINT_H
#define BBP_COMPAT_STDINT_H
#ifndef _BBP_L01_HAVE_FIXED_TYPES
typedef __INT8_TYPE__    int8_t;
typedef __INT16_TYPE__   int16_t;
typedef __INT32_TYPE__   int32_t;
typedef __INT64_TYPE__   int64_t;
typedef __UINT8_TYPE__   uint8_t;
typedef __UINT16_TYPE__  uint16_t;
typedef __UINT32_TYPE__  uint32_t;
typedef __UINT64_TYPE__  uint64_t;
typedef __INTPTR_TYPE__  intptr_t;
typedef __UINTPTR_TYPE__ uintptr_t;
#endif /* _BBP_L01_HAVE_FIXED_TYPES */
#endif /* BBP_COMPAT_STDINT_H */
