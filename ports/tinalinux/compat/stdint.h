/* compat/stdint.h — freestanding <stdint.h> for the Linux -nostdinc build.
 *
 * The ABI-FROZEN BBP core headers do `#include <stdint.h>`. The Linux kernel is
 * built -nostdinc, so this port-local shim satisfies that include. Two worlds:
 *
 *  - FREESTANDING TUs (osif.c, adapter.c, the core) never pull <linux/...>, so
 *    _LINUX_TYPES_H is undefined and we provide the fixed-width types from the
 *    compiler's own predefined builtins (available even under -nostdinc).
 *  - The GLUE TU (tina_bbp.c) includes <linux/...> first, which defines
 *    _LINUX_TYPES_H and ALL of int8_t..uint64_t + intptr_t/uintptr_t. We then
 *    defer entirely to the kernel's types — no redefinition, no clash.
 *
 * ports/tinalinux only; the core is never edited.
 */
#ifndef BBP_COMPAT_STDINT_H
#define BBP_COMPAT_STDINT_H
#ifndef _LINUX_TYPES_H   /* kernel already provides these when its types are in */
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
#endif /* _LINUX_TYPES_H */
#endif /* BBP_COMPAT_STDINT_H */
