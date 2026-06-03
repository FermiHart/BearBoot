/* compat/stddef.h — freestanding <stddef.h> for the Linux -nostdinc build.
 * size_t / NULL / offsetof via compiler builtins. Defers to the kernel's
 * linux/stddef.h when present (glue TU). ports/tinalinux only. */
#ifndef BBP_COMPAT_STDDEF_H
#define BBP_COMPAT_STDDEF_H
#ifndef _LINUX_STDDEF_H
typedef __SIZE_TYPE__    size_t;
#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif
#endif /* _LINUX_STDDEF_H */
#endif /* BBP_COMPAT_STDDEF_H */
