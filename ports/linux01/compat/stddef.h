/* compat/stddef.h — freestanding <stddef.h> for the linux-0.01 -nostdinc build.
 * size_t / NULL / offsetof via compiler builtins. ports/linux01 only; the BBP
 * core is never edited. linux-0.01's own include/stddef.h defines size_t and
 * offsetof too, but the BBP core TUs do not pull it, so this shim is what they
 * see under -nostdinc. */
#ifndef BBP_COMPAT_STDDEF_H
#define BBP_COMPAT_STDDEF_H
#ifndef _BBP_L01_HAVE_STDDEF
typedef __SIZE_TYPE__    size_t;
#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif
#endif /* _BBP_L01_HAVE_STDDEF */
#endif /* BBP_COMPAT_STDDEF_H */
