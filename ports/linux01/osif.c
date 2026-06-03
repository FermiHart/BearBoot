/*
 * osif.c — linux-0.01 port of the Bear Boot Protocol OSIF (NATIVE).
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Wires the OS-independent BBP core to Linus' linux-0.01 (i386). This file is
 * FREESTANDING (no kernel headers) so it compiles for `make scaffold-check`
 * and the standalone harness AND drops into the kernel build unchanged.
 *
 * The OSIF primitives delegate to weak hooks (bbp_l01_hook_*). With no override
 * (harness / scaffold) they use freestanding fallbacks: COM1 serial, cli;hlt, a
 * static arena, rdtsc. Inside the real kernel the glue TU (linux01_bbp.c)
 * provides STRONG hooks bound to printk / panic — the link picks those.
 *
 * phys_to_virt is pure arithmetic over a runtime HHDM offset. On linux-0.01
 * that offset is 0: pg_dir at physical 0 identity-maps the first 8 MiB
 * (mm/memory.c), so virt == phys and phys_to_virt is the identity.
 */
#define BBP_PORT_LINUX01_REAL 1

#include "osif.h"

/* ===================================================================== *
 *  Runtime HHDM offset + kernel slide.
 *
 *  linux-0.01 runs IDENTITY-mapped: pg_dir = 0 maps the first 8 MiB with
 *  virt == phys. So hhdm_offset is 0 and phys_to_virt is the identity. The
 *  scratch arena is a static buffer that therefore has arena_phys ==
 *  arena_virt — a single alias, so the classic MINIX kernel-image-vs-HHDM
 *  arena hazard cannot occur. The kernel slide (phys_base / virt_base) is
 *  recorded only to populate the KERNEL_ADDRESS tag; on linux-0.01 it is 0/0
 *  (the kernel is linked AND loaded at physical 0).
 * ===================================================================== */
static bbp_virt_t l01_hhdm_offset = 0;
static uint64_t   l01_kphys_base  = 0;
static bbp_virt_t l01_kvirt_base  = 0;
static int        l01_kslide_set  = 0;

bbp_virt_t bbp_l01_set_hhdm(bbp_virt_t hhdm_offset)
{
    l01_hhdm_offset = hhdm_offset;
    return l01_hhdm_offset;
}

bbp_virt_t bbp_l01_get_hhdm(void) { return l01_hhdm_offset; }

void bbp_l01_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base)
{
    l01_kphys_base = kphys_base;
    l01_kvirt_base = kvirt_base;
    l01_kslide_set = 1;
}

/* Direct-map virtual -> physical: phys = virt - hhdm_offset. With HHDM 0 this
 * is the identity (the linux-0.01 case). */
uint64_t bbp_l01_virt_to_phys(uint64_t kvirt)
{
    return kvirt - (uint64_t)l01_hhdm_offset;
}

/* ===================================================================== *
 *  phys_to_virt — identity map (HHDM offset 0 on linux-0.01).
 * ===================================================================== */
static void *l01_phys_to_virt(uint64_t phys)
{
    if (phys == 0)
        return (void *)0;                 /* OSIF contract: NULL for phys 0 */
    return (void *)(uintptr_t)(phys + l01_hhdm_offset);
}

/* ===================================================================== *
 *  WEAK hooks — freestanding fallbacks. The kernel glue overrides log/panic
 *  with strong symbols bound to printk / panic.
 * ===================================================================== */

/* --- serial COM1 fallback (only used when the glue does not override log) -- */
static inline void osif_outb(unsigned short port, unsigned char val)
{ __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port)); }
static inline unsigned char osif_inb(unsigned short port)
{ unsigned char r; __asm__ volatile("inb %1, %0" : "=a"(r) : "Nd"(port)); return r; }

static int l01_serial_ready = 0;
static void l01_serial_init_once(void)
{
    if (l01_serial_ready) return;
    osif_outb(0x3F8 + 1, 0x00); osif_outb(0x3F8 + 3, 0x80);
    osif_outb(0x3F8 + 0, 0x01); osif_outb(0x3F8 + 1, 0x00);
    osif_outb(0x3F8 + 3, 0x03); osif_outb(0x3F8 + 2, 0xC7);
    osif_outb(0x3F8 + 4, 0x0B); l01_serial_ready = 1;
}
static void l01_serial_putc(char c)
{
    while ((osif_inb(0x3F8 + 5) & 0x20) == 0) ;
    osif_outb(0x3F8, (unsigned char)c);
}

__attribute__((weak)) void bbp_l01_hook_log(const char *msg)
{
    l01_serial_init_once();
    if (!msg) return;
    for (; *msg; msg++) {
        if (*msg == '\n') l01_serial_putc('\r');
        l01_serial_putc(*msg);
    }
}

__attribute__((weak, noreturn)) void bbp_l01_hook_panic(const char *msg)
{
    bbp_l01_hook_log("\n[bbp] PANIC: ");
    bbp_l01_hook_log(msg ? msg : "(null)");
    bbp_l01_hook_log("\n");
    for (;;) __asm__ volatile("cli; hlt");
}

/* --- static arena fallback (harness / scaffold / kernel v1) --------------- *
 * linux-0.01 has no general page allocator usable at the call site, so the
 * port uses a static arena. The kernel is identity-mapped there, so this is
 * coherent (arena_phys == arena_virt). TECH DEBT: switch to get_free_page()
 * once a consumer needs a larger tag set than this 64 KiB buffer holds. */
#ifndef BBP_L01_ARENA_BYTES
#define BBP_L01_ARENA_BYTES (64u * 1024u)
#endif
static unsigned char l01_arena[BBP_L01_ARENA_BYTES] __attribute__((aligned(4096)));
static unsigned long l01_arena_used = 0;

__attribute__((weak)) void *bbp_l01_arena_base(unsigned long *out_size)
{
    if (out_size) *out_size = (unsigned long)sizeof(l01_arena);
    return l01_arena;
}

__attribute__((weak)) void *bbp_l01_hook_alloc(size_t bytes, uint64_t *out_phys)
{
    unsigned long start = (l01_arena_used + 7u) & ~7uL;
    if (start > sizeof(l01_arena) || bytes > sizeof(l01_arena) - start)
        return (void *)0;
    void *p = l01_arena + start;
    l01_arena_used = start + bytes;
    if (out_phys) *out_phys = bbp_l01_virt_to_phys((uint64_t)(uintptr_t)p);
    return p;
}

__attribute__((weak)) uint64_t bbp_l01_hook_now_ns(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;   /* nominal 1 GHz; honest approx */
}

/* ===================================================================== *
 *  OSIF vtable — primitives delegate to the (possibly overridden) hooks.
 * ===================================================================== */
static void  l01_log(const char *m)               { bbp_l01_hook_log(m); }
__attribute__((noreturn)) static void l01_panic(const char *m) { bbp_l01_hook_panic(m); }
static void *l01_alloc(size_t n, uint64_t *phys)   { return bbp_l01_hook_alloc(n, phys); }
static uint64_t l01_now_ns(void)                   { return bbp_l01_hook_now_ns(); }

static const struct bbp_osif l01_osif = {
    .os_name      = "linux-0.01",
    .port_version = "1.0.0",
    .phys_to_virt = l01_phys_to_virt,
    .log          = l01_log,
    .panic        = l01_panic,
    .alloc_pages  = l01_alloc,
    .now_ns       = l01_now_ns,
};

const struct bbp_osif *bbp_l01_osif(void) { return &l01_osif; }
