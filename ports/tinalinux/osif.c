/*
 * osif.c — TinaLinux port of the Bear Boot Protocol OSIF (NATIVE).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Wires the OS-independent BBP core to TinaLinux (Linux 6.12 derivative). This
 * file is FREESTANDING (no <linux/...> headers) so it compiles for `make scaffold-check`
 * and the standalone harness AND drops into the kernel build unchanged.
 *
 * The five OSIF primitives delegate to weak hooks (bbp_tina_hook_*). With no
 * override (harness / scaffold) they use freestanding fallbacks: COM1 serial,
 * cli;hlt, a static arena, rdtsc. Inside the real kernel the glue TU
 * (tina_bbp.c) provides STRONG hooks bound to printk / panic / __get_free_pages
 * / ktime_get_ns — the link picks those. phys_to_virt is pure arithmetic over a
 * runtime HHDM offset (Linux page_offset_base), identical to __va().
 */
#define BBP_PORT_TINALINUX_REAL 1

#include "osif.h"

/* ===================================================================== *
 *  Runtime HHDM offset + kernel slide.
 *
 *  On Linux there is ONE linear map for physical RAM: the direct map at
 *  page_offset_base, i.e. __va(phys) == phys + page_offset_base. The glue sets
 *  hhdm_offset = page_offset_base. Because the adapter's scratch arena lives in
 *  THAT direct map (glue uses __get_free_pages), arena_phys == __pa(arena) and
 *  phys_to_virt == __va are the same map — the MINIX dual-alias hazard is
 *  structurally absent. The kernel slide (phys_base / _text) is recorded only
 *  to populate the KERNEL_ADDRESS tag.
 * ===================================================================== */
static bbp_virt_t tina_hhdm_offset = 0;
static uint64_t   tina_kphys_base  = 0;
static bbp_virt_t tina_kvirt_base  = 0;
static int        tina_kslide_set  = 0;

bbp_virt_t bbp_tina_set_hhdm(bbp_virt_t hhdm_offset)
{
    tina_hhdm_offset = hhdm_offset;
    return tina_hhdm_offset;
}

bbp_virt_t bbp_tina_get_hhdm(void) { return tina_hhdm_offset; }

void bbp_tina_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base)
{
    tina_kphys_base = kphys_base;
    tina_kvirt_base = kvirt_base;
    tina_kslide_set = 1;
}

/* Direct-map virtual -> physical: phys = virt - hhdm_offset (== __pa for a
 * direct-map pointer). The kernel-image slide is a different relation and is
 * NOT used for arena physicals here — the arena is always direct-mapped. */
uint64_t bbp_tina_virt_to_phys(uint64_t kvirt)
{
    return kvirt - (uint64_t)tina_hhdm_offset;
}

/* ===================================================================== *
 *  phys_to_virt — Linux direct map (== __va).
 * ===================================================================== */
static void *tina_phys_to_virt(uint64_t phys)
{
    if (phys == 0)
        return (void *)0;                 /* OSIF contract: NULL for phys 0 */
    return (void *)(uintptr_t)(phys + tina_hhdm_offset);
}

/* ===================================================================== *
 *  WEAK hooks — freestanding fallbacks. The kernel glue overrides each with a
 *  strong symbol bound to a real Linux API.
 * ===================================================================== */

/* --- serial COM1 fallback (only used when the glue does not override log) -- */
static inline void osif_outb(unsigned short port, unsigned char val)
{ __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port)); }
static inline unsigned char osif_inb(unsigned short port)
{ unsigned char r; __asm__ volatile("inb %1, %0" : "=a"(r) : "Nd"(port)); return r; }

static int tina_serial_ready = 0;
static void tina_serial_init_once(void)
{
    if (tina_serial_ready) return;
    osif_outb(0x3F8 + 1, 0x00); osif_outb(0x3F8 + 3, 0x80);
    osif_outb(0x3F8 + 0, 0x01); osif_outb(0x3F8 + 1, 0x00);
    osif_outb(0x3F8 + 3, 0x03); osif_outb(0x3F8 + 2, 0xC7);
    osif_outb(0x3F8 + 4, 0x0B); tina_serial_ready = 1;
}
static void tina_serial_putc(char c)
{
    while ((osif_inb(0x3F8 + 5) & 0x20) == 0) ;
    osif_outb(0x3F8, (unsigned char)c);
}

__attribute__((weak)) void bbp_tina_hook_log(const char *msg)
{
    tina_serial_init_once();
    if (!msg) return;
    for (; *msg; msg++) {
        if (*msg == '\n') tina_serial_putc('\r');
        tina_serial_putc(*msg);
    }
}

__attribute__((weak, noreturn)) void bbp_tina_hook_panic(const char *msg)
{
    bbp_tina_hook_log("\n[bbp] PANIC: ");
    bbp_tina_hook_log(msg ? msg : "(null)");
    bbp_tina_hook_log("\n");
    for (;;) __asm__ volatile("cli; hlt");
}

/* --- static arena fallback (harness / scaffold only) ---------------------- */
#ifndef BBP_TINA_ARENA_BYTES
#define BBP_TINA_ARENA_BYTES (64u * 1024u)
#endif
static unsigned char tina_arena[BBP_TINA_ARENA_BYTES] __attribute__((aligned(4096)));
static unsigned long tina_arena_used = 0;

__attribute__((weak)) void *bbp_tina_arena_base(unsigned long *out_size)
{
    if (out_size) *out_size = (unsigned long)sizeof(tina_arena);
    return tina_arena;
}

__attribute__((weak)) void *bbp_tina_hook_alloc(size_t bytes, uint64_t *out_phys)
{
    unsigned long start = (tina_arena_used + 7u) & ~7uL;
    if (start > sizeof(tina_arena) || bytes > sizeof(tina_arena) - start)
        return (void *)0;
    void *p = tina_arena + start;
    tina_arena_used = start + bytes;
    if (out_phys) *out_phys = bbp_tina_virt_to_phys((uint64_t)(uintptr_t)p);
    return p;
}

__attribute__((weak)) uint64_t bbp_tina_hook_now_ns(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;   /* nominal 1 GHz; honest approx */
}

/* ===================================================================== *
 *  OSIF vtable — primitives delegate to the (possibly overridden) hooks.
 * ===================================================================== */
static void  tina_log(const char *m)               { bbp_tina_hook_log(m); }
__attribute__((noreturn)) static void tina_panic(const char *m) { bbp_tina_hook_panic(m); }
static void *tina_alloc(size_t n, uint64_t *phys)   { return bbp_tina_hook_alloc(n, phys); }
static uint64_t tina_now_ns(void)                   { return bbp_tina_hook_now_ns(); }

static const struct bbp_osif tina_osif = {
    .os_name      = "tinalinux",
    .port_version = "1.0.0",
    .phys_to_virt = tina_phys_to_virt,
    .log          = tina_log,
    .panic        = tina_panic,
    .alloc_pages  = tina_alloc,
    .now_ns       = tina_now_ns,
};

const struct bbp_osif *bbp_tina_osif(void) { return &tina_osif; }
