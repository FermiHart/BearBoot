/*
 * osif.c — MINIX port of the Bear Boot Protocol OSIF (REAL implementation).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Wires the OS-independent BBP core to MINIX internals. This is a REAL port
 * (BBP_PORT_MINIX_REAL): every hook is implemented, none are stubs.
 *
 *   phys_to_virt : phys + HHDM offset. The offset is the SAME one MINIX
 *                  derives from Limine (limine_hhdm_offset, set in
 *                  limine_kinfo.c). The integration calls bbp_minix_set_hhdm()
 *                  with it once, early; see integration.md. This matches the
 *                  kernel's own direct map, so a pointer the parser translates
 *                  lands on exactly the bytes MINIX put there.
 *   log          : raw COM1 (0x3F8) polled output — identical register
 *                  sequence to limine_entry.c / limine_kinfo.c serial, so it
 *                  works before the MINIX tty driver exists and routes to the
 *                  same -serial console=tty00 the rest of boot uses.
 *   panic        : log + optional MINIX panic() hook, then halt. Never returns.
 *   alloc_pages  : hands out 8-byte-aligned chunks of a static arena. A static
 *                  arena is fine for v1 (the adapter needs <64 KiB once, before
 *                  the PMM exists). Integration may swap to the kernel PMM later.
 *   now_ns       : TSC-derived (rdtsc / assumed-MHz), good enough for boot
 *                  metrics; if the integration prefers no clock it can ignore it.
 *
 * Freestanding: no libc, no MINIX headers — so this same file compiles for
 * `make scaffold-check` against the frozen core AND links into the standalone
 * Limine test harness AND drops into the MINIX kernel build unchanged.
 */
#define BBP_PORT_MINIX_REAL 1

#include "osif.h"

/* ===================================================================== *
 *  Runtime HHDM offset + kernel slide (set once by integration / harness).
 *
 *  Two distinct virtual aliases exist for any physical page on a higher-half
 *  kernel, and conflating them is THE classic BBP bring-up bug:
 *
 *    1. KERNEL-IMAGE alias: where a kernel symbol (&minix_arena) resolves,
 *       i.e. kernel_virt_base + (load offset). phys = virt - virt_base + phys_base.
 *    2. HHDM alias: phys + hhdm_offset, used to dereference the (physical) tag
 *       pointers the builder emits, AFTER CR3 is the kernel's own.
 *
 *  So phys_to_virt() uses the HHDM (alias 2 — what the parser walks), while
 *  alloc_pages() must turn the arena's KERNEL-image address into a TRUE
 *  physical using the kernel slide (alias 1). The adapter then stores those
 *  true physicals in tags; the parser translates them back via the HHDM. */
static bbp_virt_t minix_hhdm_offset = 0;
static uint64_t   minix_kphys_base  = 0;   /* Limine kernel-address phys base */
static bbp_virt_t minix_kvirt_base  = 0;   /* Limine kernel-address virt base */
static int        minix_kslide_set  = 0;

bbp_virt_t bbp_minix_set_hhdm(bbp_virt_t hhdm_offset)
{
    minix_hhdm_offset = hhdm_offset;
    return minix_hhdm_offset;
}

bbp_virt_t bbp_minix_get_hhdm(void)
{
    return minix_hhdm_offset;
}

void bbp_minix_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base)
{
    minix_kphys_base = kphys_base;
    minix_kvirt_base = kvirt_base;
    minix_kslide_set = 1;
}

/* Translate a KERNEL-IMAGE virtual address (a kernel symbol such as the scratch
 * arena) to its TRUE physical via the kernel slide. Single source of truth for
 * the slide math used by both alloc_pages and the adapter. Identity fallback
 * (valid only while identity-mapped) when the slide was never set. */
uint64_t bbp_minix_virt_to_phys(uint64_t kimage_virt)
{
    if (minix_kslide_set)
        return kimage_virt - (uint64_t)minix_kvirt_base + minix_kphys_base;
    return kimage_virt;
}

/* ===================================================================== *
 *  phys_to_virt — MINIX higher-half direct map.
 * ===================================================================== */
static void *minix_phys_to_virt(uint64_t phys)
{
    if (phys == 0)
        return (void *)0;                  /* OSIF contract: NULL for phys 0 */
    return (void *)(uintptr_t)(phys + minix_hhdm_offset);
}

/* ===================================================================== *
 *  Serial COM1 (0x3F8) — polled, freestanding.
 * ===================================================================== */
static inline void osif_outb(unsigned short port, unsigned char val)
{
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline unsigned char osif_inb(unsigned short port)
{
    unsigned char r;
    __asm__ volatile("inb %1, %0" : "=a"(r) : "Nd"(port));
    return r;
}

static int serial_ready = 0;

static void serial_init_once(void)
{
    if (serial_ready)
        return;
    osif_outb(0x3F8 + 1, 0x00);   /* disable interrupts            */
    osif_outb(0x3F8 + 3, 0x80);   /* enable DLAB                   */
    osif_outb(0x3F8 + 0, 0x01);   /* divisor low  (115200 baud)    */
    osif_outb(0x3F8 + 1, 0x00);   /* divisor high                  */
    osif_outb(0x3F8 + 3, 0x03);   /* 8N1, DLAB off                 */
    osif_outb(0x3F8 + 2, 0xC7);   /* enable+clear FIFO, 14-byte    */
    osif_outb(0x3F8 + 4, 0x0B);   /* IRQs off, RTS/DSR set         */
    serial_ready = 1;
}

static void serial_putc(char c)
{
    while ((osif_inb(0x3F8 + 5) & 0x20) == 0)
        ;
    osif_outb(0x3F8, (unsigned char)c);
}

static void minix_log(const char *msg)
{
    serial_init_once();
    if (!msg)
        return;
    for (; *msg; msg++) {
        if (*msg == '\n')
            serial_putc('\r');
        serial_putc(*msg);
    }
}

/* ===================================================================== *
 *  panic — log, optionally call the MINIX kernel panic(), then halt.
 *
 *  ports/minix/ must not #include MINIX kernel headers (that would break the
 *  freestanding scaffold-check and the standalone harness). So the real MINIX
 *  panic() is reached through an OPTIONAL hook the integration installs with
 *  bbp_minix_set_panic_hook(). When no hook is set (harness, scaffold), panic
 *  logs and halts the CPU. Either way it never returns.
 * ===================================================================== */
static void (*minix_panic_hook)(const char *) = 0;

void bbp_minix_set_panic_hook(void (*hook)(const char *))
{
    minix_panic_hook = hook;
}

__attribute__((noreturn)) static void minix_panic(const char *msg)
{
    minix_log("\n[bbp] PANIC: ");
    minix_log(msg ? msg : "(null)");
    minix_log("\n");
    if (minix_panic_hook)
        minix_panic_hook(msg);             /* MINIX panic() if integration set it */
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* ===================================================================== *
 *  alloc_pages — static scratch arena (v1).
 *
 *  The adapter builds its tag list here. We keep the arena 4 KiB-aligned and
 *  page-multiple sized so a returned chunk + its physical alias are page-clean,
 *  and so alloc_pages's *out_phys (arena_virt - hhdm) is a valid physical
 *  address the parser can translate back. Bump allocator: this scratch is
 *  produced once at boot and never freed.
 * ===================================================================== */
#ifndef BBP_MINIX_ARENA_BYTES
#define BBP_MINIX_ARENA_BYTES (64u * 1024u)
#endif

static unsigned char minix_arena[BBP_MINIX_ARENA_BYTES]
    __attribute__((aligned(4096)));
static unsigned long minix_arena_used = 0;

void *bbp_minix_arena_base(unsigned long *out_size)
{
    if (out_size)
        *out_size = (unsigned long)sizeof(minix_arena);
    return minix_arena;
}

static void *minix_alloc_pages(size_t bytes, uint64_t *out_phys)
{
    /* 8-byte align like the BBP builder expects for tag pointers. */
    unsigned long start = (minix_arena_used + 7u) & ~7uL;
    if (start > sizeof(minix_arena) || bytes > sizeof(minix_arena) - start)
        return (void *)0;                  /* overflow: caller handles NULL */
    void *p = minix_arena + start;
    minix_arena_used = start + bytes;
    if (out_phys) {
        /* The arena is a kernel symbol: translate its KERNEL-image virtual to
         * a TRUE physical via the kernel slide (NOT hhdm — see the alias note
         * above), through the single-source-of-truth helper. */
        *out_phys = bbp_minix_virt_to_phys((uint64_t)(uintptr_t)p);
    }
    return p;
}

/* ===================================================================== *
 *  now_ns — TSC-derived monotonic nanoseconds (boot metrics).
 *
 *  We do not have a calibrated TSC frequency this early, so we assume a
 *  nominal 1 GHz (1 tick == 1 ns). This is an HONEST approximation used only
 *  for relative boot-phase deltas in BBP_TAG_METRICS, never for wall-clock.
 *  TECH DEBT: calibrate against the PIT/HPET once the timer subsystem is up,
 *  or expose the real cpu_hz from MINIX's tsc_per_ms — tracked in integration.md.
 * ===================================================================== */
static uint64_t minix_now_ns(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;      /* ~ns at the 1 GHz nominal assumption */
}

/* ===================================================================== *
 *  The OSIF vtable handed to the core.
 * ===================================================================== */
static const struct bbp_osif minix_osif = {
    .os_name      = "minix",
    .port_version = "0.1.0",
    .phys_to_virt = minix_phys_to_virt,
    .log          = minix_log,
    .panic        = minix_panic,
    .alloc_pages  = minix_alloc_pages,
    .now_ns       = minix_now_ns,
};

const struct bbp_osif *bbp_minix_osif(void) { return &minix_osif; }
