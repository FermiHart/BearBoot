/*
 * osif.c — Josh-Bear port of the Bear Boot Protocol OSIF (REAL implementation).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Wires the OS-independent BBP core to Josh-Bear ("lisabeth") internals. Every
 * hook is real; none are stubs. Unlike ports/minix/ (a microkernel adapter that
 * runs before any allocator exists, hence a static arena + kernel-slide math),
 * Josh runs the adapter AFTER vmm/pmm/heap are up, so this port is direct:
 *
 *   phys_to_virt : phys + g_hhdm_offset. Josh's single higher-half direct map;
 *                  g_hhdm_offset is the same global the rest of the kernel uses
 *                  (e.g. drivers/net/virtio_net.c), so a pointer the parser
 *                  translates lands on exactly the bytes the adapter wrote.
 *   log          : kserial_puts — Josh's COM1 console, already initialized.
 *   panic        : kpanic — Josh's noreturn panic.
 *   alloc_pages  : pmm_alloc_pages(order) — buddy allocator, TRUE physical,
 *                  contiguous. *out_phys is that physical directly; the returned
 *                  virtual is phys + g_hhdm_offset. No alias gymnastics.
 *   now_ns       : rdtsc at a nominal 1 GHz (1 tick ~ 1 ns). Honest boot-metric
 *                  approximation only — never wall-clock. (TECH DEBT: feed Josh's
 *                  calibrated TSC frequency once the timer subsystem exposes it.)
 *
 * The `extern` Josh symbols below link to the real kernel when vendored into the
 * Josh tree; the standalone bearboot harness (test/harness.c) provides stubs.
 */
#include "osif.h"

/* ── Josh kernel symbols (real when vendored; stubbed by test/harness.c) ──── */
extern uint64_t g_hhdm_offset;                       /* Josh higher-half direct map */
extern void     kserial_puts(const char *s);         /* Josh COM1 console           */
extern void     kpanic(const char *msg) __attribute__((noreturn)); /* Josh panic    */
extern uint64_t pmm_alloc_pages(unsigned char order);/* buddy alloc → phys, 2^order */

/* ── phys_to_virt — Josh's higher-half direct map ────────────────────────── */
static void *josh_phys_to_virt(uint64_t phys)
{
    if (phys == 0)
        return (void *)0;                  /* OSIF contract: NULL for phys 0 */
    return (void *)(uintptr_t)(phys + g_hhdm_offset);
}

/* ── log / panic — native Josh console + panic ───────────────────────────── */
static void josh_log(const char *msg)
{
    if (msg)
        kserial_puts(msg);                 /* core appends no newline; we pass through */
}

__attribute__((noreturn)) static void josh_panic(const char *msg)
{
    kpanic(msg ? msg : "(bbp: null panic message)");
    for (;;)                               /* kpanic is noreturn; satisfy the compiler */
        __asm__ volatile("cli; hlt");
}

/* ── alloc_pages — buddy allocator, contiguous physical ──────────────────── *
 * Round `bytes` up to a power-of-two page count and ask the buddy allocator
 * for that order. Returns the HHDM-virtual base and writes the matching TRUE
 * physical to *out_phys. The adapter stores that physical in tags; the parser
 * translates it back through phys_to_virt above — one consistent map. */
#define JOSH_PAGE_SIZE 4096u

static unsigned char order_for_bytes(size_t bytes)
{
    size_t pages = (bytes + (JOSH_PAGE_SIZE - 1)) / JOSH_PAGE_SIZE;
    if (pages == 0)
        pages = 1;
    unsigned char order = 0;
    size_t cap = 1;
    while (cap < pages && order < 31) {    /* smallest 2^order >= pages */
        cap <<= 1;
        order++;
    }
    return order;
}

static void *josh_alloc_pages(size_t bytes, uint64_t *out_phys)
{
    uint64_t phys = pmm_alloc_pages(order_for_bytes(bytes));
    if (phys == 0) {                       /* allocator exhausted */
        if (out_phys)
            *out_phys = 0;
        return (void *)0;
    }
    if (out_phys)
        *out_phys = phys;
    return (void *)(uintptr_t)(phys + g_hhdm_offset);
}

/* ── now_ns — rdtsc, nominal 1 GHz (boot metrics only) ───────────────────── */
static uint64_t josh_now_ns(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* ── The OSIF vtable handed to the core/adapter ──────────────────────────── */
static const struct bbp_osif josh_osif = {
    .os_name      = "josh-bear",
    .port_version = "1.0.0",
    .phys_to_virt = josh_phys_to_virt,
    .log          = josh_log,
    .panic        = josh_panic,
    .alloc_pages  = josh_alloc_pages,
    .now_ns       = josh_now_ns,
};

const struct bbp_osif *bbp_josh_osif(void) { return &josh_osif; }
