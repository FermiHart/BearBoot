// SPDX-License-Identifier: BSD-3-Clause
/*
 * tina_bbp.c — TinaLinux <-> BBP kernel glue (the REAL native integration).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *
 * This is the ONLY BBP translation unit that includes <linux/...> headers. It does two
 * jobs:
 *
 *  1. STRONG OSIF hook overrides. osif.c declares bbp_tina_hook_{log,panic,
 *     alloc,now_ns} and bbp_tina_arena_base as __weak with freestanding
 *     fallbacks (serial/hlt/static-arena/rdtsc). The strong symbols below bind
 *     them to printk / panic / __get_free_pages / ktime_get_ns. Same osif.o,
 *     real kernel infrastructure — chosen at link time, zero #ifdef in the core.
 *
 *  2. The CALL SITE. A late_initcall sources the NATIVE Linux boot data
 *     (e820_table, acpi_os_get_root_pointer, phys_base/_text, saved_command_line,
 *     page_offset_base), copies it into the neutral struct bbp_tina_bootinfo,
 *     and runs the frozen adapter+parser. NON-FATAL: TinaLinux boots normally
 *     regardless; this ADDS a CRC-sealed, integrity-checked view of the
 *     firmware tables. Emits the BBP banner + a one-line verdict to the kernel
 *     log on success.
 *
 * Vendored into the kernel at arch/x86/bbp/ alongside the BBP core
 * (bbp_kernel.c, bbp_build.c) and the port (osif.c, adapter.c). See
 * integration.md.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/string.h>
#include <linux/panic.h>
#include <asm/e820/api.h>
#include <asm/e820/types.h>
#include <asm/page.h>
#include <asm/page_64.h>
#include <asm/sections.h>
#include <linux/acpi.h>

#include <bbp/bbp.h>
#include "adapter.h"
#include "osif.h"
#include "tina_bbp.h"

/* ===================================================================== *
 *  1. STRONG OSIF hooks — bind the freestanding port to real Linux APIs.
 * ===================================================================== */

/* printk per line. The OSIF emits substrings without a trailing newline, so we
 * buffer until '\n' to keep one BBP line == one printk record. KERN_INFO. */
#define BBP_LINE_MAX 256
static char  bbp_line[BBP_LINE_MAX];
static int   bbp_line_len;

void bbp_tina_hook_log(const char *msg)
{
    if (!msg)
        return;
    for (; *msg; msg++) {
        if (*msg == '\n' || bbp_line_len == BBP_LINE_MAX - 1) {
            bbp_line[bbp_line_len] = '\0';
            printk(KERN_INFO "bbp: %s\n", bbp_line);
            bbp_line_len = 0;
            if (*msg == '\n')
                continue;
        }
        bbp_line[bbp_line_len++] = *msg;
    }
}

__attribute__((noreturn)) void bbp_tina_hook_panic(const char *msg)
{
    panic("bbp: %s", msg ? msg : "(null)");
}

/* Real allocator: a few pages out of the Linux DIRECT MAP. Because this lives
 * in the direct map, __pa(arena) == arena - page_offset_base, exactly the OSIF
 * phys_to_virt relation — one alias, no kernel-image-vs-HHDM hazard. */
#ifndef BBP_TINA_ARENA_ORDER
#define BBP_TINA_ARENA_ORDER 4            /* 16 pages = 64 KiB */
#endif
static void         *bbp_arena_va;
static unsigned long  bbp_arena_bytes = (1UL << BBP_TINA_ARENA_ORDER) * PAGE_SIZE;
static unsigned long  bbp_arena_used;

void *bbp_tina_arena_base(unsigned long *out_size)
{
    if (!bbp_arena_va)
        bbp_arena_va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                                BBP_TINA_ARENA_ORDER);
    if (out_size)
        *out_size = bbp_arena_va ? bbp_arena_bytes : 0;
    return bbp_arena_va;
}

void *bbp_tina_hook_alloc(size_t bytes, uint64_t *out_phys)
{
    unsigned long start;
    void *p;
    if (!bbp_arena_va)
        (void)bbp_tina_arena_base(NULL);
    if (!bbp_arena_va)
        return NULL;
    start = (bbp_arena_used + 7u) & ~7uL;
    if (start > bbp_arena_bytes || bytes > bbp_arena_bytes - start)
        return NULL;
    p = (char *)bbp_arena_va + start;
    bbp_arena_used = start + bytes;
    if (out_phys)
        *out_phys = (uint64_t)__pa(p);
    return p;
}

uint64_t bbp_tina_hook_now_ns(void)
{
    return ktime_get_ns();
}

/* ===================================================================== *
 *  2. The call site — source native Linux boot data, build + validate.
 * ===================================================================== */
#define BBP_TINA_MAX_MMAP 256
static struct bbp_tina_mmap_entry bbp_mmap[BBP_TINA_MAX_MMAP];
static struct bbp_kctx            bbp_ctx;
static int                        bbp_ctx_valid;

/* Validated BBP context for the rest of the kernel (tag queries). */
const struct bbp_kctx *bbp_tina_boot_ctx(void)
{
    return bbp_ctx_valid ? &bbp_ctx : NULL;
}

/* RSDP from the CRC-VERIFIED ACPI tag (0 if no valid ctx / no tag). A corrupt
 * ACPI tag is treated as absent — the kernel never trusts a tampered RSDP. */
u64 bbp_tina_get_rsdp(void)
{
    const struct bbp_tag_header *t;
    if (!bbp_ctx_valid)
        return 0;
    t = bbp_find_tag(&bbp_ctx, BBP_TAG_ACPI);
    if (!t)
        return 0;
    return ((const struct bbp_tag_acpi *)t)->rsdp_address;
}

static int bbp_count_cb(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(u32 *)user)++;
    return 0;
}

static void bbp_tina_banner(const struct bbp_osif *o, u64 hhdm, u32 tags)
{
    o->log("\n");
    o->log("  +========================================================+\n");
    o->log("  |   B E A R   B O O T   P R O T O C O L   v1.1           |\n");
    o->log("  |   native TinaLinux OSIF  -  CRC64-sealed boot tags     |\n");
    o->log("  +========================================================+\n");
    o->log("     [*] native Linux -> BBP adapter .... ACTIVE\n");
    o->log("     [*] handoff integrity ............. CRC-64/XZ verified\n");
    o->log("     [*] source tables ................. e820 + ACPI + cmdline\n");
    o->log("     TinaLinux x86_64 now sees firmware through BBP.\n");
    o->log("     F E R M I  \xe2\x88\x9e  H A R T\n");
    o->log("  +========================================================+\n\n");
    (void)hhdm; (void)tags;
}

static int __init bbp_tina_init(void)
{
    struct bbp_tina_bootinfo bi;
    const struct bbp_osif *osif = bbp_tina_osif();
    bbp_status_t st;
    u32 i, m = 0, ntags = 0;

    memset(&bi, 0, sizeof(bi));

    /* HHDM = Linux direct map base (== __va offset over all RAM). */
    bi.hhdm_offset = (bbp_virt_t)page_offset_base;

    /* Kernel slide: phys_base + the kernel virtual base (_text). */
    bi.kernel_phys_base    = (uint64_t)phys_base;
    bi.kernel_virt_base    = (bbp_virt_t)(uintptr_t)_text;
    bi.have_kernel_address = 1;

    /* e820 firmware memory map (ALL types — informational, keeps RESERVED). */
    for (i = 0; i < (u32)e820_table->nr_entries && m < BBP_TINA_MAX_MMAP; i++) {
        bbp_mmap[m].base   = e820_table->entries[i].addr;
        bbp_mmap[m].length = e820_table->entries[i].size;
        bbp_mmap[m].type   = (uint32_t)e820_table->entries[i].type;
        m++;
    }
    bi.mmap       = bbp_mmap;
    bi.mmap_count = m;

    /* ACPI RSDP physical from the native getter. */
    bi.rsdp_phys = (uint64_t)acpi_os_get_root_pointer();

    /* Boot cmdline. */
    bi.cmdline = saved_command_line;

    st = bbp_tina_adapter(&bbp_ctx, &bi);

    osif->log("native Linux -> BBP adapter: ");
    osif->log(bbp_strstatus(st));
    osif->log("\n");

    bbp_ctx_valid = (st == BBP_OK);
    if (bbp_ctx_valid) {
        bbp_for_each_tag(&bbp_ctx, bbp_count_cb, &ntags);
        bbp_tina_banner(osif, bbp_ctx.hhdm_offset, ntags);
        /* The single deliverable marker the conformance rig greps for. */
        printk(KERN_INFO "bbp: tinalinux adapter ok, %u tags, hhdm=0x%llx\n",
               ntags, (unsigned long long)bbp_ctx.hhdm_offset);
    } else {
        printk(KERN_WARNING "bbp: tinalinux adapter FAILED: %s\n",
               bbp_strstatus(st));
    }
    return 0;
}
late_initcall(bbp_tina_init);
