/*
 * josh_glue.c — Josh-Bear integration entry point for the Bear Boot Protocol.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The ONE file coupled to Josh's headers. It reads Josh's already-parsed Limine
 * responses (the limine_get_*() accessors in kernel/boot/limine_requests.c),
 * fills the neutral struct bbp_josh_bootinfo, and calls bbp_josh_adapter(),
 * which synthesizes + validates a CRC-sealed BBP tag view. After this returns
 * BBP_OK the rest of Josh can query boot data through the hardened BBP parser
 * (bbp_find_tag / bbp_for_each_tag) instead of trusting raw Limine structs.
 *
 * Call bbp_josh_init() once early — AFTER vmm/pmm/heap are up (the OSIF arena
 * comes from pmm_alloc_pages) and BEFORE subsystems that want boot data.
 *
 * This file lives ONLY in the Josh tree (it needs <kernel/boot/limine.h>); the
 * standalone bearboot harness uses test/harness.c with synthetic data instead.
 */
#include <kernel/boot/limine.h>          /* pulls in boot/limine/limine.h structs */

#include <bbp/bbp.h>
#include "adapter.h"
#include "osif.h"

/* Josh console (declared here to avoid dragging kio.h's world in). */
extern void kserial_puts(const char *s);
extern void kserial_puthex(uint64_t v);

/* Caller-owned neutral snapshots the adapter borrows for the duration of the
 * call. Sized generously; entries beyond the cap are dropped (and logged). */
#define JOSH_MMAP_MAX 256
#define JOSH_CPU_MAX  256
static struct bbp_josh_mmap_entry g_mmap[JOSH_MMAP_MAX];
static struct bbp_josh_cpu        g_cpus[JOSH_CPU_MAX];

/* The validated context, kept for the rest of the kernel to query. */
static struct bbp_kctx g_josh_kctx;
static int             g_josh_bbp_ok = 0;

/* Public: the validated BBP context (NULL until bbp_josh_init returns BBP_OK). */
const struct bbp_kctx *bbp_josh_context(void)
{
    return g_josh_bbp_ok ? &g_josh_kctx : (const struct bbp_kctx *)0;
}

/* Counting callback — bbp_for_each_tag returns 0 for a NULL cb, so we pass a
 * real one that just tallies into *user. */
static int count_cb(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(uint32_t *)user)++;
    return 0;
}

/* Map a Limine framebuffer bpp to a BBP pixel format (best-effort: most Limine
 * framebuffers are 32-bpp little-endian BGRA). 0 lets the adapter default. */
static uint16_t fb_format_for_bpp(uint16_t bpp)
{
    return (bpp == 32) ? (uint16_t)BBP_FB_BGRA8888 : (uint16_t)0;
}

/* Build the BBP tag view from Limine and validate it. Returns BBP_OK on
 * success. Logs a one-line proof either way. */
int bbp_josh_init(void)
{
    struct bbp_josh_bootinfo bi;
    for (unsigned i = 0; i < sizeof(bi); i++)
        ((unsigned char *)&bi)[i] = 0;

    /* HHDM — mandatory for the higher-half handoff. */
    bi.hhdm_offset = limine_get_hhdm_offset();
    if (bi.hhdm_offset == 0) {
        kserial_puts("[BBP] no Limine HHDM — cannot build BBP view\r\n");
        return BBP_ERR_NULL;
    }

    /* Memory map. */
    struct limine_memmap_response *mm = limine_get_memmap();
    if (mm && mm->entry_count) {
        uint32_t n = 0;
        for (uint64_t i = 0; i < mm->entry_count && n < JOSH_MMAP_MAX; i++) {
            struct limine_memmap_entry *e = mm->entries[i];
            if (!e)
                continue;
            g_mmap[n].base   = e->base;
            g_mmap[n].length = e->length;
            g_mmap[n].type   = e->type;   /* RAW Limine type; adapter maps it */
            n++;
        }
        if (mm->entry_count > JOSH_MMAP_MAX) {
            kserial_puts("[BBP] WARN: memmap truncated to ");
            kserial_puthex(JOSH_MMAP_MAX);
            kserial_puts(" entries\r\n");
        }
        bi.mmap       = g_mmap;
        bi.mmap_count = n;
    }

    /* Framebuffer (optional). */
    struct limine_framebuffer_response *fbr = limine_get_framebuffer();
    if (fbr && fbr->framebuffer_count > 0 && fbr->framebuffers[0]) {
        struct limine_framebuffer *fb = fbr->framebuffers[0];
        bi.fb_address      = (uint64_t)(uintptr_t)fb->address; /* HHDM-virt; see note */
        bi.fb_pitch        = (uint32_t)fb->pitch;
        bi.fb_width        = (uint16_t)fb->width;
        bi.fb_height       = (uint16_t)fb->height;
        bi.fb_bpp          = (uint16_t)fb->bpp;
        bi.fb_pixel_format = fb_format_for_bpp((uint16_t)fb->bpp);
    }

    /* SMP — Josh is multicore (the minix port never emitted this tag). */
    struct limine_smp_response *smp = limine_get_smp();
    if (smp && smp->cpu_count) {
        uint32_t n = 0;
        for (uint64_t i = 0; i < smp->cpu_count && n < JOSH_CPU_MAX; i++) {
            struct limine_smp_info *c = smp->cpus[i];
            if (!c)
                continue;
            g_cpus[n].processor_id = c->processor_id;
            g_cpus[n].apic_id      = c->lapic_id;
            n++;
        }
        bi.cpus      = g_cpus;
        bi.cpu_count = n;
        bi.bsp_id    = smp->bsp_lapic_id;
    }

    /* No cmdline tag for v1: Josh boots without a kernel command line through
     * Limine. (When one is added, point bi.cmdline at it; the adapter seals
     * its string_crc and the consumer must bbp_verify_blob() it.) */

    bbp_status_t st = bbp_josh_adapter(&g_josh_kctx, &bi);
    if (st != BBP_OK) {
        kserial_puts("[BBP] josh adapter FAILED: ");
        kserial_puts(bbp_strstatus(st));
        kserial_puts("\r\n");
        g_josh_bbp_ok = 0;
        return st;
    }

    g_josh_bbp_ok = 1;
    uint32_t tags = 0;
    bbp_for_each_tag(&g_josh_kctx, count_cb, &tags);
    kserial_puts("[BBP] josh adapter ok, ");
    kserial_puthex(tags);
    kserial_puts(" tags, hhdm=");
    kserial_puthex(bi.hhdm_offset);   /* kserial_puthex already prefixes "0x" */
    kserial_puts(" (CRC-sealed, parser-validated)\r\n");
    return BBP_OK;
}
