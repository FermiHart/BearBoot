/*
 * harness.c — standalone test for the Josh-Bear BBP port.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Exercises ports/josh/{osif.c,adapter.c} against the frozen BBP core WITHOUT
 * the Josh kernel: it stubs the four Josh symbols osif.c needs (g_hhdm_offset,
 * kserial_puts, kpanic, pmm_alloc_pages) with a hosted identity map, feeds a
 * synthetic bbp_josh_bootinfo (memmap + framebuffer + 4 CPUs), runs
 * bbp_josh_adapter(), then validates the result through the public parser API
 * (bbp_find_tag / bbp_for_each_tag). hhdm_offset=0 makes phys==virt so the
 * malloc'd arena is directly walkable. Exit code 0 = all checks pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <bbp/bbp.h>
#include "../adapter.h"

/* ── Josh symbol stubs (identity map: phys == virt) ──────────────────────── */
uint64_t g_hhdm_offset = 0;

void kserial_puts(const char *s) { fputs(s, stdout); }

__attribute__((noreturn)) void kpanic(const char *msg)
{
    fprintf(stderr, "PANIC: %s\n", msg ? msg : "(null)");
    exit(2);
}

/* Bump allocator over one big arena; returns the "physical" (== virtual, since
 * hhdm=0) base of 2^order pages. */
uint64_t pmm_alloc_pages(unsigned char order)
{
    static unsigned char *pool = NULL;
    static size_t used = 0;
    static const size_t POOL = 4u * 1024u * 1024u;
    if (!pool) {
        pool = aligned_alloc(4096, POOL);
        if (!pool) return 0;
        memset(pool, 0xCC, POOL);          /* poison: catch reliance on zeroing */
    }
    size_t pages = (size_t)1 << order;
    size_t bytes = pages * 4096;
    size_t start = (used + 4095) & ~((size_t)4095);
    if (start + bytes > POOL) return 0;
    used = start + bytes;
    return (uint64_t)(uintptr_t)(pool + start);
}

/* ── Synthetic Limine boot data ──────────────────────────────────────────── */
static int count_cb(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(uint32_t *)user)++;
    return 0;
}

int main(void)
{
    struct bbp_josh_mmap_entry mmap[] = {
        { 0x0,        0x9F000,     0 },  /* usable */
        { 0x9F000,    0x1000,      1 },  /* reserved */
        { 0x100000,   0x7EF00000,  0 },  /* usable (~2 GiB) */
        { 0x7FF00000, 0x100000,    2 },  /* ACPI reclaimable */
        { 0xFEE00000, 0x1000,      1 },  /* reserved (LAPIC) */
    };
    struct bbp_josh_cpu cpus[] = {
        { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 3 },
    };

    struct bbp_josh_bootinfo bi;
    memset(&bi, 0, sizeof(bi));
    bi.hhdm_offset    = 0;                 /* identity for the hosted test */
    bi.mmap           = mmap;
    bi.mmap_count     = (uint32_t)(sizeof(mmap) / sizeof(mmap[0]));
    bi.fb_address     = 0xFD000000;
    bi.fb_pitch       = 1280 * 4;
    bi.fb_width       = 1280;
    bi.fb_height      = 800;
    bi.fb_bpp         = 32;
    bi.fb_pixel_format = 0;                 /* let glue/adapter default */
    bi.cpus           = cpus;
    bi.cpu_count      = (uint32_t)(sizeof(cpus) / sizeof(cpus[0]));
    bi.bsp_id         = 0;
    bi.cmdline        = "josh.test=1 root=/dev/ram0";

    struct bbp_kctx k;
    bbp_status_t st = bbp_josh_adapter(&k, &bi);
    printf("bbp_josh_adapter -> %s\n", bbp_strstatus(st));
    if (st != BBP_OK) return 1;

    int fails = 0;
    struct { uint64_t id; const char *name; int want; } want[] = {
        { BBP_TAG_HHDM,        "HHDM",        1 },
        { BBP_TAG_MEMORY_MAP,  "MEMORY_MAP",  1 },
        { BBP_TAG_FRAMEBUFFER, "FRAMEBUFFER", 1 },
        { BBP_TAG_SMP,         "SMP",         1 },
        { BBP_TAG_CMDLINE,     "CMDLINE",     1 },
    };
    for (unsigned i = 0; i < sizeof(want)/sizeof(want[0]); i++) {
        const struct bbp_tag_header *t = bbp_find_tag(&k, want[i].id);
        printf("  tag %-12s : %s\n", want[i].name, t ? "present" : "ABSENT");
        if (!!t != want[i].want) fails++;
    }

    /* Verify memory map decoded correctly. */
    const struct bbp_tag_memory_map *mm =
        (const struct bbp_tag_memory_map *)bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    if (mm) {
        uint32_t n = 0;
        const struct bbp_memory_entry *e =
            bbp_tag_array(&mm->header, sizeof(*mm), sizeof(struct bbp_memory_entry),
                          mm->entry_count, &n);
        printf("  memmap entries: %u (type[0]=%u expect USABLE=%u)\n",
               n, e[0].type, BBP_MEM_USABLE);
        if (n != bi.mmap_count || e[0].type != BBP_MEM_USABLE) fails++;
    }

    /* Verify SMP decoded. */
    const struct bbp_tag_smp *smp =
        (const struct bbp_tag_smp *)bbp_find_tag(&k, BBP_TAG_SMP);
    if (smp) {
        printf("  smp cpu_count=%u bsp_id=%u\n", smp->cpu_count, smp->bsp_id);
        if (smp->cpu_count != bi.cpu_count) fails++;
    }

    /* Verify the cmdline blob CRC (ADR-0006). */
    const struct bbp_tag_cmdline *cl =
        (const struct bbp_tag_cmdline *)bbp_find_tag(&k, BBP_TAG_CMDLINE);
    if (cl) {
        bbp_status_t bs = bbp_verify_blob(&k, cl->string, cl->length,
                                          cl->string_crc, 0);
        printf("  cmdline verify_blob -> %s\n", bbp_strstatus(bs));
        if (bs != BBP_OK) fails++;
    }

    uint32_t total = 0;
    bbp_for_each_tag(&k, count_cb, &total);
    printf("total tags walked: %u\n", total);
    printf(fails ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", fails);
    return fails ? 1 : 0;
}
