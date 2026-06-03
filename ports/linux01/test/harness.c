/*
 * test/harness.c — hosted verification of the linux-0.01 BBP port.
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * WHY THIS EXISTS
 * ---------------
 * The shipped deliverable is a kernel serial log proving the native
 * linux-0.01 -> BBP adapter validated on the kernel's fixed RAM model (the
 * bbp_linux01_init() call site in linux01_bbp.c). We cannot boot the whole
 * 1991 kernel in CI for every edit, and we must not edit anything outside
 * ports/linux01/. So this hosted rig stands in for the kernel:
 *
 *   - It supplies STRONG hosted overrides for the port's __weak OSIF hooks
 *     (bbp_l01_hook_{log,panic,alloc,now_ns} + bbp_l01_arena_base), exactly as
 *     linux01_bbp.c does for the real kernel — but bound to stdio/malloc-style
 *     storage instead of printk/static-arena. This is the SAME mechanism the
 *     kernel uses; it proves the weak/strong binding contract works.
 *   - It builds the EXACT bootinfo shape the kernel call site fills: the
 *     linux-0.01 fixed RAM model (0..640K RAM, 640K..1M reserved, 1M..8M RAM),
 *     HHDM offset 0 (identity map), kernel base 0/0.
 *   - It runs the REAL adapter (bbp_l01_adapter, the shipped code) and asserts
 *     the FROZEN parser returns BBP_OK and walks every CRC-validated tag.
 *
 * If this prints PASS, the adapter is proven against the real linux-0.01 RAM
 * model through the frozen core; the kernel integration is then just the wiring
 * in linux01_bbp.c (same field copy, same call), verified at boot by the serial
 * log. This file is the verification rig only; NOT a shipped port object.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <bbp/bbp.h>
#include "../adapter.h"
#include "../osif.h"

/* ===================================================================== *
 *  STRONG hosted overrides of the port's __weak OSIF hooks.
 *  (Same override mechanism the kernel glue linux01_bbp.c uses.)
 * ===================================================================== */
void bbp_l01_hook_log(const char *msg) { if (msg) fputs(msg, stdout); }

__attribute__((noreturn)) void bbp_l01_hook_panic(const char *msg)
{
    fprintf(stderr, "\n[harness] PANIC: %s\n", msg ? msg : "(null)");
    exit(2);
}

/* Hosted arena: a static buffer plays the role of the identity-mapped low RAM.
 * We hand out a synthetic "physical" equal to the buffer's own address and use
 * HHDM offset 0 in the bootinfo — so phys_to_virt is the identity and the
 * parser can dereference the tag pointers directly in this process, exactly as
 * the real identity-mapped linux-0.01 kernel does. */
#define HARENA_BYTES (128u * 1024u)
static unsigned char harena[HARENA_BYTES] __attribute__((aligned(4096)));
static unsigned long harena_used;

void *bbp_l01_arena_base(unsigned long *out_size)
{
    if (out_size) *out_size = (unsigned long)sizeof(harena);
    return harena;
}

void *bbp_l01_hook_alloc(size_t bytes, uint64_t *out_phys)
{
    unsigned long start = (harena_used + 7u) & ~7uL;
    if (start > sizeof(harena) || bytes > sizeof(harena) - start) return NULL;
    void *p = harena + start;
    harena_used = start + bytes;
    if (out_phys) *out_phys = (uint64_t)(uintptr_t)p;   /* HHDM 0 => phys==virt */
    return p;
}

uint64_t bbp_l01_hook_now_ns(void) { return 0; }

/* ===================================================================== *
 *  The linux-0.01 fixed RAM model — the EXACT field shape linux01_bbp.c
 *  fills from config.h HIGH_MEMORY (LINUS_HD = 8 MiB) + the 640K-1M hole.
 *  Types are BBP_MEM_* directly (no firmware map to decode in 1991).
 * ===================================================================== */
#define L01_HIGH_MEMORY  0x800000ULL   /* 8 MiB, config.h LINUS_HD */
static const struct bbp_l01_mmap_entry ram_model[] = {
    { 0x00000000ULL, 0x000A0000ULL,                 BBP_MEM_USABLE   }, /* 0..640K RAM */
    { 0x000A0000ULL, 0x00060000ULL,                 BBP_MEM_RESERVED }, /* 640K..1M    */
    { 0x00100000ULL, L01_HIGH_MEMORY - 0x00100000ULL, BBP_MEM_USABLE }, /* 1M..8M  RAM */
};
#define RAM_MODEL_N (sizeof(ram_model) / sizeof(ram_model[0]))

static int count_cb(const struct bbp_tag_header *tag, void *user)
{
    uint32_t *n = (uint32_t *)user;
    (*n)++;
    printf("       tag id=0x%016llx size=%u\n",
           (unsigned long long)tag->tag_id, tag->tag_size);
    return 0;
}

int main(void)
{
    printf("================================================\n");
    printf("  BBP linux-0.01 port - native adapter VERIFICATION (hosted)\n");
    printf("  F E R M I \xe2\x88\x9e H A R T  <contact@fermihart.com>\n");
    printf("================================================\n");

    struct bbp_l01_bootinfo bi;
    memset(&bi, 0, sizeof(bi));

    bi.hhdm_offset         = 0;            /* identity map */
    bi.kernel_phys_base    = 0;            /* linked + loaded at physical 0 */
    bi.kernel_virt_base    = 0;
    bi.have_kernel_address = 1;
    bi.mmap                = ram_model;
    bi.mmap_count          = (uint32_t)RAM_MODEL_N;

    printf("[harness] RAM model entries .... %u\n", bi.mmap_count);
    printf("[harness] HIGH_MEMORY .......... 0x%llx (8 MiB, LINUS_HD)\n",
           (unsigned long long)L01_HIGH_MEMORY);
    printf("[harness] HHDM offset .......... 0x%llx (identity map)\n",
           (unsigned long long)bi.hhdm_offset);

    printf("\n[harness] calling bbp_l01_adapter()...\n");
    struct bbp_kctx k;
    bbp_status_t st = bbp_l01_adapter(&k, &bi);
    printf("[harness] bbp_init -> %s\n", bbp_strstatus(st));
    if (st != BBP_OK) {
        printf("[harness] RESULT: FAIL (parser rejected synthesized info)\n");
        return 1;
    }

    uint32_t visited = 0;
    printf("[harness] walking tags:\n");
    bbp_for_each_tag(&k, count_cb, &visited);
    printf("[harness] tags validated ....... %u\n", visited);

    const struct bbp_tag_header *hhdm = bbp_find_tag(&k, BBP_TAG_HHDM);
    const struct bbp_tag_header *mm   = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    const struct bbp_tag_header *ka   = bbp_find_tag(&k, BBP_TAG_KERNEL_ADDRESS);
    printf("[harness] HHDM tag ............. %s\n", hhdm ? "present" : "MISSING");
    printf("[harness] MEMORY_MAP tag ....... %s\n", mm   ? "present" : "MISSING");
    printf("[harness] KERNEL_ADDRESS tag ... %s\n", ka   ? "present" : "MISSING");
    if (!hhdm || !mm || !ka) {
        printf("[harness] RESULT: FAIL (a mandatory tag is missing)\n");
        return 1;
    }

    /* HHDM must be exactly 0 (identity map) — the whole point of this port. */
    if (((const struct bbp_tag_hhdm *)hhdm)->offset != 0) {
        printf("[harness] RESULT: FAIL (HHDM offset != 0 on identity map)\n");
        return 1;
    }

    if (mm) {
        const struct bbp_tag_memory_map *m = (const struct bbp_tag_memory_map *)mm;
        uint32_t cnt = 0;
        const struct bbp_memory_entry *e =
            bbp_tag_array(mm, sizeof(*m), sizeof(struct bbp_memory_entry),
                          m->entry_count, &cnt);
        uint64_t usable = 0;
        for (uint32_t i = 0; i < cnt; i++)
            if (e[i].type == BBP_MEM_USABLE) usable += e[i].length;
        printf("[harness] MEMORY_MAP entries ... %u usable=%llu KiB\n",
               cnt, (unsigned long long)(usable / 1024));
        if (cnt != bi.mmap_count) {
            printf("[harness] RESULT: FAIL (entry count mismatch %u != %u)\n",
                   cnt, bi.mmap_count);
            return 1;
        }
        /* 640K + (8M - 1M) = 640 + 7168 = 7808 KiB usable */
        if (usable != (0x000A0000ULL + (L01_HIGH_MEMORY - 0x00100000ULL))) {
            printf("[harness] RESULT: FAIL (usable RAM total wrong: %llu)\n",
                   (unsigned long long)usable);
            return 1;
        }
    }

    /* Adversarial: corrupt the MEMORY_MAP tag in place, parser must reject. */
    {
        struct bbp_tag_memory_map *m = (struct bbp_tag_memory_map *)mm;
        uint32_t saved = m->entry_count;
        m->entry_count = 0xDEAD;
        if (bbp_find_tag(&k, BBP_TAG_MEMORY_MAP) != NULL) {
            printf("[harness] RESULT: FAIL (corrupt tag not rejected)\n");
            return 1;
        }
        m->entry_count = saved;   /* restore (CRC now matches again) */
        printf("[harness] corrupt-tag rejection . ok\n");
    }

    printf("\n================================================\n");
    printf("  bbp: linux-0.01 adapter ok, %u tags, hhdm=0x%llx\n",
           visited, (unsigned long long)k.hhdm_offset);
    printf("  RESULT: PASS - native adapter validated on the linux-0.01 RAM model\n");
    printf("================================================\n");
    return 0;
}
