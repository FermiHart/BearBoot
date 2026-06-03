/*
 * test/harness.c — hosted verification of the TinaLinux BBP port.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * WHY THIS EXISTS
 * ---------------
 * The shipped deliverable is a kernel serial log proving the native Linux->BBP
 * adapter validated on real e820/ACPI/cmdline data (the late_initcall in
 * tina_bbp.c). We cannot boot the whole kernel in CI for every edit, and we
 * must not edit anything outside ports/tinalinux/. So this hosted rig stands in
 * for the kernel:
 *
 *   - It supplies STRONG hosted overrides for the port's __weak OSIF hooks
 *     (bbp_tina_hook_{log,panic,alloc,now_ns} + bbp_tina_arena_base), exactly
 *     as tina_bbp.c does for the real kernel — but bound to stdio/malloc instead
 *     of printk/__get_free_pages. This is the SAME mechanism the kernel uses;
 *     it proves the weak/strong binding contract works.
 *   - It builds a REPRESENTATIVE native bootinfo: an e820-style memory map (the
 *     RAW E820_TYPE_* values the kernel call site copies from e820_table), a
 *     kernel slide, an ACPI RSDP, and a cmdline — the EXACT field shape the
 *     real call site fills.
 *   - It runs the REAL adapter (bbp_tina_adapter, the shipped code) and asserts
 *     the FROZEN parser returns BBP_OK, walks every CRC-validated tag, and
 *     verifies the out-of-line cmdline via bbp_verify_blob (ADR-0006).
 *
 * If this prints PASS, the adapter is proven against representative native boot
 * data through the frozen core; the kernel integration is then just the wiring
 * in tina_bbp.c (same field copy, same call), verified at boot by the serial
 * log. This file is the verification rig only; it is NOT a shipped port object.
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
 *  (Same override mechanism the kernel glue tina_bbp.c uses.)
 * ===================================================================== */
void bbp_tina_hook_log(const char *msg) { if (msg) fputs(msg, stdout); }

__attribute__((noreturn)) void bbp_tina_hook_panic(const char *msg)
{
    fprintf(stderr, "\n[harness] PANIC: %s\n", msg ? msg : "(null)");
    exit(2);
}

/* Hosted arena: a static buffer plays the role of the direct-map pages. We hand
 * out a synthetic "physical" by treating the buffer's own address as physical
 * and using HHDM offset 0 in the bootinfo — so phys_to_virt is the identity and
 * the parser can dereference the tag pointers directly in this process. */
#define HARENA_BYTES (256u * 1024u)
static unsigned char harena[HARENA_BYTES] __attribute__((aligned(4096)));
static unsigned long harena_used;

void *bbp_tina_arena_base(unsigned long *out_size)
{
    if (out_size) *out_size = (unsigned long)sizeof(harena);
    return harena;
}

void *bbp_tina_hook_alloc(size_t bytes, uint64_t *out_phys)
{
    unsigned long start = (harena_used + 7u) & ~7uL;
    if (start > sizeof(harena) || bytes > sizeof(harena) - start) return NULL;
    void *p = harena + start;
    harena_used = start + bytes;
    if (out_phys) *out_phys = (uint64_t)(uintptr_t)p;   /* HHDM 0 => phys==virt */
    return p;
}

uint64_t bbp_tina_hook_now_ns(void) { return 0; }

/* ===================================================================== *
 *  Representative NATIVE boot data — the field shape the kernel call site
 *  (tina_bbp.c) copies from e820_table / phys_base / RSDP / cmdline.
 *  RAW E820_TYPE_* values: 1=RAM 2=RESERVED 3=ACPI 4=NVS 0xefffffff=SOFT_RES.
 * ===================================================================== */
static const struct bbp_tina_mmap_entry e820ish[] = {
    { 0x0000000000000000ULL, 0x000000000009fc00ULL, 1 },          /* RAM   */
    { 0x000000000009fc00ULL, 0x0000000000000400ULL, 2 },          /* RESV  */
    { 0x00000000000f0000ULL, 0x0000000000010000ULL, 2 },          /* RESV  */
    { 0x0000000000100000ULL, 0x000000007ee00000ULL, 1 },          /* RAM   */
    { 0x000000007ef00000ULL, 0x0000000000100000ULL, 3 },          /* ACPI  */
    { 0x000000007f000000ULL, 0x0000000000100000ULL, 4 },          /* NVS   */
    { 0x00000000fe000000ULL, 0x0000000002000000ULL, 2 },          /* RESV  */
    { 0x0000000100000000ULL, 0x0000000080000000ULL, 1 },          /* RAM   */
    { 0x0000000180000000ULL, 0x0000000010000000ULL, 0xefffffffu },/* SOFT  */
};
#define E820ISH_N (sizeof(e820ish) / sizeof(e820ish[0]))

static const char harness_cmdline[] =
    "console=ttyS0,115200 root=/dev/ram0 quiet tina.bbp=1";

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
    printf("  BBP TinaLinux port - native adapter VERIFICATION (hosted)\n");
    printf("  F E R M I \xe2\x88\x9e H A R T  <contact@fermihart.com>\n");
    printf("================================================\n");

    struct bbp_tina_bootinfo bi;
    memset(&bi, 0, sizeof(bi));

    bi.hhdm_offset         = 0;            /* hosted: identity map */
    bi.kernel_phys_base    = 0x0000000001000000ULL;
    bi.kernel_virt_base    = 0xffffffff81000000ULL;
    bi.have_kernel_address = 1;
    bi.mmap                = e820ish;
    bi.mmap_count          = (uint32_t)E820ISH_N;
    bi.rsdp_phys           = 0x000000007ef00000ULL;
    bi.cmdline             = harness_cmdline;

    printf("[harness] e820 entries ......... %u\n", bi.mmap_count);
    printf("[harness] kernel phys base ..... 0x%llx\n",
           (unsigned long long)bi.kernel_phys_base);
    printf("[harness] ACPI RSDP phys ....... 0x%llx\n",
           (unsigned long long)bi.rsdp_phys);
    printf("[harness] cmdline .............. %s\n", bi.cmdline);

    printf("\n[harness] calling bbp_tina_adapter()...\n");
    struct bbp_kctx k;
    bbp_status_t st = bbp_tina_adapter(&k, &bi);
    printf("[harness] bbp_init_ex -> %s\n", bbp_strstatus(st));
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
    const struct bbp_tag_header *acpi = bbp_find_tag(&k, BBP_TAG_ACPI);
    printf("[harness] HHDM tag ............. %s\n", hhdm ? "present" : "MISSING");
    printf("[harness] MEMORY_MAP tag ....... %s\n", mm   ? "present" : "MISSING");
    printf("[harness] KERNEL_ADDRESS tag ... %s\n", ka   ? "present" : "MISSING");
    printf("[harness] ACPI tag ............. %s\n", acpi ? "present" : "MISSING");
    if (!hhdm || !mm || !ka || !acpi) {
        printf("[harness] RESULT: FAIL (a mandatory tag is missing)\n");
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
        printf("[harness] MEMORY_MAP entries ... %u usable=%llu MiB\n",
               cnt, (unsigned long long)(usable / (1024 * 1024)));
        if (cnt != bi.mmap_count) {
            printf("[harness] RESULT: FAIL (entry count mismatch %u != %u)\n",
                   cnt, bi.mmap_count);
            return 1;
        }
    }

    /* ADR-0006: verify the out-of-line cmdline before trusting it. */
    const struct bbp_tag_header *clh = bbp_find_tag(&k, BBP_TAG_CMDLINE);
    if (clh) {
        const struct bbp_tag_cmdline *cl = (const struct bbp_tag_cmdline *)clh;
        bbp_status_t vb = bbp_verify_blob(&k, cl->string, cl->length,
                                          cl->string_crc, 0);
        printf("[harness] CMDLINE tag .......... present len=%u\n", cl->length);
        printf("[harness] bbp_verify_blob ...... %s\n", bbp_strstatus(vb));
        if (vb != BBP_OK) {
            printf("[harness] RESULT: FAIL (cmdline CRC rejected)\n");
            return 1;
        }
        const char *s = (const char *)bbp_phys_to_virt(&k, cl->string);
        printf("[harness] cmdline contents ..... \"%s\"\n", s);
        if (strcmp(s, harness_cmdline) != 0) {
            printf("[harness] RESULT: FAIL (cmdline content mismatch)\n");
            return 1;
        }
    }

    printf("\n================================================\n");
    printf("  bbp: tinalinux adapter ok, %u tags, hhdm=0x%llx\n",
           visited, (unsigned long long)k.hhdm_offset);
    printf("  RESULT: PASS - native adapter validated on representative e820 data\n");
    printf("================================================\n");
    return 0;
}
