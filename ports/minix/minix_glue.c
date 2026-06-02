/*
 * minix_glue.c — thin MINIX<->BBP boot glue (lives in the port, by design).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * WHY A GLUE TU
 * -------------
 * minix/kernel/arch/x86_64/limine_kinfo.c is compiled -nostdinc and DELIBERATELY
 * avoids limine.h "to avoid stdint.h / type conflicts with the -nostdinc kernel
 * build". Pulling <bbp/bbp.h> (which includes <stdint.h>) straight into that
 * conflict. So the BBP side is fully contained HERE — this file owns all the
 * bbp includes — and exposes ONE function with plain scalar
 * + void* parameters. The MINIX entry only needs a 1-line extern and 1 call;
 * no BBP header ever enters the MINIX translation unit.
 *
 * This keeps the integration footprint in the MINIX tree to two trivial lines
 * (see ../integration.md §3) and the whole BBP surface inside ports/minix/.
 *
 * Compiles under the MINIX kernel CFLAGS (-nostdinc + -idirafter destdir,
 * -I<BearBoot>/include) — verified.
 */
#include <bbp/bbp.h>
#include "adapter.h"
#include "osif.h"

/* Mirror of a Limine memmap entry (base,length,type) — same 3x u64 layout as
 * `struct lim_memmap_entry` in limine_kinfo.c and `struct limine_memmap_entry`
 * in limine.h. The caller passes the Limine response's `entries` array (an
 * array of POINTERS to entries) as void**, which we reinterpret here. */
struct glue_lim_mmap_entry { uint64_t base, length, type; };

/* Bounded static storage: a Limine map is routinely 30-40 entries; 256 is a
 * safe ceiling (~6 KiB BSS). The validated context is kept here so the rest of
 * the kernel can fetch it via bbp_minix_boot_ctx() and query tags. */
#define GLUE_MAX_MMAP 256
static struct bbp_minix_mmap_entry g_mmap[GLUE_MAX_MMAP];
static struct bbp_kctx             g_ctx;
static int                         g_ctx_valid = 0;

/* Returns the validated BBP context after a successful glue call, or NULL. */
const struct bbp_kctx *bbp_minix_boot_ctx(void)
{
    return g_ctx_valid ? &g_ctx : (const struct bbp_kctx *)0;
}

/* --- tiny number printers (no libc; OSIF log takes one string at a time) --- */
static void glue_hex(const struct bbp_osif *o, uint64_t v)
{
    char buf[19]; const char *h = "0123456789abcdef";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; i++) buf[2 + i] = h[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = 0;
    o->log(buf);
}

static void glue_dec(const struct bbp_osif *o, uint64_t v)
{
    char buf[21]; int i = 20; buf[20] = 0;
    if (v == 0) { o->log("0"); return; }
    while (v && i) { buf[--i] = '0' + (v % 10); v /= 10; }
    o->log(&buf[i]);
}

/*
 * Bear Boot Protocol boot banner — printed to the serial console when the
 * adapter validates the synthesized tag list on real Limine data. This is the
 * "BBP is ACTIVE" marker the rest of the boot (and the user) can see.
 */
static void bbp_minix_banner(const struct bbp_osif *osif,
                             uint64_t hhdm, uint32_t tags)
{
    osif->log("\n");
    osif->log("  +========================================================+\n");
    osif->log("  |   B E A R   B O O T   P R O T O C O L   v1.1           |\n");
    osif->log("  |   the bear-grade kernel handoff  -  CRC64-sealed tags  |\n");
    osif->log("  +========================================================+\n");
    osif->log("     [*] Limine -> BBP adapter ......... ACTIVE\n");
    osif->log("     [*] handoff integrity ............. CRC-64/XZ verified\n");
    osif->log("     [*] HHDM reachability (SPEC 10.1b)  ok, offset=");
    glue_hex(osif, hhdm);
    osif->log("\n");
    osif->log("     [*] tags validated ................ ");
    glue_dec(osif, tags);
    osif->log("\n");
    osif->log("     MINIX x86_64 now sees hardware through BBP.\n");
    osif->log("     F E R M I  \xe2\x88\x9e  H A R T\n");
    osif->log("  +========================================================+\n\n");
}

/* Counting callback: bbp_for_each_tag only invokes it for CRC-validated tags,
 * so the tally is the number of tags that actually passed integrity checks. */
static int glue_count_cb(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(uint32_t *)user)++;
    return 0;
}

/*
 * Build + validate the BBP tag list from the boot values MINIX already pulled
 * out of the Limine responses. All parameters are plain (no BBP/Limine types
 * in the signature) so the MINIX caller stays header-clean.
 *
 *   hhdm        Limine HHDM offset (limine_hhdm_offset)
 *   kphys/kvirt Limine kernel-address physical_base / virtual_base
 *   have_kaddr  1 if the kernel-address response was present
 *   rsdp        Limine RSDP physical (limine_rsdp_phys), 0 if none
 *   entries     Limine memmap_request.response->entries (void**), or NULL
 *   count       memmap entry_count
 *   cmdline     NUL-terminated boot cmdline, or NULL
 *
 * Returns the BBP status as int (0 == BBP_OK). Logs a one-line verdict to the
 * serial console via the OSIF. NON-FATAL by contract: on any error MINIX keeps
 * booting from its legacy kinfo_t — this only ADDS a CRC-checked tag view.
 */
int bbp_minix_boot_glue(uint64_t hhdm, uint64_t kphys, uint64_t kvirt,
                        int have_kaddr, uint64_t rsdp,
                        void **entries, uint64_t count,
                        const char *cmdline)
{
    struct bbp_minix_bootinfo bi;
    for (unsigned z = 0; z < sizeof(bi); z++)
        ((char *)&bi)[z] = 0;

    bi.hhdm_offset         = hhdm;
    bi.kernel_phys_base    = kphys;
    bi.kernel_virt_base    = kvirt;
    bi.have_kernel_address = have_kaddr ? 1 : 0;
    bi.rsdp_phys           = rsdp;

    uint32_t m = 0;
    if (entries && count) {
        struct glue_lim_mmap_entry **e = (struct glue_lim_mmap_entry **)entries;
        for (uint64_t i = 0; i < count && m < GLUE_MAX_MMAP; i++) {
            if (!e[i])
                continue;
            g_mmap[m].base   = e[i]->base;
            g_mmap[m].length = e[i]->length;
            g_mmap[m].type   = e[i]->type;   /* RAW Limine type; adapter maps it */
            m++;
        }
    }
    bi.mmap       = g_mmap;
    bi.mmap_count = m;
    bi.cmdline    = cmdline;

    bbp_status_t st = bbp_minix_adapter(&g_ctx, &bi);

    const struct bbp_osif *osif = bbp_minix_osif();
    osif->log("[limine] BBP adapter: ");
    osif->log(bbp_strstatus(st));
    osif->log("\n");

    g_ctx_valid = (st == BBP_OK);
    if (g_ctx_valid) {
        /* Count CRC-validated tags for the banner (parser verifies each). */
        uint32_t ntags = 0;
        bbp_for_each_tag(&g_ctx, glue_count_cb, &ntags);
        bbp_minix_banner(osif, g_ctx.hhdm_offset, ntags);
    }
    return (int)st;
}
