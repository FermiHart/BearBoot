/*
 * adapter.c — Limine -> Bear Boot Protocol adapter for MINIX.
 *   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
 *
 * STATUS: SCAFFOLD. Synthesizes a bbp_info + tag list from Limine's boot
 * responses so the MINIX kernel can consume hardware data through the BBP
 * defensive parser. The MINIX agent fills each BBP_PORT_TODO with the real
 * Limine request/response reads from the limine-boot branch.
 *
 * This file compiles against the frozen core today (the Limine reads are
 * stubbed) so the scaffolding is verifiable; it is NOT yet functional.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../../bootloader/bbp_build.h"
#include "../../kernel/bbp_kernel.h"
#include "osif.h"

/* Scratch arena for the synthesized info + tags. A static arena is fine for
 * v1; switch to osif->alloc_pages when MINIX has a PMM available this early. */
#ifndef BBP_MINIX_ARENA
#define BBP_MINIX_ARENA (64u * 1024u)
#endif
static unsigned char bbp_minix_arena[BBP_MINIX_ARENA] __attribute__((aligned(16)));

/* Build a BBP context from Limine boot info. Returns BBP_OK and fills *out on
 * success. `hhdm_offset` is Limine's HHDM offset (MINIX is already mapped, so
 * we feed it to bbp_init_ex per SPEC §10.1). */
bbp_status_t bbp_minix_adapter(struct bbp_kctx *out, bbp_virt_t hhdm_offset)
{
    const struct bbp_osif *osif = bbp_minix_osif();
    (void)osif;

    struct bbp_info *info = (struct bbp_info *)bbp_minix_arena;
    for (unsigned i = 0; i < sizeof(bbp_minix_arena); i++) bbp_minix_arena[i] = 0;

    struct bbp_builder b;
    unsigned char *tagbase = bbp_minix_arena + sizeof(struct bbp_info);
    bbp_builder_init(&b, tagbase, (bbp_phys_t)(uintptr_t)tagbase,
                     sizeof(bbp_minix_arena) - sizeof(struct bbp_info));

    /* HHDM first — it drives all later translation. */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h) h->offset = hhdm_offset;

    /* === BBP_PORT_TODO: translate Limine responses into tags ============ *
     *  - limine memmap   -> BBP_TAG_MEMORY_MAP (map Limine type -> BBP_MEM_*)
     *  - limine kaddr     -> BBP_TAG_KERNEL_ADDRESS
     *  - limine rsdp      -> BBP_TAG_ACPI
     *  - limine fb        -> BBP_TAG_FRAMEBUFFER (optional)
     *  - cmdline          -> BBP_TAG_CMDLINE  (MUST set string_crc via
     *                        bbp_crc64 over the copied string)
     * Use bbp_alloc_tag for each; bbp_builder_finalize re-seals every CRC.
     * ==================================================================== */

    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);
    if (b.overflow) return BBP_ERR_SIZE;

    /* MINIX is already on its page tables; seed the parser with the HHDM. */
    return bbp_init_ex(out, info, hhdm_offset);
}
