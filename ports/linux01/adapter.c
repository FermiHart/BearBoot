/*
 * adapter.c — native linux-0.01 -> Bear Boot Protocol adapter (REAL).
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Synthesizes a bbp_info + tag list from the boot data Linus' 1991 kernel has:
 * a FIXED RAM model (config.h HIGH_MEMORY, 640K-1M hole reserved) and the fact
 * that it is loaded + linked at physical 0 and runs identity-mapped. Then
 * validates the result through the frozen BBP core parser.
 *
 * linux-0.01 is IDENTITY-mapped when this runs (pg_dir = 0 maps the first
 * 8 MiB; mm/memory.c), so we follow SPEC §10.1(a):
 *   - every tag pointer stored is a TRUE PHYSICAL address (the builder writes
 *     arena_phys + offset; arena_phys == arena_virt because HHDM offset is 0);
 *   - bbp_init is seeded with HHDM offset 0 (the identity), so the parser walks
 *     the physically-linked list directly — no bbp_init_ex, no higher-half
 *     translation, because there is none.
 *
 * SINGLE-ALIAS NOTE (why this port is even simpler than tinalinux's): the
 * scratch arena is a static buffer, but at the call site the kernel is
 * identity-mapped, so arena_phys == arena_virt. There is exactly one alias;
 * the classic "kernel-image vs HHDM" arena bug is structurally impossible — for
 * the most elementary reason of all, the HHDM offset is literally 0.
 *
 * Tags produced:
 *   HHDM           (mandatory — offset 0; documents the identity map)
 *   MEMORY_MAP     (the kernel's fixed RAM model: usable RAM + reserved hole)
 *   KERNEL_ADDRESS (0 / 0 — linked + loaded at physical 0)
 *
 * Tags NOT produced (honest absence — linux-0.01 predates them, 1991):
 *   ACPI, CMDLINE, FRAMEBUFFER, SMP, SECURITY. We never fabricate a tag for
 *   hardware the kernel has no knowledge of.
 *
 * No libc, no kernel headers: compiles for `make scaffold-check`, links into
 * the standalone harness, and drops into linux-0.01 unchanged.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../../bootloader/bbp_build.h"
#include "../../kernel/bbp_kernel.h"
#include "osif.h"
#include "adapter.h"

static uint32_t bbp_mem_default_attrs(uint32_t bbp_type)
{
    switch (bbp_type) {
    case BBP_MEM_USABLE:
    case BBP_MEM_BOOTLOADER_RECLAIM:
    case BBP_MEM_ACPI_RECLAIMABLE:
    case BBP_MEM_KERNEL_AND_MODULES:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_CACHED;
    default:
        return BBP_MEM_ATTR_READABLE;
    }
}

bbp_status_t bbp_l01_adapter(struct bbp_kctx *out,
                             const struct bbp_l01_bootinfo *bi)
{
    if (!out || !bi)
        return BBP_ERR_NULL;

    const struct bbp_osif *osif = bbp_l01_osif();

    /* Make the OSIF coherent with the data we synthesize: HHDM drives
     * phys_to_virt (0 on linux-0.01); the slide feeds the KERNEL_ADDRESS tag. */
    bbp_l01_set_hhdm(bi->hhdm_offset);
    if (bi->have_kernel_address)
        bbp_l01_set_kslide(bi->kernel_phys_base, bi->kernel_virt_base);

    /* Scratch arena from the OSIF; carve bbp_info off its front so info_size
     * (info + arena span) is meaningful (ADR-0008). */
    unsigned long arena_size = 0;
    unsigned char *arena = (unsigned char *)bbp_l01_arena_base(&arena_size);
    if (!arena || arena_size <= sizeof(struct bbp_info))
        return BBP_ERR_SIZE;

    struct bbp_info *info = (struct bbp_info *)arena;
    for (unsigned long i = 0; i < arena_size; i++)
        arena[i] = 0;

    /* Tag region begins just past the info struct. Its TRUE physical is the
     * arena's physical (== virtual here, HHDM 0). One alias. */
    unsigned char *tagbase = arena + sizeof(struct bbp_info);
    uint64_t tagbase_phys = bbp_l01_virt_to_phys((uint64_t)(uintptr_t)tagbase);
    /* NOTE: tagbase_phys may legitimately be 0 only if the arena sits at the
     * very bottom of physical RAM AND HHDM is 0 AND sizeof(bbp_info)==0, which
     * cannot happen (bbp_info is 144 bytes). A static arena never starts at
     * phys 0 on linux-0.01 (BSS is well above the page tables). */

    struct bbp_builder b;
    bbp_builder_init(&b, tagbase, (bbp_phys_t)tagbase_phys,
                     arena_size - sizeof(struct bbp_info));

    /* --- HHDM first: documents the identity map (offset 0) -------------- */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h)
        h->offset = bi->hhdm_offset;

    /* --- MEMORY_MAP (the kernel's fixed RAM model) --------------------- */
    if (bi->mmap && bi->mmap_count) {
        size_t total = sizeof(struct bbp_tag_memory_map)
                     + (size_t)bi->mmap_count * sizeof(struct bbp_memory_entry);
        struct bbp_tag_memory_map *mm =
            bbp_alloc_tag(&b, BBP_TAG_MEMORY_MAP, 1, total);
        if (mm) {
            mm->entry_count = bi->mmap_count;
            mm->entry_size  = sizeof(struct bbp_memory_entry);
            struct bbp_memory_entry *ent =
                (struct bbp_memory_entry *)bbp_tag_payload(&mm->header,
                                            sizeof(struct bbp_tag_memory_map));
            for (uint32_t i = 0; i < bi->mmap_count; i++) {
                uint32_t bt = bi->mmap[i].type;   /* already a BBP_MEM_* class */
                ent[i].base       = bi->mmap[i].base;
                ent[i].length     = bi->mmap[i].length;
                ent[i].type       = bt;
                ent[i].attributes = bbp_mem_default_attrs(bt);
                ent[i].numa_node  = 0;
                ent[i].reserved   = 0;
            }
        }
    }

    /* --- KERNEL_ADDRESS ------------------------------------------------ */
    if (bi->have_kernel_address) {
        struct bbp_tag_kernel_address *ka =
            bbp_alloc_tag(&b, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*ka));
        if (ka) {
            ka->physical_base = bi->kernel_phys_base;
            ka->virtual_base  = bi->kernel_virt_base;
        }
    }

    /* --- finalize: seal every tag CRC + info CRC ----------------------- */
    bbp_phys_t info_phys = (bbp_phys_t)tagbase_phys - (bbp_phys_t)sizeof(struct bbp_info);
    bbp_builder_finalize(&b, info, info_phys);
    if (b.overflow)
        return BBP_ERR_SIZE;

    /* linux-0.01 is identity-mapped (HHDM 0): the INFO physical IS its valid
     * virtual. Seed the parser with offset 0 via bbp_init (SPEC §10.1(a)). */
    const struct bbp_info *info_virt =
        (const struct bbp_info *)osif->phys_to_virt(info_phys);

    return bbp_init(out, info_virt);
}
