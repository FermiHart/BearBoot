/*
 * adapter.c — native Linux -> Bear Boot Protocol adapter for TinaLinux (REAL).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Synthesizes a bbp_info + tag list from the boot data the NATIVE Linux boot
 * path discovered (e820, ACPI RSDP, kernel slide, cmdline), then validates it
 * through the frozen BBP core parser. TinaLinux is already on its own higher-
 * half page tables when this runs, so we follow SPEC §10.1(b):
 *   - every tag pointer stored is a TRUE PHYSICAL address (the builder writes
 *     arena_phys + offset; arena_phys is __pa(arena) because the arena lives in
 *     the Linux direct map — see the dual-alias note below);
 *   - bbp_init_ex is seeded with the HHDM offset (page_offset_base) so the
 *     parser translates those physicals back through __va and walks the list.
 *
 * DUAL-ALIAS NOTE (why this port is simpler than MINIX's): the scratch arena is
 * NOT a kernel-image symbol here; the glue allocates it with __get_free_pages,
 * so it sits in the direct map. Therefore arena_phys == __pa(arena) == arena -
 * page_offset_base, the SAME linear relation as phys_to_virt. There is only one
 * alias; the classic "kernel-image vs HHDM" arena bug cannot occur.
 *
 * Tags produced:
 *   HHDM           (mandatory — drives all later translation)
 *   MEMORY_MAP     (e820, RAW E820_TYPE_* -> BBP_MEM_*, with R/W attrs)
 *   KERNEL_ADDRESS (phys_base / _text)
 *   ACPI           (acpi_os_get_root_pointer RSDP)
 *   CMDLINE        (saved_command_line, copied into arena, string_crc sealed)
 *
 * No libc, no <linux/...> headers: compiles for `make scaffold-check`, links into the
 * standalone harness, and drops into TinaLinux unchanged.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../../bootloader/bbp_build.h"
#include "../../kernel/bbp_kernel.h"
#include "osif.h"
#include "adapter.h"

/* Map a RAW Linux E820_TYPE_* to a BBP_MEM_* class. Values mirror
 * arch/x86/include/asm/e820/types.h. Unknown -> RESERVED (never treat unknown
 * memory as free RAM). */
static uint32_t e820_type_to_bbp(uint32_t e820_type)
{
    switch (e820_type) {
    case 1:           return BBP_MEM_USABLE;            /* E820_TYPE_RAM            */
    case 2:           return BBP_MEM_RESERVED;          /* E820_TYPE_RESERVED       */
    case 3:           return BBP_MEM_ACPI_RECLAIMABLE;  /* E820_TYPE_ACPI           */
    case 4:           return BBP_MEM_ACPI_NVS;          /* E820_TYPE_NVS            */
    case 5:           return BBP_MEM_BAD_MEMORY;        /* E820_TYPE_UNUSABLE       */
    case 7:           return BBP_MEM_PERSISTENT;        /* E820_TYPE_PMEM           */
    case 12:          return BBP_MEM_PERSISTENT;        /* E820_TYPE_PRAM           */
    case 128:         return BBP_MEM_KERNEL_AND_MODULES;/* E820_TYPE_RESERVED_KERN  */
    case 0xefffffffu: return BBP_MEM_SOFT_RESERVED;     /* E820_TYPE_SOFT_RESERVED  */
    default:          return BBP_MEM_RESERVED;
    }
}

static uint32_t bbp_mem_default_attrs(uint32_t bbp_type)
{
    switch (bbp_type) {
    case BBP_MEM_USABLE:
    case BBP_MEM_BOOTLOADER_RECLAIM:
    case BBP_MEM_ACPI_RECLAIMABLE:
    case BBP_MEM_KERNEL_AND_MODULES:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_CACHED;
    case BBP_MEM_PERSISTENT:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE;
    default:
        return BBP_MEM_ATTR_READABLE;
    }
}

bbp_status_t bbp_tina_adapter(struct bbp_kctx *out,
                              const struct bbp_tina_bootinfo *bi)
{
    if (!out || !bi)
        return BBP_ERR_NULL;

    const struct bbp_osif *osif = bbp_tina_osif();

    /* Make the OSIF coherent with the data we synthesize: HHDM drives
     * phys_to_virt; the kernel slide feeds the KERNEL_ADDRESS tag. */
    bbp_tina_set_hhdm(bi->hhdm_offset);
    if (bi->have_kernel_address)
        bbp_tina_set_kslide(bi->kernel_phys_base, bi->kernel_virt_base);

    /* Scratch arena from the OSIF; carve bbp_info off its front so info_size
     * (info + arena span) is meaningful (ADR-0008). */
    unsigned long arena_size = 0;
    unsigned char *arena = (unsigned char *)bbp_tina_arena_base(&arena_size);
    if (!arena || arena_size <= sizeof(struct bbp_info))
        return BBP_ERR_SIZE;

    struct bbp_info *info = (struct bbp_info *)arena;
    for (unsigned long i = 0; i < arena_size; i++)
        arena[i] = 0;

    /* Tag region begins just past the info struct. Its TRUE physical is the
     * arena's direct-map physical (arena_virt - hhdm == __pa). One alias. */
    unsigned char *tagbase = arena + sizeof(struct bbp_info);
    uint64_t tagbase_phys = bbp_tina_virt_to_phys((uint64_t)(uintptr_t)tagbase);
    if (tagbase_phys == 0)
        return BBP_ERR_SIZE;

    struct bbp_builder b;
    bbp_builder_init(&b, tagbase, (bbp_phys_t)tagbase_phys,
                     arena_size - sizeof(struct bbp_info));

    /* --- HHDM first: it drives all later translation -------------------- */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h)
        h->offset = bi->hhdm_offset;

    /* --- MEMORY_MAP (e820) --------------------------------------------- */
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
                uint32_t bt = e820_type_to_bbp(bi->mmap[i].type);
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

    /* --- ACPI ---------------------------------------------------------- */
    if (bi->rsdp_phys) {
        struct bbp_tag_acpi *ac = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*ac));
        if (ac) {
            ac->rsdp_address = bi->rsdp_phys;
            ac->xsdt_address = 0;       /* unknown without parsing the RSDP */
            ac->oem_id       = 0;
            ac->acpi_version = 0;
            ac->flags        = 0;
        }
    }

    /* --- CMDLINE (out-of-line string + string_crc, ADR-0006) ----------- */
    if (bi->cmdline && bi->cmdline[0]) {
        struct bbp_tag_cmdline *cl =
            bbp_alloc_tag(&b, BBP_TAG_CMDLINE, 1, sizeof(*cl));
        if (cl) {
            uint32_t len = 0;
            bbp_phys_t sphys = bbp_arena_strdup(&b, bi->cmdline, &len);
            cl->string = sphys;
            cl->length = len;
            cl->flags  = 0;
            if (sphys) {
                const char *copy =
                    (const char *)(tagbase + (size_t)(sphys - (bbp_phys_t)tagbase_phys));
                cl->string_crc = bbp_crc64(copy, len);
            } else {
                cl->string_crc = 0;
            }
        }
    }

    /* --- finalize: seal every tag CRC + info CRC ----------------------- */
    bbp_builder_finalize(&b, info, (bbp_phys_t)tagbase_phys
                                   - (bbp_phys_t)(sizeof(struct bbp_info)));
    if (b.overflow)
        return BBP_ERR_SIZE;

    /* TinaLinux is on its own page tables; pass the INFO as its HHDM-virtual
     * alias and seed the parser with the HHDM offset (SPEC §10.1(b)). */
    bbp_phys_t info_phys = (bbp_phys_t)tagbase_phys - sizeof(struct bbp_info);
    const struct bbp_info *info_hhdm =
        (const struct bbp_info *)osif->phys_to_virt(info_phys);

    return bbp_init_ex(out, info_hhdm, bi->hhdm_offset);
}
