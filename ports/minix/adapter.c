/*
 * adapter.c — Limine -> Bear Boot Protocol adapter for MINIX (REAL).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Synthesizes a bbp_info + tag list from the boot data Limine handed MINIX,
 * then validates it through the frozen BBP core parser. MINIX is already on its
 * own higher-half page tables when this runs, so we follow SPEC §10.1(b):
 *   - every tag pointer stored is a TRUE PHYSICAL address (the builder writes
 *     arena_phys + offset; arena_phys is computed from the kernel slide);
 *   - bbp_init_ex is seeded with the HHDM offset so the parser can translate
 *     those physicals back to the kernel's direct-map alias and walk the list.
 *
 * Tags produced:
 *   HHDM           (mandatory — drives all later translation)
 *   MEMORY_MAP     (Limine memmap, RAW type -> BBP_MEM_*, with R/W attrs)
 *   KERNEL_ADDRESS (Limine kernel-address)
 *   ACPI           (Limine RSDP)
 *   FRAMEBUFFER    (optional — only if Limine gave one)
 *   CMDLINE        (optional — copied into the arena, string_crc sealed)
 *
 * No libc, no MINIX headers, no limine.h: compiles for `make scaffold-check`,
 * links into the standalone test harness, and drops into MINIX unchanged.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../../bootloader/bbp_build.h"
#include "../../kernel/bbp_kernel.h"
#include "osif.h"
#include "adapter.h"

/* Map a RAW Limine memmap type to a BBP_MEM_* class. Limine's 0..7 enum is
 * documented in minix/kernel/boot/limine/limine.h (LIMINE_MEMMAP_*). Anything
 * unrecognized is conservatively RESERVED so the consumer never treats unknown
 * memory as free RAM. */
static uint32_t limine_memtype_to_bbp(uint64_t lim_type)
{
    switch (lim_type) {
    case 0:  return BBP_MEM_USABLE;             /* LIMINE_MEMMAP_USABLE              */
    case 1:  return BBP_MEM_RESERVED;           /* LIMINE_MEMMAP_RESERVED            */
    case 2:  return BBP_MEM_ACPI_RECLAIMABLE;   /* LIMINE_MEMMAP_ACPI_RECLAIMABLE    */
    case 3:  return BBP_MEM_ACPI_NVS;           /* LIMINE_MEMMAP_ACPI_NVS            */
    case 4:  return BBP_MEM_BAD_MEMORY;         /* LIMINE_MEMMAP_BAD_MEMORY          */
    case 5:  return BBP_MEM_BOOTLOADER_RECLAIM; /* LIMINE_MEMMAP_BOOTLOADER_RECLAIM. */
    case 6:  return BBP_MEM_KERNEL_AND_MODULES; /* LIMINE_MEMMAP_KERNEL_AND_MODULES  */
    case 7:  return BBP_MEM_FRAMEBUFFER;        /* LIMINE_MEMMAP_FRAMEBUFFER         */
    default: return BBP_MEM_RESERVED;
    }
}

/* Per-type default attributes. Usable + reclaimable RAM is R/W/cached; ACPI/
 * reserved/bad get R only; the framebuffer region gets R/W/write-combine. The
 * BBP core does not interpret these — they are passed through for the consumer
 * — so this is best-effort metadata, honestly labeled. */
static uint32_t bbp_mem_default_attrs(uint32_t bbp_type)
{
    switch (bbp_type) {
    case BBP_MEM_USABLE:
    case BBP_MEM_BOOTLOADER_RECLAIM:
    case BBP_MEM_ACPI_RECLAIMABLE:
    case BBP_MEM_KERNEL_AND_MODULES:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_CACHED;
    case BBP_MEM_FRAMEBUFFER:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_WRITE_COMBINE;
    default:
        return BBP_MEM_ATTR_READABLE;
    }
}

bbp_status_t bbp_minix_adapter(struct bbp_kctx *out,
                               const struct bbp_minix_bootinfo *bi)
{
    if (!out || !bi)
        return BBP_ERR_NULL;

    const struct bbp_osif *osif = bbp_minix_osif();

    /* Make the OSIF coherent with the data we are about to synthesize:
     *  - HHDM drives phys_to_virt (the parser's translation alias);
     *  - the kernel slide lets alloc_pages turn the arena's kernel-image
     *    address into the TRUE physical the builder must store in tags. */
    bbp_minix_set_hhdm(bi->hhdm_offset);
    if (bi->have_kernel_address)
        bbp_minix_set_kslide(bi->kernel_phys_base, bi->kernel_virt_base);

    /* Grab the scratch arena from the OSIF and carve the bbp_info off its
     * front so info_size (info + arena span) is meaningful (ADR-0008). */
    unsigned long arena_size = 0;
    unsigned char *arena = (unsigned char *)bbp_minix_arena_base(&arena_size);
    if (!arena || arena_size <= sizeof(struct bbp_info))
        return BBP_ERR_SIZE;

    struct bbp_info *info = (struct bbp_info *)arena;
    for (unsigned long i = 0; i < arena_size; i++)
        arena[i] = 0;

    /* The tag region begins just past the info struct at the arena front. Its
     * TRUE physical (what the builder must stamp into tag pointers) comes from
     * the OSIF kernel-slide helper — the single source of truth. */
    unsigned char *tagbase = arena + sizeof(struct bbp_info);
    uint64_t tagbase_phys = bbp_minix_virt_to_phys((uint64_t)(uintptr_t)tagbase);
    if (tagbase_phys == 0)
        return BBP_ERR_SIZE;

    struct bbp_builder b;
    bbp_builder_init(&b, tagbase, (bbp_phys_t)tagbase_phys,
                     arena_size - sizeof(struct bbp_info));

    /* --- HHDM first: it drives all later translation -------------------- */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h)
        h->offset = bi->hhdm_offset;

    /* --- MEMORY_MAP ---------------------------------------------------- */
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
                uint32_t bt = limine_memtype_to_bbp(bi->mmap[i].type);
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

    /* --- FRAMEBUFFER (optional) ---------------------------------------- */
    if (bi->fb_address && bi->fb_width && bi->fb_height) {
        size_t total = sizeof(struct bbp_tag_framebuffer)
                     + sizeof(struct bbp_display_info);
        struct bbp_tag_framebuffer *fb =
            bbp_alloc_tag(&b, BBP_TAG_FRAMEBUFFER, 1, total);
        if (fb) {
            fb->address       = bi->fb_address;
            fb->display_count = 1;
            fb->flags         = 0;
            fb->pitch         = bi->fb_pitch;
            fb->total_size    = (uint64_t)bi->fb_pitch * bi->fb_height;
            fb->cursor_buffer = 0;
            fb->cursor_width  = 0;
            fb->cursor_height = 0;
            struct bbp_display_info *d =
                (struct bbp_display_info *)bbp_tag_payload(&fb->header,
                                            sizeof(struct bbp_tag_framebuffer));
            d->width        = bi->fb_width;
            d->height       = bi->fb_height;
            d->color_depth  = bi->fb_bpp ? (bi->fb_bpp / 4) : 8; /* bits/channel est. */
            d->pixel_format = bi->fb_pixel_format ? bi->fb_pixel_format
                                                  : BBP_FB_RGB888;
            d->edid_size    = 0;
            d->edid_data    = 0;
            d->edid_crc     = 0;
        }
    }

    /* --- CMDLINE (optional, out-of-line string + string_crc) ----------- */
    if (bi->cmdline && bi->cmdline[0]) {
        struct bbp_tag_cmdline *cl =
            bbp_alloc_tag(&b, BBP_TAG_CMDLINE, 1, sizeof(*cl));
        if (cl) {
            uint32_t len = 0;
            bbp_phys_t sphys = bbp_arena_strdup(&b, bi->cmdline, &len);
            cl->string = sphys;
            cl->length = len;
            cl->flags  = 0;
            /* ADR-0006: seal the out-of-line string CRC so the consumer can
             * bbp_verify_blob() it before trusting the cmdline. The string copy
             * lives in the builder arena at (sphys - tagbase_phys) bytes past
             * tagbase; CRC those exact bytes — the same the consumer reads via
             * the HHDM alias of sphys. */
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

    /* MINIX is on its own page tables; pass the INFO as its HHDM-virtual alias
     * and seed the parser with the HHDM offset (SPEC §10.1(b)). The info sits
     * at the arena front; its physical is tagbase_phys - sizeof(info). */
    bbp_phys_t info_phys = (bbp_phys_t)tagbase_phys - sizeof(struct bbp_info);
    const struct bbp_info *info_hhdm =
        (const struct bbp_info *)osif->phys_to_virt(info_phys);

    return bbp_init_ex(out, info_hhdm, bi->hhdm_offset);
}
