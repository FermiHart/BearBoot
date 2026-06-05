/*
 * adapter.c — Limine -> Bear Boot Protocol adapter for Josh-Bear (REAL).
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Synthesizes a bbp_info + tag list from the boot data Limine handed Josh, then
 * validates it through the frozen BBP core parser. Josh is already on its own
 * higher-half page tables when this runs (SPEC §10.1(b)):
 *   - the OSIF arena comes from Josh's PMM (pmm_alloc_pages), so its TRUE
 *     physical is returned directly alongside its HHDM-virtual base — no
 *     kernel-slide computation (the minix port needs that only because it has
 *     no allocator that early);
 *   - bbp_init_ex is seeded with the HHDM offset so the parser translates the
 *     physical tag pointers back to the kernel's direct-map alias.
 *
 * Tags produced (only what Limine actually gave Josh; absent => omitted):
 *   HHDM        (mandatory — drives all later translation)
 *   MEMORY_MAP  (Limine memmap, RAW type -> BBP_MEM_*, with R/W attrs)
 *   FRAMEBUFFER (optional)
 *   SMP         (Josh is multicore; the minix port never emitted this)
 *   CMDLINE     (optional — copied into the arena, string_crc sealed)
 *
 * Freestanding: no Josh headers, no limine.h — builds in the bearboot scaffold,
 * the standalone harness, and drops into the Josh tree unchanged.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../../bootloader/bbp_build.h"
#include "../../kernel/bbp_kernel.h"
#include "osif.h"
#include "adapter.h"

/* Arena for the synthesized info + tags. 64 KiB is ample: a large memory map
 * (~200 entries × 32 B) + framebuffer + SMP (~256 CPUs × 48 B) + cmdline still
 * fits with headroom. Allocated once from the PMM, never freed. */
#define BBP_JOSH_ARENA_BYTES (64u * 1024u)

/* Map a RAW Limine memmap type to a BBP_MEM_* class. Limine's 0..7 enum is in
 * the kernel's limine.h (LIMINE_MEMMAP_*). Unknown => conservatively RESERVED,
 * so the consumer never treats unknown memory as free RAM. */
static uint32_t limine_memtype_to_bbp(uint64_t lim_type)
{
    switch (lim_type) {
    case 0:  return BBP_MEM_USABLE;             /* LIMINE_MEMMAP_USABLE             */
    case 1:  return BBP_MEM_RESERVED;           /* LIMINE_MEMMAP_RESERVED           */
    case 2:  return BBP_MEM_ACPI_RECLAIMABLE;   /* LIMINE_MEMMAP_ACPI_RECLAIMABLE   */
    case 3:  return BBP_MEM_ACPI_NVS;           /* LIMINE_MEMMAP_ACPI_NVS           */
    case 4:  return BBP_MEM_BAD_MEMORY;         /* LIMINE_MEMMAP_BAD_MEMORY         */
    case 5:  return BBP_MEM_BOOTLOADER_RECLAIM; /* LIMINE_MEMMAP_BOOTLOADER_RECLAIM */
    case 6:  return BBP_MEM_KERNEL_AND_MODULES; /* LIMINE_MEMMAP_KERNEL_AND_MODULES */
    case 7:  return BBP_MEM_FRAMEBUFFER;        /* LIMINE_MEMMAP_FRAMEBUFFER        */
    default: return BBP_MEM_RESERVED;
    }
}

/* Per-type default attributes — best-effort, honestly-labeled metadata; the BBP
 * core never interprets these, it passes them through for the consumer. */
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

bbp_status_t bbp_josh_adapter(struct bbp_kctx *out,
                              const struct bbp_josh_bootinfo *bi)
{
    if (!out || !bi)
        return BBP_ERR_NULL;

    const struct bbp_osif *osif = bbp_josh_osif();
    if (!osif->alloc_pages)
        return BBP_ERR_NULL;

    /* One PMM-backed arena: bbp_info at the front, tag region after it. The
     * allocator hands back the HHDM-virtual base AND the TRUE physical, so the
     * info's physical is exactly arena_phys and the tag region's is
     * arena_phys + sizeof(info) — no slide math (ADR-0008 contiguity holds). */
    uint64_t arena_phys = 0;
    unsigned char *arena = (unsigned char *)osif->alloc_pages(BBP_JOSH_ARENA_BYTES,
                                                              &arena_phys);
    if (!arena || arena_phys == 0)
        return BBP_ERR_SIZE;

    for (unsigned long i = 0; i < BBP_JOSH_ARENA_BYTES; i++)
        arena[i] = 0;

    struct bbp_info *info = (struct bbp_info *)arena;   /* HHDM-virtual alias */
    unsigned char   *tagbase      = arena + sizeof(struct bbp_info);
    bbp_phys_t       tagbase_phys = (bbp_phys_t)arena_phys + sizeof(struct bbp_info);

    struct bbp_builder b;
    bbp_builder_init(&b, tagbase, tagbase_phys,
                     BBP_JOSH_ARENA_BYTES - sizeof(struct bbp_info));

    /* --- HHDM first: it drives all later translation ------------------- */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h)
        h->offset = bi->hhdm_offset;

    /* --- MEMORY_MAP --------------------------------------------------- */
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

    /* --- FRAMEBUFFER (optional) --------------------------------------- */
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

    /* --- SMP (optional, Josh-specific: multicore topology) ------------- */
    if (bi->cpus && bi->cpu_count) {
        size_t total = sizeof(struct bbp_tag_smp)
                     + (size_t)bi->cpu_count * sizeof(struct bbp_cpu_info);
        struct bbp_tag_smp *smp = bbp_alloc_tag(&b, BBP_TAG_SMP, 1, total);
        if (smp) {
            smp->cpu_count = bi->cpu_count;
            smp->bsp_id    = bi->bsp_id;
            smp->flags     = 0;
            struct bbp_cpu_info *ci =
                (struct bbp_cpu_info *)bbp_tag_payload(&smp->header,
                                            sizeof(struct bbp_tag_smp));
            for (uint32_t i = 0; i < bi->cpu_count; i++) {
                ci[i].processor_id   = bi->cpus[i].processor_id;
                ci[i].apic_id        = bi->cpus[i].apic_id;
                ci[i].state          = (bi->cpus[i].apic_id == bi->bsp_id)
                                       ? BBP_CPU_STATE_RUNNING
                                       : BBP_CPU_STATE_STOPPED;
                ci[i].flags          = 0;
                ci[i].package_id     = 0;
                ci[i].core_id        = 0;
                ci[i].thread_id      = 0;
                ci[i].numa_node      = 0;
                ci[i].capabilities   = 0;
                ci[i].clock_frequency = 0;
                ci[i].wakeup_vector  = 0;
                ci[i].extra_argument = 0;
            }
        }
    }

    /* --- SECURITY (optional: boot entropy = root-of-trust seed) -------- *
     * Only the entropy fields are populated (no TPM/measured-boot in v1). The
     * seed is copied into the arena as an out-of-line blob and entropy_crc is
     * sealed so the consumer can bbp_verify_blob() it before seeding its CSPRNG
     * (ADR-0006). */
    if (bi->entropy && bi->entropy_len) {
        struct bbp_tag_security *se =
            bbp_alloc_tag(&b, BBP_TAG_SECURITY, 1, sizeof(*se));
        if (se) {
            bbp_phys_t ephys = bbp_arena_blob(&b, bi->entropy, bi->entropy_len);
            se->entropy_size = bi->entropy_len;
            se->entropy_data = ephys;
            if (ephys) {
                const uint8_t *copy =
                    (const uint8_t *)(tagbase + (size_t)(ephys - tagbase_phys));
                se->entropy_crc = bbp_crc64(copy, bi->entropy_len);
            } else {
                se->entropy_size = 0;
                se->entropy_crc  = 0;
            }
            /* TPM / secure-boot / measurements: none in v1 (left zeroed). */
        }
    }

    /* --- CMDLINE (optional, out-of-line string + string_crc) ---------- */
    if (bi->cmdline && bi->cmdline[0]) {
        struct bbp_tag_cmdline *cl =
            bbp_alloc_tag(&b, BBP_TAG_CMDLINE, 1, sizeof(*cl));
        if (cl) {
            uint32_t len = 0;
            bbp_phys_t sphys = bbp_arena_strdup(&b, bi->cmdline, &len);
            cl->string = sphys;
            cl->length = len;
            cl->flags  = 0;
            /* ADR-0006: seal the string CRC so the consumer can bbp_verify_blob()
             * it. The copy lives at (sphys - tagbase_phys) past tagbase; CRC those
             * exact bytes — the same the consumer reads via the HHDM alias. */
            if (sphys) {
                const char *copy =
                    (const char *)(tagbase + (size_t)(sphys - tagbase_phys));
                cl->string_crc = bbp_crc64(copy, len);
            } else {
                cl->string_crc = 0;
            }
        }
    }

    /* --- finalize: seal every tag CRC + info CRC ---------------------- */
    bbp_builder_finalize(&b, info, (bbp_phys_t)arena_phys);
    if (b.overflow)
        return BBP_ERR_SIZE;

    /* `info` is already the HHDM-virtual alias (alloc_pages returned phys+hhdm),
     * so pass it straight to the parser and seed the HHDM offset (SPEC §10.1(b)).
     * Bound the parser's walk to the arena region (ADR-0009): every tag pointer
     * must lie within [arena_phys, arena_phys + arena_bytes), so a corrupt
     * next_tag is rejected as corruption instead of faulting on unmapped RAM. */
    return bbp_init_win(out, info, bi->hhdm_offset,
                        (bbp_phys_t)arena_phys,
                        (bbp_phys_t)arena_phys + BBP_JOSH_ARENA_BYTES);
}
