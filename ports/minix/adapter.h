/*
 * adapter.h — Limine -> Bear Boot Protocol adapter interface for MINIX.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The adapter synthesizes a BBP bbp_info + tag list from the boot data Limine
 * handed MINIX, then validates it with the frozen BBP core parser. It runs
 * INSIDE MINIX, which is already on its own higher-half page tables, so it
 * follows SPEC §10.1(b): tag pointers are TRUE physicals and the parser is
 * seeded with the HHDM offset (bbp_init_ex).
 *
 * To stay decoupled from the MINIX-private / -nostdinc limine.h (and so this
 * file compiles standalone for `make scaffold-check` and the test harness),
 * the caller does NOT pass Limine structs. It fills the neutral
 * `struct bbp_minix_bootinfo` below from the Limine responses (a few field
 * copies — see integration.md and test/harness.c for the exact mapping) and
 * passes that. One translation point, no hidden ABI coupling.
 */
#ifndef BBP_PORT_MINIX_ADAPTER_H
#define BBP_PORT_MINIX_ADAPTER_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* One memory-map entry, already decoded from a Limine memmap entry. `type` is
 * the RAW Limine type (LIMINE_MEMMAP_*); the adapter maps it to BBP_MEM_*. */
struct bbp_minix_mmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;        /* raw Limine memmap type (0..7) */
};

/* Neutral snapshot of everything the adapter needs from Limine. The caller
 * copies these out of the Limine responses. A zero/NULL field means "Limine
 * did not provide it" and the adapter simply omits that tag (except HHDM,
 * which is mandatory for a higher-half handoff). */
struct bbp_minix_bootinfo {
    /* HHDM (mandatory). virt = phys + hhdm_offset over all RAM. */
    bbp_virt_t hhdm_offset;

    /* Kernel address (Limine kernel-address response). Needed both for the
     * KERNEL_ADDRESS tag and for the arena's true-physical computation. */
    uint64_t   kernel_phys_base;
    bbp_virt_t kernel_virt_base;
    int        have_kernel_address;

    /* Memory map. `entries` points to caller-owned storage that stays valid
     * for the duration of the adapter call. */
    const struct bbp_minix_mmap_entry *mmap;
    uint32_t   mmap_count;

    /* ACPI RSDP physical address (Limine rsdp response, API rev 0/1). 0=none. */
    uint64_t   rsdp_phys;

    /* Framebuffer (optional). All zero / fb_address==0 => omit the tag. */
    uint64_t   fb_address;
    uint32_t   fb_pitch;
    uint16_t   fb_width;
    uint16_t   fb_height;
    uint16_t   fb_bpp;
    uint16_t   fb_pixel_format;   /* BBP_FB_* already chosen by caller, 0=RGB888 default */

    /* Command line (optional). NUL-terminated, caller-owned; the adapter
     * copies it into the arena and seals its string_crc. NULL => omit. */
    const char *cmdline;

    /* SMP / MP topology (optional). The adapter emits a BBP_TAG_SMP carrying
     * cpu_count entries when cpu_count > 0. lapic_ids points to caller-owned
     * storage valid for the call; entry i becomes cpu_info[i].apic_id. A
     * uniprocessor boot (cpu_count==1) still produces a valid 1-entry tag. */
    uint32_t        cpu_count;
    uint32_t        bsp_lapic_id;
    const uint32_t *lapic_ids;     /* cpu_count entries, or NULL */
    int             x2apic;        /* 1 if x2APIC mode */
};

/* Build + validate a BBP context from `bi`. On BBP_OK, *out is a validated
 * kctx the kernel can query with bbp_find_tag()/bbp_for_each_tag(). The HHDM
 * offset is also pushed into the OSIF (bbp_minix_set_hhdm) and the kernel
 * slide (bbp_minix_set_kslide) so OSIF phys_to_virt / alloc_pages are coherent
 * with the data just built. Returns a bbp_status_t (BBP_OK on success). */
bbp_status_t bbp_minix_adapter(struct bbp_kctx *out,
                               const struct bbp_minix_bootinfo *bi);

#endif /* BBP_PORT_MINIX_ADAPTER_H */
