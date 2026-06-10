/*
 * adapter.h — Limine -> Bear Boot Protocol adapter for Josh-Bear.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Synthesizes a BBP bbp_info + tag list from the boot data Limine handed Josh,
 * then validates it through the frozen BBP core parser. Josh is already on its
 * own higher-half page tables when this runs (SPEC §10.1(b)): tag pointers are
 * TRUE physicals (the OSIF arena is allocated from Josh's PMM, so its physical
 * is known directly), and the parser is seeded with the HHDM offset.
 *
 * To keep adapter.c freestanding (no Josh headers, so it builds in the bearboot
 * scaffold + standalone harness), the caller does NOT pass Limine structs. The
 * Josh glue (josh_glue.c, which DOES include Josh's limine.h) fills the neutral
 * `struct bbp_josh_bootinfo` from the limine_get_*() accessors and passes it.
 * One translation point, no hidden ABI coupling — same discipline as ports/minix.
 */
#ifndef BBP_PORT_JOSH_ADAPTER_H
#define BBP_PORT_JOSH_ADAPTER_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* One memory-map entry decoded from a Limine memmap entry. `type` is the RAW
 * Limine type (LIMINE_MEMMAP_*); the adapter maps it to BBP_MEM_*. */
struct bbp_josh_mmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;        /* raw Limine memmap type (0..7) */
};

/* One CPU decoded from a Limine SMP response entry. */
struct bbp_josh_cpu {
    uint32_t processor_id;   /* ACPI processor id */
    uint32_t apic_id;        /* LAPIC id */
};

/* Neutral snapshot of everything the adapter needs from Limine. The Josh glue
 * copies these out of the Limine responses. A zero/NULL field means "Limine did
 * not provide it" and the adapter omits that tag — except HHDM, mandatory for a
 * higher-half handoff. */
struct bbp_josh_bootinfo {
    /* HHDM (mandatory). virt = phys + hhdm_offset over all RAM. */
    bbp_virt_t hhdm_offset;

    /* Memory map. `mmap` points to caller-owned storage valid for the call. */
    const struct bbp_josh_mmap_entry *mmap;
    uint32_t   mmap_count;

    /* Framebuffer (optional). fb_address==0 => omit. */
    uint64_t   fb_address;
    uint32_t   fb_pitch;
    uint16_t   fb_width;
    uint16_t   fb_height;
    uint16_t   fb_bpp;
    uint16_t   fb_pixel_format;   /* BBP_FB_* (0 => RGB888 default) */

    /* SMP (optional). cpu_count==0 => omit. Josh is multicore; the minix port
     * never emitted this tag — it is the clearest Josh-specific addition. */
    const struct bbp_josh_cpu *cpus;
    uint32_t   cpu_count;
    uint32_t   bsp_id;

    /* Command line (optional). NUL-terminated, caller-owned; copied into the
     * arena with its string_crc sealed. NULL => omit. */
    const char *cmdline;

    /* Boot entropy (optional). Caller-owned CSPRNG seed gathered from the best
     * hardware source available (RDSEED > RDRAND > TSC jitter). The adapter
     * copies it into the arena and emits a BBP_TAG_SECURITY whose entropy_data
     * carries it with entropy_crc sealed (ADR-0006). entropy==NULL/len==0 =>
     * omit the SECURITY tag. This is the boot root-of-trust seed: the consumer
     * verifies entropy_crc, then seeds its kernel CSPRNG (and, later, the
     * capability HMAC keys) from it. */
    const uint8_t *entropy;
    uint32_t       entropy_len;
};

/* Build + validate a BBP context from `bi`. On BBP_OK, *out is a validated kctx
 * the kernel queries with bbp_find_tag()/bbp_for_each_tag(). Returns a
 * bbp_status_t (BBP_OK on success). */
bbp_status_t bbp_josh_adapter(struct bbp_kctx *out,
                              const struct bbp_josh_bootinfo *bi);

#endif /* BBP_PORT_JOSH_ADAPTER_H */
