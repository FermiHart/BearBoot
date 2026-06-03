/*
 * adapter.h — native linux-0.01 -> Bear Boot Protocol adapter interface.
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The adapter synthesizes a BBP bbp_info + tag list from the boot data Linus'
 * 1991 kernel actually has — a FIXED RAM model (config.h HIGH_MEMORY, with the
 * 640K-1M hole reserved) and the fact that it is loaded + linked at physical 0
 * and runs identity-mapped — then validates it with the frozen BBP core parser.
 *
 * linux-0.01 is IDENTITY-mapped when this runs (pg_dir = 0 maps the first
 * 8 MiB; mm/memory.c), so this follows SPEC §10.1(a): every tag pointer stored
 * is a TRUE physical that is ALSO a valid virtual (offset 0), and the parser is
 * seeded with HHDM 0 via bbp_init — no bbp_init_ex needed.
 *
 * To stay decoupled from kernel headers (so this file also compiles standalone
 * for `make scaffold-check` and the harness), the caller does NOT pass kernel
 * structs. It fills the neutral `struct bbp_l01_bootinfo` from the kernel's
 * compile-time constants (HIGH_MEMORY etc.) and passes that. One translation
 * point, no hidden ABI coupling.
 */
#ifndef BBP_PORT_LINUX01_ADAPTER_H
#define BBP_PORT_LINUX01_ADAPTER_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* One memory-map entry the caller derives from the kernel's RAM model. `type`
 * is a RAW BBP_MEM_* class already (linux-0.01 has no firmware map to decode;
 * the caller knows directly which ranges are RAM vs reserved). */
struct bbp_l01_mmap_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;        /* BBP_MEM_* directly (no firmware decode step) */
};

/* Neutral snapshot of everything the adapter needs from linux-0.01. A zero/NULL
 * field means "not provided" and the adapter omits that tag (except HHDM, which
 * is mandatory — and on linux-0.01 is always 0). */
struct bbp_l01_bootinfo {
    /* HHDM (mandatory). On linux-0.01 this is 0: identity map, virt == phys. */
    bbp_virt_t hhdm_offset;

    /* Kernel slide. On linux-0.01 both are 0 (linked AND loaded at physical 0).
     * Feeds the KERNEL_ADDRESS tag. Set have_kernel_address to emit it. */
    uint64_t   kernel_phys_base;
    bbp_virt_t kernel_virt_base;
    int        have_kernel_address;

    /* Memory map. `mmap` points to caller-owned storage valid for the duration
     * of the call. Built from config.h HIGH_MEMORY + the 640K-1M hole. */
    const struct bbp_l01_mmap_entry *mmap;
    uint32_t   mmap_count;
};

/* Build + validate a BBP context from `bi`. On BBP_OK, *out is a validated
 * kctx the kernel can query with bbp_find_tag()/bbp_for_each_tag(). The HHDM
 * offset is pushed into the OSIF (bbp_l01_set_hhdm) and the kernel slide
 * (bbp_l01_set_kslide) so OSIF phys_to_virt/alloc are coherent with the data
 * just built. Returns a bbp_status_t (BBP_OK on success). */
bbp_status_t bbp_l01_adapter(struct bbp_kctx *out,
                             const struct bbp_l01_bootinfo *bi);

#endif /* BBP_PORT_LINUX01_ADAPTER_H */
