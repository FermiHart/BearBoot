/*
 * adapter.h — native Linux -> Bear Boot Protocol adapter interface for TinaLinux.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The adapter synthesizes a BBP bbp_info + tag list from the boot data the
 * NATIVE Linux boot path already discovered (e820 firmware memory map, ACPI
 * RSDP, kernel slide, boot cmdline), then validates it with the frozen BBP core
 * parser. TinaLinux is already on its own higher-half page tables when this
 * runs, so it follows SPEC §10.1(b): tag pointers are TRUE physicals and the
 * parser is seeded with the HHDM offset (page_offset_base) via bbp_init_ex.
 *
 * To stay decoupled from <linux/...> headers (so this file also compiles standalone for
 * `make scaffold-check` and the harness), the caller does NOT pass Linux
 * structs. It fills the neutral `struct bbp_tina_bootinfo` from the Linux
 * globals (a few field copies — see integration.md and test/harness.c) and
 * passes that. One translation point, no hidden ABI coupling.
 */
#ifndef BBP_PORT_TINALINUX_ADAPTER_H
#define BBP_PORT_TINALINUX_ADAPTER_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* One memory-map entry, already decoded from an e820_entry. `type` is the RAW
 * Linux E820_TYPE_* value; the adapter maps it to BBP_MEM_*. */
struct bbp_tina_mmap_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;        /* raw E820_TYPE_* */
};

/* Neutral snapshot of everything the adapter needs from the Linux boot path.
 * The caller copies these out of the kernel globals. A zero/NULL field means
 * "not provided" and the adapter omits that tag (except HHDM, mandatory). */
struct bbp_tina_bootinfo {
    /* HHDM (mandatory). On Linux this is page_offset_base; __va == phys+offset
     * over all direct-mapped RAM. */
    bbp_virt_t hhdm_offset;

    /* Kernel slide: phys_base and the kernel virtual base (_text). Feeds the
     * KERNEL_ADDRESS tag (undo-KASLR / symbol resolution for a consumer). */
    uint64_t   kernel_phys_base;
    bbp_virt_t kernel_virt_base;
    int        have_kernel_address;

    /* e820 memory map. `mmap` points to caller-owned storage valid for the
     * duration of the call. */
    const struct bbp_tina_mmap_entry *mmap;
    uint32_t   mmap_count;

    /* ACPI RSDP physical (acpi_os_get_root_pointer()). 0 = none. */
    uint64_t   rsdp_phys;

    /* Command line (saved_command_line). NUL-terminated, caller-owned; the
     * adapter copies it into the arena and seals string_crc. NULL => omit. */
    const char *cmdline;
};

/* Build + validate a BBP context from `bi`. On BBP_OK, *out is a validated
 * kctx the kernel can query with bbp_find_tag()/bbp_for_each_tag(). The HHDM
 * offset is pushed into the OSIF (bbp_tina_set_hhdm) and the kernel slide
 * (bbp_tina_set_kslide) so OSIF phys_to_virt/alloc are coherent with the data
 * just built. Returns a bbp_status_t (BBP_OK on success). */
bbp_status_t bbp_tina_adapter(struct bbp_kctx *out,
                              const struct bbp_tina_bootinfo *bi);

#endif /* BBP_PORT_TINALINUX_ADAPTER_H */
