/*
 * osif.h — linux-0.01 port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Public surface of the linux-0.01 OSIF glue. Only files under ports/linux01/
 * may be edited; the BBP core is ABI-frozen. The OSIF wires the OS-independent
 * core to Linus' 1991 kernel (linux-0.01-modern: i386, booted by a Limine
 * bootstub that relocates the image to physical 0).
 *
 * THIS IS A NATIVE PORT, NOT A LIMINE ADAPTER. linux-0.01 does not consume
 * Limine response structs; by the time the protocol runs, the kernel is on its
 * own page tables — pg_dir at physical 0 IDENTITY-maps the first 8 MiB
 * (mm/memory.c hardcodes pg_dir = 0). So this port consumes the boot data the
 * 1991 kernel actually knows:
 *
 *   HHDM offset  = 0                        (identity map; virt == phys)
 *   memory map   = config.h HIGH_MEMORY     (the kernel's fixed RAM model)
 *   kernel base  = 0 / 0                     (loaded + linked at physical 0)
 *   ACPI RSDP    = none                      (1991 — predates ACPI)
 *   cmdline      = none                      (1991 — no boot cmdline)
 *
 * Because the map is the identity (HHDM offset 0), the handoff follows
 * SPEC §10.1(a): tag pointers are TRUE physicals that are ALSO valid virtuals,
 * so the parser is seeded with offset 0 (bbp_init), no bbp_init_ex needed.
 *
 * DESIGN — graceful binding (mirrors the tinalinux port):
 *   osif.c stays FREESTANDING (no kernel headers) so it compiles standalone for
 *   `make scaffold-check` and the hosted harness. Its OSIF primitives are
 *   __attribute__((weak)) defaults (COM1 serial / cli;hlt / static arena /
 *   rdtsc). When linked INTO the real linux-0.01 kernel, the glue TU
 *   linux01_bbp.c provides STRONG overrides bound to printk / panic. Same
 *   object, two worlds — chosen at link time, zero #ifdef in core or port.
 *
 * Why the classic BBP dual-alias bug cannot occur here:
 *   The scratch arena is a static buffer, but the kernel is IDENTITY-mapped at
 *   the call site (pg_dir = 0, first 8 MiB), so arena_phys == arena_virt: there
 *   is only one alias. The "kernel-image vs HHDM" arena hazard is structurally
 *   absent — for the simplest possible reason (HHDM offset is literally 0).
 */
#ifndef BBP_PORT_LINUX01_OSIF_H
#define BBP_PORT_LINUX01_OSIF_H

#include <bbp/bbp_osif.h>

/* Return the linux-0.01 implementation of the OSIF contract. */
const struct bbp_osif *bbp_l01_osif(void);

/* Seed the HHDM offset the OSIF uses for phys_to_virt. On linux-0.01 this is
 * always 0 (the kernel is identity-mapped: virt == phys over the first 8 MiB).
 * Kept as a setter for symmetry with the other ports and to make the value
 * explicit at the call site. Returns the offset stored. */
bbp_virt_t bbp_l01_set_hhdm(bbp_virt_t hhdm_offset);

/* The HHDM offset currently in effect (0 until bbp_l01_set_hhdm runs). */
bbp_virt_t bbp_l01_get_hhdm(void);

/* Seed the kernel slide (phys_base + virtual base). On linux-0.01 both are 0
 * (linked AND loaded at physical 0). Used only to populate KERNEL_ADDRESS. */
void bbp_l01_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base);

/* Translate a direct-map kernel-virtual address to its physical via the HHDM
 * offset (phys = virt - hhdm_offset). With HHDM 0 this is the identity. Single
 * source of truth for the arena's physical under the static-arena fallback. */
uint64_t bbp_l01_virt_to_phys(uint64_t kvirt);

/* Scratch arena base + capacity. With the weak fallback this is a static
 * buffer; a future strong glue override may return a page-allocator region.
 * The adapter carves the bbp_info off the front of this arena. */
void *bbp_l01_arena_base(unsigned long *out_size);

/* ---- OSIF override seam (the weak/strong binding contract) --------------- *
 * osif.c defines these as __weak freestanding fallbacks (COM1 serial / cli;hlt
 * / static arena / rdtsc). The kernel glue (linux01_bbp.c) and the hosted
 * harness each provide STRONG overrides bound to their world (printk/panic, or
 * stdio/malloc). Declared here so definer and overrider share one prototype. */
void     bbp_l01_hook_log(const char *msg);
void     bbp_l01_hook_panic(const char *msg) __attribute__((noreturn));
void    *bbp_l01_hook_alloc(size_t bytes, uint64_t *out_phys);
uint64_t bbp_l01_hook_now_ns(void);

#endif /* BBP_PORT_LINUX01_OSIF_H */
