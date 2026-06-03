/*
 * osif.h — TinaLinux port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Public surface of the TinaLinux OSIF glue. Only files under ports/tinalinux/
 * may be edited; the BBP core is ABI-frozen. The OSIF wires the OS-independent
 * core to TinaLinux (a Linux 6.12 derivative) internals.
 *
 * THIS IS A NATIVE PORT, NOT A LIMINE ADAPTER. TinaLinux is booted by the
 * native Linux x86_64 path (EFI stub / BIOS -> boot_params), so the boot data
 * the adapter consumes are the REAL Linux sources:
 *
 *   HHDM offset  = page_offset_base        (Linux direct map; __va == phys+off)
 *   memory map   = e820_table              (firmware memory map)
 *   kernel base  = phys_base / _text       (the kernel slide)
 *   ACPI RSDP    = acpi_os_get_root_pointer()
 *   cmdline      = saved_command_line
 *
 * DESIGN — graceful binding (the elegant bit):
 *   osif.c stays FREESTANDING (no <linux/...> headers) so it compiles standalone for
 *   `make scaffold-check` and the test harness. Its five OSIF primitives are
 *   __attribute__((weak)) defaults (serial / hlt / static arena / rdtsc). When
 *   the port is linked INTO the real TinaLinux kernel, the glue TU tina_bbp.c
 *   provides STRONG overrides bound to printk / panic / __get_free_pages /
 *   ktime_get_ns. Same object, two worlds: freestanding test rig, or real
 *   kernel infrastructure — chosen at link time, zero #ifdef.
 *
 * Why the classic BBP dual-alias bug cannot occur here:
 *   The MINIX port must juggle a kernel-image alias and an HHDM alias because
 *   its scratch arena is a kernel symbol. The TinaLinux glue allocates the
 *   arena in the Linux DIRECT MAP (__get_free_pages), so arena_phys ==
 *   __pa(arena) and phys_to_virt == __va are the SAME linear map. There is
 *   only one alias. (See CONFORMANCE.md.)
 */
#ifndef BBP_PORT_TINALINUX_OSIF_H
#define BBP_PORT_TINALINUX_OSIF_H

#include <bbp/bbp_osif.h>

/* Return the TinaLinux implementation of the OSIF contract. */
const struct bbp_osif *bbp_tina_osif(void);

/* Seed the HHDM offset the OSIF uses for phys_to_virt. On Linux this is
 * page_offset_base (virt = phys + page_offset_base == __va(phys) over all
 * direct-mapped RAM). MUST be called once, early, before the adapter runs.
 * Returns the offset stored, so a caller can log it. */
bbp_virt_t bbp_tina_set_hhdm(bbp_virt_t hhdm_offset);

/* The HHDM offset currently in effect (0 until bbp_tina_set_hhdm runs). */
bbp_virt_t bbp_tina_get_hhdm(void);

/* Seed the kernel slide (phys_base + the kernel virtual base, _text). Used for
 * the KERNEL_ADDRESS tag. NOT needed for arena physical computation here — the
 * arena lives in the direct map, so its physical is exact via the HHDM. */
void bbp_tina_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base);

/* Translate a direct-map kernel-virtual address to its physical via the HHDM
 * offset (phys = virt - hhdm_offset). Single source of truth for the arena's
 * physical when the weak static-arena fallback is in play. */
uint64_t bbp_tina_virt_to_phys(uint64_t kvirt);

/* Scratch arena base + capacity. With the weak fallback this is a static
 * buffer; the strong glue override returns its __get_free_pages() region. The
 * adapter carves the bbp_info off the front of this arena. */
void *bbp_tina_arena_base(unsigned long *out_size);

/* ---- OSIF override seam (the weak/strong binding contract) --------------- *
 * osif.c defines these five as __weak freestanding fallbacks (serial / hlt /
 * static arena / rdtsc). The kernel glue (tina_bbp.c) and the hosted harness
 * each provide STRONG overrides bound to their world (printk/__get_free_pages/
 * ktime, or stdio/malloc). Declared here so both the definer and the overrider
 * share one prototype — no -Wmissing-prototypes, no signature drift. */
void     bbp_tina_hook_log(const char *msg);
void     bbp_tina_hook_panic(const char *msg) __attribute__((noreturn));
void    *bbp_tina_hook_alloc(size_t bytes, uint64_t *out_phys);
uint64_t bbp_tina_hook_now_ns(void);

#endif /* BBP_PORT_TINALINUX_OSIF_H */
