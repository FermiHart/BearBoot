/*
 * osif.h — MINIX port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Public surface of the MINIX OSIF glue. Only files under ports/minix/ may be
 * edited; the BBP core is ABI-frozen. The OSIF wires the OS-independent core to
 * MINIX internals (serial console, panic, HHDM phys->virt, scratch arena).
 *
 * The implementation is REAL (BBP_PORT_MINIX_REAL): it talks to COM1 directly
 * and computes phys->virt from a runtime-supplied HHDM offset, exactly the
 * offset MINIX itself derives from Limine (limine_hhdm_offset in
 * minix/kernel/arch/x86_64/limine_kinfo.c).
 */
#ifndef BBP_PORT_MINIX_OSIF_H
#define BBP_PORT_MINIX_OSIF_H

#include <bbp/bbp_osif.h>

/* Return the MINIX implementation of the OSIF contract. */
const struct bbp_osif *bbp_minix_osif(void);

/* Seed the HHDM offset the OSIF uses for phys_to_virt. MUST be called once,
 * early in the MINIX C entry, with the offset MINIX got from Limine
 * (hhdm_request.response->offset == limine_hhdm_offset). Until it is called,
 * phys_to_virt behaves as the identity map (offset 0), which is correct only
 * while execution is still identity-mapped.
 *
 * Returns the offset stored, so a caller can log it. */
bbp_virt_t bbp_minix_set_hhdm(bbp_virt_t hhdm_offset);

/* The HHDM offset currently in effect (0 until bbp_minix_set_hhdm runs). */
bbp_virt_t bbp_minix_get_hhdm(void);

/* Seed the kernel slide (Limine kernel-address response: physical_base /
 * virtual_base). REQUIRED before the adapter builds tags on a higher-half
 * kernel: the scratch arena is a kernel symbol, so its TRUE physical address
 * is arena_virt - kvirt_base + kphys_base, which is what tag pointers must
 * carry. Without it, alloc_pages falls back to identity (only valid while
 * still identity-mapped). */
void bbp_minix_set_kslide(uint64_t kphys_base, bbp_virt_t kvirt_base);

/* Translate a KERNEL-IMAGE virtual address (a kernel symbol, e.g. the scratch
 * arena) to its TRUE physical via the kernel slide. Single source of truth for
 * the slide math, shared by alloc_pages and the adapter. Identity when the
 * slide is unset (valid only while identity-mapped). */
uint64_t bbp_minix_virt_to_phys(uint64_t kimage_virt);

/* OPTIONAL. Install the MINIX kernel panic() so the OSIF panic hook routes to
 * it. ports/minix/ must not #include MINIX headers (it would break the
 * freestanding scaffold-check and the standalone harness), so the integration
 * passes a thin wrapper: void wrap(const char *m){ panic("%s", m); }. When no
 * hook is installed (harness / scaffold), panic logs to serial and halts. */
void bbp_minix_set_panic_hook(void (*hook)(const char *));

/* Scratch arena exposed so the adapter can compute its arena's PHYSICAL base
 * (arena_phys = arena_virt - hhdm_offset) without duplicating the math, and so
 * the integration can place the arena wherever it likes for v2. Returns the
 * arena virtual base and writes its byte capacity to *out_size. */
void *bbp_minix_arena_base(unsigned long *out_size);

#endif /* BBP_PORT_MINIX_OSIF_H */
