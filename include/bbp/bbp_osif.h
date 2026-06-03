/*
 * bbp_osif.h — Bear Boot Protocol OS-Interface (OSIF) contract.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * THE BBP CORE IS OS-INDEPENDENT (zero #ifdef per OS). Everything that differs
 * between operating systems when wiring BBP into a kernel is funneled through
 * this thin interface, exactly like the core/ vs osif/ split in a portable
 * libc. A port (e.g. ports/minix/) IMPLEMENTS these hooks; the core never
 * calls an OS API directly.
 *
 * Design rules (enforced by review, not by the linker):
 *   - The core parser (kernel/bbp_kernel.c) does NOT depend on this header.
 *     It is self-contained and takes the HHDM offset via struct bbp_kctx.
 *   - This interface exists for the PORT's own glue and for the optional
 *     producer adapter (e.g. a Limine->BBP shim) that synthesizes a bbp_info
 *     inside a kernel already booted by another protocol.
 *   - A port provides a `const struct bbp_osif *` and must implement every
 *     non-optional hook. Optional hooks may be NULL.
 */
#ifndef BBP_OSIF_H
#define BBP_OSIF_H

#include <bbp/bbp.h>

struct bbp_osif {
    /* Identity of the port, for logging/conformance reports. */
    const char *os_name;          /* e.g. "minix" */
    const char *port_version;     /* e.g. "0.1.0" */

    /* REQUIRED. Translate a physical address to a kernel-virtual pointer in
     * THIS OS's address space. For a higher-half kernel this is usually
     * `phys + hhdm_offset`. Returns NULL for phys==0. The value returned for
     * a valid phys is also used to seed bbp_kctx.hhdm_offset when the port
     * builds the context, so it MUST be consistent with a linear offset. */
    void *(*phys_to_virt)(uint64_t phys);

    /* REQUIRED. Emit one line of diagnostic text (no implicit newline added by
     * the core; the port decides). Routed to the OS's early console/serial. */
    void (*log)(const char *msg);

    /* REQUIRED. Abort the boot. Must not return. */
    void (*panic)(const char *msg) __attribute__((noreturn));

    /* OPTIONAL (may be NULL). Allocate `bytes` of scratch for a producer
     * adapter's tag arena, returning the virtual ptr and writing the matching
     * physical address to *out_phys. NULL if the port doesn't build tags. */
    void *(*alloc_pages)(size_t bytes, uint64_t *out_phys);

    /* OPTIONAL (may be NULL). Current time in nanoseconds, for boot metrics. */
    uint64_t (*now_ns)(void);
};

/* The HHDM offset implied by a port's phys_to_virt, derived once so the core
 * parser context can be seeded. A port whose mapping is not a simple linear
 * offset must NOT use this and should drive the parser with an explicit
 * offset instead (see bbp_init_ex). */
static inline bbp_virt_t bbp_osif_hhdm_offset(const struct bbp_osif *osif)
{
    /* Probe with a known non-zero phys; offset = virt - phys. */
    const uint64_t probe = 0x1000;
    uintptr_t v = (uintptr_t)osif->phys_to_virt(probe);
    return (bbp_virt_t)((uint64_t)v - probe);
}

#endif /* BBP_OSIF_H */
