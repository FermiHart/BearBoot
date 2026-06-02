/*
 * osif.c — MINIX port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
 *
 * STATUS: SCAFFOLD. The MINIX agent fills each BBP_PORT_TODO. These stubs let
 * the port COMPILE against the frozen core today; they are not functional and
 * are clearly marked so they cannot be mistaken for a finished port.
 */
#include "osif.h"

/* === BBP_PORT_TODO: wire these to MINIX internals ======================= *
 * phys_to_virt : MINIX phys->kernel-virtual (HHDM). See the kernel's existing
 *                 phys/virt macro on the limine-boot branch.
 * log/panic    : MINIX serial (console=tty00 / COM1) and panic().
 * alloc_pages  : scratch for the adapter's tag arena (a static arena is OK v1).
 * now_ns       : TSC-derived, or leave NULL.
 * ======================================================================== */

#ifndef BBP_PORT_MINIX_REAL
/* --- placeholder implementations (compile-only) ------------------------- */
static void  *minix_phys_to_virt(uint64_t phys){ return (void *)(uintptr_t)phys; /* TODO: + HHDM */ }
static void   minix_log(const char *msg){ (void)msg; /* TODO: MINIX serial */ }
__attribute__((noreturn)) static void minix_panic(const char *msg){ (void)msg; for(;;){} /* TODO: MINIX panic() */ }
#else
/* Real implementations provided by the integration (define BBP_PORT_MINIX_REAL). */
extern void  *minix_phys_to_virt(uint64_t phys);
extern void   minix_log(const char *msg);
__attribute__((noreturn)) extern void minix_panic(const char *msg);
#endif

static const struct bbp_osif minix_osif = {
    .os_name      = "minix",
    .port_version = "0.0.1-scaffold",
    .phys_to_virt = minix_phys_to_virt,
    .log          = minix_log,
    .panic        = minix_panic,
    .alloc_pages  = 0,   /* TODO: optional */
    .now_ns       = 0,   /* TODO: optional */
};

const struct bbp_osif *bbp_minix_osif(void){ return &minix_osif; }
