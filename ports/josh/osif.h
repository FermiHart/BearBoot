/*
 * osif.h — Josh-Bear port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Josh-Bear is a monolithic x86_64 ("lisabeth") kernel booted by Limine. By the
 * time the BBP adapter runs, Josh's VMM, PMM (a buddy allocator) and heap are
 * ALREADY up — which lets this port be markedly simpler than a microkernel port
 * like ports/minix/:
 *
 *   - phys_to_virt uses Josh's real HHDM global `g_hhdm_offset` directly. No
 *     set_hhdm() plumbing, no two-aliases dance: there is one direct map.
 *   - alloc_pages uses Josh's buddy allocator `pmm_alloc_pages(order)`, which
 *     returns a TRUE physical, page-aligned, CONTIGUOUS block. The arena's
 *     physical is therefore trivially known and its virtual is phys+hhdm — so
 *     none of the kernel-image-vs-HHDM alias gymnastics the minix port needs.
 *   - log/panic are Josh's native kserial_puts/kpanic.
 *
 * This file is the ONLY Josh-coupled OSIF surface. It `extern`-declares the few
 * Josh kernel symbols it needs; when vendored into the Josh tree they link to
 * the real implementations, and the standalone bearboot test harness provides
 * stubs (see test/harness.c).
 */
#ifndef BBP_PORT_JOSH_OSIF_H
#define BBP_PORT_JOSH_OSIF_H

#include <bbp/bbp.h>
#include <bbp/bbp_osif.h>

/* The Josh OSIF vtable handed to the BBP core/adapter. */
const struct bbp_osif *bbp_josh_osif(void);

#endif /* BBP_PORT_JOSH_OSIF_H */
