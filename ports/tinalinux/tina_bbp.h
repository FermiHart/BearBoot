/*
 * tina_bbp.h — kernel-facing accessors exposed by the TinaLinux BBP glue.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The glue TU (tina_bbp.c) validates a BBP context at late_initcall and exposes
 * it to the rest of the kernel through these accessors. Declared in a header so
 * both the definer and any consumer share one prototype (no -Wmissing-
 * prototypes, no drift). A consumer includes this plus bbp_kernel.h to query
 * tags with bbp_find_tag()/bbp_for_each_tag().
 */
#ifndef BBP_PORT_TINALINUX_GLUE_H
#define BBP_PORT_TINALINUX_GLUE_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* The CRC-validated BBP context built at boot, or NULL if validation failed
 * (in which case TinaLinux is running purely on its legacy boot path). */
const struct bbp_kctx *bbp_tina_boot_ctx(void);

/* ACPI RSDP physical address from the CRC-VERIFIED ACPI tag, or 0 if there is
 * no valid context / no ACPI tag. A corrupt ACPI tag is treated as absent, so
 * the kernel never trusts a tampered RSDP pointer. */
uint64_t bbp_tina_get_rsdp(void);

#endif /* BBP_PORT_TINALINUX_GLUE_H */
