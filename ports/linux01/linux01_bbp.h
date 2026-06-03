/*
 * linux01_bbp.h — kernel glue surface for the Bear Boot Protocol on linux-0.01.
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Include this from init/main.c (or wherever you wire the call) to run the
 * native linux-0.01 -> BBP adapter and, later, to query the validated tags.
 *
 * The glue provides STRONG overrides of the port's __weak OSIF hooks
 * (bbp_l01_hook_log -> printk, bbp_l01_hook_panic -> panic) so BBP diagnostics
 * route through the kernel's own console instead of the freestanding COM1
 * fallback. Same osif.o, kernel world chosen at link time.
 *
 * The call is ADDITIVE and NON-FATAL: linux-0.01 boots exactly as before
 * whether or not validation succeeds. On success the kernel gains a
 * CRC-verified view of its own RAM model through bbp_find_tag().
 */
#ifndef BBP_PORT_LINUX01_GLUE_H
#define BBP_PORT_LINUX01_GLUE_H

#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"

/* Run the adapter once, early in main() (after trap_init/sched are NOT
 * required — the adapter touches no interrupts; call it any time the kernel is
 * identity-mapped, which is always on linux-0.01). Logs a one-line verdict via
 * printk. Returns BBP_OK on success; never panics on failure (non-fatal). */
bbp_status_t bbp_linux01_init(void);

/* The validated context from the last successful bbp_linux01_init(), or NULL
 * if it never ran or validation failed. Use with bbp_find_tag() /
 * bbp_for_each_tag(). */
const struct bbp_kctx *bbp_linux01_boot_ctx(void);

#endif /* BBP_PORT_LINUX01_GLUE_H */
