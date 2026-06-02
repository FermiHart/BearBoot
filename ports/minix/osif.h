/*
 * osif.h — MINIX port of the Bear Boot Protocol OSIF.
 *   Author: F E R M I  ∞  H A R T   SPDX-License-Identifier: BSD-3-Clause
 *
 * STATUS: SCAFFOLD — to be implemented by the MINIX integration agent.
 * Only files under ports/minix/ may be edited; the BBP core is ABI-frozen.
 */
#ifndef BBP_PORT_MINIX_OSIF_H
#define BBP_PORT_MINIX_OSIF_H

#include <bbp/bbp_osif.h>

/* Return the MINIX implementation of the OSIF contract. */
const struct bbp_osif *bbp_minix_osif(void);

#endif /* BBP_PORT_MINIX_OSIF_H */
