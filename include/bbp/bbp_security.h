/* bbp_security.h — BBP_TAG_SECURITY consumer (v1.2).
 *
 * F6/F14 campaign (BearTrace): the kernel-side verification of the
 * boot measurement chain. The SECURITY tag carries the TCG2 event log,
 * the PTP startup locality, hardware entropy, and component measurements.
 * This module verifies everything and produces a single verdict.
 *
 * Copyright (c) 2026 F E R M I ∞ H A R T. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_SECURITY_H
#define BBP_SECURITY_H

#include <bbp/bbp.h>

/* The consumer's verdict. */
enum bbp_security_verdict {
    BBP_SEC_NOT_PRESENT = 0,       /* no SECURITY tag in the handoff */
    BBP_SEC_ENTROPY_ONLY = 1,     /* entropy present, no TCG2 log */
    BBP_SEC_CHAIN_VERIFIED = 2,   /* TCG2 replay == live PCR (the receipt) */
    BBP_SEC_CHAIN_MISMATCH = 3,   /* TCG2 replay != live PCR (the lie) */
    BBP_SEC_CRC_FAILED = 4,       /* a blob CRC mismatch — evidence corrupt */
    BBP_SEC_TPM_UNREACHABLE = 5,  /* CRB driver could not read live PCRs */
};

struct bbp_security_result {
    enum bbp_security_verdict verdict;

    /* What the tag said (raw facts from the producer). */
    uint64_t tpm_base_address;
    uint16_t tpm_version;
    uint16_t tpm_interface;
    uint32_t tpm_flags;
    uint8_t  startup_locality;
    uint32_t measurement_count;
    uint32_t entropy_size;

    /* What the kernel computed (the verification). */
    uint32_t tcg2_events_parsed;
    uint32_t tcg2_events_extended;
    uint32_t pcr_match_mask;       /* bit N = PCR N replay == live */
    uint32_t pcr_covered_mask;     /* bit N = PCR N had >= 1 extend in log */
    uint8_t  replayed_pcr[8][32];  /* the shadow PCRs after replay */
    uint8_t  live_pcr[8][32];      /* the live PCR values from the CRB */
};

/* Main entry: consume the SECURITY tag and produce the verdict.
 * `k` = the parsed BBP context (from bbp_init_bounded).
 * `result` = optional output for the details (can be NULL).
 * Returns the verdict. */
enum bbp_security_verdict
bbp_security_consume(const struct bbp_kctx *k,
                     struct bbp_security_result *result);

#endif /* BBP_SECURITY_H */
