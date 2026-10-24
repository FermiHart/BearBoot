/* bbp_security.c — kernel-side consumption of BBP_TAG_SECURITY (v1.2).
 *
 * F6/F14 campaign (BearTrace): the SECURITY tag carries everything the
 * kernel needs to verify the boot measurement chain against the live
 * TPM: the staged TCG2 event log, the final events table, the PTP
 * startup locality, and the TPM's own base address/interface.
 *
 * The flow:
 *   1. Find the SECURITY tag (validated by the BBP parser — CRC-64 sealed)
 *   2. Verify the out-of-line blob CRCs (measurements, TCG2 log, final table)
 *   3. Seed the kernel CSPRNG from the hardware entropy blob
 *   4. Replay the TCG2 log with the PTP startup-locality rule
 *   5. Read the live PCR bank through the CRB driver
 *   6. Compare: replay == live → CHAIN VERIFIED; else MISMATCH
 *
 * Copyright (c) 2026 F E R M I ∞ H A R T. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include <bbp/bbp_kernel.h>

/* Platform hooks — provided by the consuming kernel. */
struct tpm2_crb_transport;  /* opaque: the kernel's CRB driver state */

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

/* SHA-256 (the kernel provides this — it already has it for PCR extend). */
struct bbp_sha256_ctx {
    uint32_t state[8];
    uint64_t total_length;
    uint8_t  buffer[64];
    size_t   buffer_fill;
};
extern void bbp_sha256_init(struct bbp_sha256_ctx *ctx);
extern void bbp_sha256_update(struct bbp_sha256_ctx *ctx,
                              const void *data, size_t length);
extern void bbp_sha256_final(struct bbp_sha256_ctx *ctx, uint8_t out[32]);

/* The kernel's CRB driver provides live PCR reads. */
extern int bbp_tpm2_pcr_read(uint32_t pcr_index, uint8_t out[32]);

/* ================================================================== */
/* Bounded TCG2 event-log replay — the campaign-verified core (F7/F14). */
/* Ported from the implementation that closed the PCR[0] gap and      */
/* replayed 8/8 PCRs on CSME 14/16 hardware (Beyond_BDM               */
/* ring0/hw/tpm2_eventlog.c). Returns the number of events parsed, or  */
/* -1 on structural violation. Fills the shadow PCRs and the          */
/* covered/extends masks.                                             */
/* ================================================================== */

#define BBP_TCG2_MAX_EVENTS      4096u
#define BBP_TCG2_MAX_EVENT_SIZE (64u * 1024u)
#define BBP_TCG2_MAX_DIGESTS    8u
#define BBP_TCG2_DIGEST_LEN     32u
#define BBP_TCG2_PCR_BANK       24u     /* replay shadow bank width */

#define EV_NO_ACTION 0x00000003u
#define EV_OMIT      0x00000012u

static uint32_t bbp_rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t bbp_rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint64_t bbp_rd_le64(const uint8_t *p)
{
    return (uint64_t)bbp_rd_le32(p) | ((uint64_t)bbp_rd_le32(p + 4) << 32);
}

static uint32_t bbp_alg_digest_size(uint16_t alg)
{
    switch (alg) {
    case 0x0004: return 20;  /* SHA-1   */
    case 0x000b: return 32;  /* SHA-256 */
    case 0x000c: return 48;  /* SHA-384 */
    case 0x000d: return 64;  /* SHA-512 */
    default:     return 0;
    }
}

struct bbp_replay {
    uint8_t  pcr[BBP_TCG2_PCR_BANK][BBP_TCG2_DIGEST_LEN];
    uint32_t covered_mask;
    uint32_t extends_total;
    uint8_t  startup_locality;
    uint32_t events_parsed;
};

/* PCR extend: new = SHA-256(old || digest) — exactly what the TPM does. */
static void bbp_sha256_extend(uint8_t pcr[BBP_TCG2_DIGEST_LEN],
                              const uint8_t digest[BBP_TCG2_DIGEST_LEN])
{
    struct bbp_sha256_ctx ctx;
    uint8_t out[BBP_TCG2_DIGEST_LEN];
    bbp_sha256_init(&ctx);
    bbp_sha256_update(&ctx, pcr, BBP_TCG2_DIGEST_LEN);
    bbp_sha256_update(&ctx, digest, BBP_TCG2_DIGEST_LEN);
    bbp_sha256_final(&ctx, out);
    for (uint32_t i = 0; i < BBP_TCG2_DIGEST_LEN; i++) pcr[i] = out[i];
}

/* Walk one TCG_PCR_EVENT2 stream (main log events 2+ and the final table).
 * Bounded by buf_len; advances *offp; returns 0 on a clean stop (terminator
 * or end of buffer), -1 on structural violation. */
static int bbp_walk_event2_stream(const uint8_t *buf, uint32_t buf_len,
                                  uint32_t *offp, struct bbp_replay *r,
                                  uint32_t max_events, int final_quirk)
{
    while (*offp < buf_len && r->events_parsed < max_events) {
        if (*offp + 12 > buf_len) break;
        /* End-of-log terminators seen in real firmware: zero or 0xFF runs. */
        uint32_t term = 0;
        for (uint32_t k = 0; k < 8 && *offp + k < buf_len; k++) {
            if (buf[*offp + k] != 0x00 && buf[*offp + k] != 0xff) break;
            term++;
        }
        if (term >= 8) break;

        uint32_t pcr = bbp_rd_le32(buf + *offp);
        uint32_t etype = bbp_rd_le32(buf + *offp + 4);
        uint32_t dcount = bbp_rd_le32(buf + *offp + 8);
        if (pcr > 23) return -1;               /* structure violated      */
        if (dcount == 0 || dcount > BBP_TCG2_MAX_DIGESTS) return -1;
        uint32_t p = *offp + 12;

        const uint8_t *sha_dig = 0;
        for (uint32_t d = 0; d < dcount; d++) {
            if (p + 2 > buf_len) return -1;
            uint16_t alg = bbp_rd_le16(buf + p);
            p += 2;
            uint32_t dsz = bbp_alg_digest_size(alg);
            if (!dsz || p + dsz > buf_len) return -1;
            if (alg == 0x000b) sha_dig = buf + p;
            p += dsz;
        }

        if (p + 4 > buf_len) return -1;
        uint32_t esize = bbp_rd_le32(buf + p);
        if (final_quirk && esize > 4096) {
            /* F7: corrupt writer; the true length is the u24 one byte late. */
            if (p + 8 > buf_len) return -1;
            esize = bbp_rd_le32(buf + p + 1) & 0xffffffu;
        }
        p += 4;
        if (esize > BBP_TCG2_MAX_EVENT_SIZE || p + esize > buf_len)
            return -1;

        if (pcr == 0 && etype == EV_NO_ACTION && esize >= 17 &&
            buf[p] == 'S' && buf[p + 1] == 't' && buf[p + 2] == 'a') {
            /* StartupLocality\0 + locality byte (PTP, F14). The firmware's
             * own claim about the startup locality is authoritative over the
             * tag hint — the same rule that closed the PCR[0] gap. */
            r->startup_locality = buf[p + esize - 1];
            for (uint32_t i = 0; i < 31; i++) r->pcr[0][i] = 0;
            r->pcr[0][31] = r->startup_locality;
        } else if (etype != EV_NO_ACTION && etype != EV_OMIT && sha_dig) {
            bbp_sha256_extend(r->pcr[pcr], sha_dig);
            r->extends_total++;
            r->covered_mask |= (1u << pcr);
        }
        p += esize;
        *offp = p;
        r->events_parsed++;
    }
    return 0;
}

/* Replay a staged TCG2 log (+ optional final events table) into the shadow
 * bank. Returns the number of events parsed, or -1 on structural violation.
 *
 * Main log: the first record is a legacy TCG_PCR_EVENT carrying the Spec ID
 * (pcrIndex u32 | eventType u32 | digest[20] | eventSize u32 | event[]).
 * Some vendors (Lenovo, F7) prepend a small preamble, so the parser anchors
 * on the "Spec ID Event03\0" signature inside the first 512 bytes and
 * derives event 1 as signature_offset - 32. Preamble bytes are reported,
 * never interpreted. */
static int bbp_tclog_replay(const uint8_t *log, uint32_t log_len,
                             const uint8_t *final_tbl, uint32_t final_len,
                             uint8_t startup_locality,
                             uint8_t pcrs[BBP_TCG2_PCR_BANK][BBP_TCG2_DIGEST_LEN],
                             uint32_t *covered_mask,
                             uint32_t *extends_total)
{
    struct bbp_replay r;
    uint32_t i, j;

    for (i = 0; i < BBP_TCG2_PCR_BANK; i++)
        for (j = 0; j < BBP_TCG2_DIGEST_LEN; j++)
            r.pcr[i][j] = 0;
    r.covered_mask = 0;
    r.extends_total = 0;
    r.startup_locality = 0;
    r.events_parsed = 0;

    /* PTP startup-locality initial rule (F14), from the v1.2 tag hint.
     * A StartupLocality event inside the log (if the firmware wrote one)
     * overrides it below. */
    if (startup_locality > 0 && startup_locality <= 4) {
        r.startup_locality = startup_locality;
        r.pcr[0][31] = startup_locality;
    }

    /* ---- Anchor the Spec ID inside the first 512 bytes (F7). ---- */
    const uint8_t *sig = 0;
    uint32_t anchor_bound = log_len < 512 ? log_len : 512;
    for (uint32_t off = 0; off + 16 <= anchor_bound; off++) {
        static const uint8_t spec_id[16] = {
            'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ',
            'E', 'v', 'e', 'n', 't', '0', '3', 0
        };
        uint8_t diff = 0;
        for (uint32_t k = 0; k < 16; k++) diff |= log[off + k] ^ spec_id[k];
        if (diff == 0) { sig = log + off; break; }
    }
    if (!sig || sig < log + 32) return -1;
    uint32_t e1 = (uint32_t)(sig - log) - 32;
    if (e1 + 32 > log_len) return -1;

    /* Event 1 sanity: EV_NO_ACTION with a 20-byte SHA-1 digest. */
    if (bbp_rd_le32(log + e1 + 4) != EV_NO_ACTION) return -1;
    uint32_t e1_size = bbp_rd_le32(log + e1 + 28);
    if (e1_size < 33 || e1_size > 512 || e1 + 32 + e1_size > log_len)
        return -1;

    uint32_t off = e1 + 32 + e1_size;
    if (bbp_walk_event2_stream(log, log_len, &off, &r,
                               BBP_TCG2_MAX_EVENTS, 0) != 0)
        return -1;

    /* ---- Final events table (F7): u64 version==1, u64 nr_events, stream. */
    if (final_tbl && final_len >= 16 && bbp_rd_le64(final_tbl) == 1) {
        uint32_t foff = 16;
        if (bbp_walk_event2_stream(final_tbl, final_len, &foff, &r,
                                   BBP_TCG2_MAX_EVENTS, 1) != 0)
            return -1;
    }

    for (i = 0; i < BBP_TCG2_PCR_BANK; i++)
        for (j = 0; j < BBP_TCG2_DIGEST_LEN; j++)
            pcrs[i][j] = r.pcr[i][j];
    *covered_mask = r.covered_mask;
    *extends_total = r.extends_total;
    return (int)r.events_parsed;
}

/* Main entry: consume the SECURITY tag and produce the verdict. */
enum bbp_security_verdict
bbp_security_consume(const struct bbp_kctx *k,
                     struct bbp_security_result *result)
{
    const struct bbp_tag_security *se =
        (const struct bbp_tag_security *)bbp_find_tag(k, BBP_TAG_SECURITY);
    /* Runtime size gate: a pre-v1.2 producer may still emit the 128-byte
     * v1.1 SECURITY tag. Its CRC only seals tag_size bytes, so reading the
     * v1.2 fields past that would read past the sealed region. A short tag
     * carries no TCG2 receipt — fail closed. (The previous compile-time
     * sizeof comparison was constant-folded and guarded nothing.) */
    if (!se || se->header.tag_size < sizeof(*se)) {
        if (result) {
            result->verdict = BBP_SEC_NOT_PRESENT;
        }
        return BBP_SEC_NOT_PRESENT;
    }

    /* --- 1. Entropy: seed the kernel CSPRNG --- */
    if (se->entropy_data && se->entropy_size > 0) {
        const uint8_t *entropy =
            (const uint8_t *)((uintptr_t)se->entropy_data);
        uint64_t expected_crc = se->entropy_crc;
        uint64_t actual_crc = bbp_crc64(entropy, se->entropy_size);
        if (expected_crc != 0 && actual_crc != expected_crc) {
            if (result) result->verdict = BBP_SEC_CRC_FAILED;
            return BBP_SEC_CRC_FAILED;
        }
        /* The kernel hooks its CSPRNG seeding here (platform-specific). */
    }

    /* --- 2. Measurements: individual component digests --- */
    if (se->measurements && se->measurement_count > 0) {
        const struct bbp_measurement *meas =
            (const struct bbp_measurement *)((uintptr_t)se->measurements);
        uint64_t expected_crc = se->measurements_crc;
        uint64_t actual_crc =
            bbp_crc64((const uint8_t *)meas,
                      se->measurement_count * sizeof(struct bbp_measurement));
        if (expected_crc != 0 && actual_crc != expected_crc) {
            if (result) result->verdict = BBP_SEC_CRC_FAILED;
            return BBP_SEC_CRC_FAILED;
        }
        /* The kernel can extend its own shadow PCRs from these. */
    }

    /* --- 3. TCG2 event log: the full firmware chain (v1.2) --- */
    int has_tclog = (se->tpm2_v2_flags & BBP_TPM2_FLAG_TCG2_LOG_PRESENT) &&
                    se->tcg2_log_start && se->tcg2_log_size > 0;
    if (!has_tclog) {
        if (result) {
            result->verdict = BBP_SEC_ENTROPY_ONLY;
            result->tpm_base_address = se->tpm_base_address;
            result->tpm_version = se->tpm_version;
            result->tpm_interface = se->tpm_interface;
            result->tpm_flags = se->tpm_flags;
            result->startup_locality = se->startup_locality;
            result->measurement_count = se->measurement_count;
            result->entropy_size = se->entropy_size;
        }
        return BBP_SEC_ENTROPY_ONLY;
    }

    /* Verify the TCG2 log CRC. */
    const uint8_t *tclog =
        (const uint8_t *)((uintptr_t)se->tcg2_log_start);
    uint64_t tclog_expected = se->tcg2_log_crc;
    uint64_t tclog_actual = bbp_crc64(tclog, se->tcg2_log_size);
    if (tclog_expected != 0 && tclog_actual != tclog_expected) {
        return BBP_SEC_CRC_FAILED;
    }

    /* Verify the final table CRC if present. */
    const uint8_t *final_tbl = NULL;
    uint32_t final_len = 0;
    if ((se->tpm2_v2_flags & BBP_TPM2_FLAG_TCG2_FINAL_PRESENT) &&
        se->tcg2_final_start && se->tcg2_final_size > 0) {
        final_tbl = (const uint8_t *)((uintptr_t)se->tcg2_final_start);
        final_len = se->tcg2_final_size;
        uint64_t fin_expected = se->tcg2_final_crc;
        uint64_t fin_actual = bbp_crc64(final_tbl, final_len);
        if (fin_expected != 0 && fin_actual != fin_expected) {
            return BBP_SEC_CRC_FAILED;
        }
    }

    /* --- 4. Replay the TCG2 log against the live PCR bank --- */
    uint8_t pcrs[24][32];
    uint32_t covered_mask = 0;
    uint32_t extends_total = 0;

    int events = bbp_tclog_replay(tclog, se->tcg2_log_size,
                                   final_tbl, final_len,
                                   se->startup_locality,
                                   pcrs, &covered_mask, &extends_total);
    if (events < 0) {
        /* Structural violation — the log is malformed, not necessarily lying. */
        if (result) result->verdict = BBP_SEC_CRC_FAILED;
        return BBP_SEC_CRC_FAILED;
    }

    /* --- 5. Read the live PCR bank through the CRB driver --- */
    uint8_t live[24][32];
    uint32_t match_mask = 0;
    int pcr_reads_ok = 1;

    for (uint32_t pcr = 0; pcr < 8; pcr++) {
        if (!(covered_mask & (1u << pcr))) continue;
        if (bbp_tpm2_pcr_read(pcr, live[pcr]) != 0) {
            pcr_reads_ok = 0;
            break;
        }
        uint8_t diff = 0;
        for (uint32_t j = 0; j < 32; j++)
            diff |= pcrs[pcr][j] ^ live[pcr][j];
        if (diff == 0) match_mask |= (1u << pcr);
    }

    if (!pcr_reads_ok) {
        /* The live bank was unreachable, but the replay DID happen — the
         * caller still gets the shadow bank, masks and event counts as
         * evidence. (This path previously dropped the details.) */
        if (result) {
            result->verdict = BBP_SEC_TPM_UNREACHABLE;
            result->tpm_base_address = se->tpm_base_address;
            result->tpm_version = se->tpm_version;
            result->tpm_interface = se->tpm_interface;
            result->tpm_flags = se->tpm_flags;
            result->startup_locality = se->startup_locality;
            result->measurement_count = se->measurement_count;
            result->entropy_size = se->entropy_size;
            result->tcg2_events_parsed = (uint32_t)events;
            result->tcg2_events_extended = extends_total;
            result->pcr_match_mask = match_mask;
            result->pcr_covered_mask = covered_mask;
            for (uint32_t i = 0; i < 8; i++) {
                for (uint32_t j = 0; j < 32; j++)
                    result->replayed_pcr[i][j] = pcrs[i][j];
            }
        }
        return BBP_SEC_TPM_UNREACHABLE;
    }

    /* --- 6. The verdict --- */
    enum bbp_security_verdict verdict;
    uint32_t covered_pcrs = covered_mask & 0xFF;
    if (covered_pcrs != 0 && match_mask == covered_pcrs)
        verdict = BBP_SEC_CHAIN_VERIFIED;
    else
        verdict = BBP_SEC_CHAIN_MISMATCH;

    if (result) {
        result->verdict = verdict;
        result->tpm_base_address = se->tpm_base_address;
        result->tpm_version = se->tpm_version;
        result->tpm_interface = se->tpm_interface;
        result->tpm_flags = se->tpm_flags;
        result->startup_locality = se->startup_locality;
        result->measurement_count = se->measurement_count;
        result->entropy_size = se->entropy_size;
        result->tcg2_events_parsed = (uint32_t)events;
        result->tcg2_events_extended = extends_total;
        result->pcr_match_mask = match_mask;
        result->pcr_covered_mask = covered_mask;
        for (uint32_t i = 0; i < 8; i++) {
            for (uint32_t j = 0; j < 32; j++) {
                result->replayed_pcr[i][j] = pcrs[i][j];
                result->live_pcr[i][j] = live[i][j];
            }
        }
    }

    return verdict;
}
