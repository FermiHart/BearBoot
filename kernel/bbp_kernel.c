/*
 * bbp_kernel.c — kernel-side Bear Boot Protocol parser (freestanding).
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * No libc dependency: provides its own tiny memcmp. HHDM-aware so the tag
 * walk keeps working after the kernel installs its own page tables.
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "bbp_kernel.h"

/* Local memcmp — kernels often lack libc this early. */
static int bbp_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    }
    return 0;
}

/* CRC64 over a struct with one 8-byte checksum field zeroed in place.
 * We checksum [0, off) then 8 zero bytes then [off+8, len).
 *
 * SAFETY: `len` may originate from untrusted memory (a tag's tag_size). The
 * caller MUST guarantee len >= off + 8 before calling; bbp_tag_len_ok() is
 * the gate. We assert the invariant here too so a mistake fails loudly in
 * the hosted self-test rather than reading 16 EiB on real hardware. */
static uint64_t bbp_crc_skip(const void *base, size_t len, size_t off)
{
    static const uint8_t zeros[8] = {0};
    /* Defensive: never let an underflowed length drive the final update. */
    if (len < off + 8) return ~(uint64_t)0; /* sentinel: cannot match a real CRC */
    uint64_t c = bbp_crc64_init();
    c = bbp_crc64_update(c, base, off);
    c = bbp_crc64_update(c, zeros, 8);
    c = bbp_crc64_update(c, (const uint8_t *)base + off + 8, len - off - 8);
    return bbp_crc64_final(c);
}

/* Absolute ceiling on tags walked, regardless of the (untrusted) tag_count.
 * A cyclic or corrupt next_tag chain can never spin the kernel forever. */
#define BBP_MAX_TAGS 1024u

/* A tag is structurally plausible if its size is at least the fixed header
 * and within a sane bound. This MUST pass before we CRC `tag_size` bytes. */
static int bbp_tag_len_ok(const struct bbp_tag_header *tag)
{
    return tag->tag_size >= sizeof(struct bbp_tag_header)
        && tag->tag_size <= (16u * 1024u * 1024u);
}

/* A physical tag pointer must be 8-byte aligned (the builder guarantees it).
 * A misaligned next_tag is corruption; reject the whole chain rather than
 * fault on an unaligned 8-byte load on strict-alignment targets. */
static int bbp_tag_ptr_ok(bbp_phys_t p)
{
    return p != 0 && (p & 7u) == 0;
}

/* Highest physical address we will ever translate/scan. Bounds a hostile
 * pointer to the canonical lower half (well under any sane HHDM base) and,
 * together with the overflow checks below, prevents phys+hhdm or phys+len
 * from wrapping the address space. 256 TiB covers 48-bit phys; raise only
 * with a matching threat review. */
#define BBP_MAX_PHYS (1ULL << 48)

/* Overflow-safe [phys, phys+len) region check against the address space and
 * the HHDM translation. Returns 1 if the region is plausible to dereference.
 * Rejects: zero phys/len, phys+len wrap, phys+len past BBP_MAX_PHYS, and a
 * phys+hhdm_offset translation that wraps uintptr_t. (Audit A2/A3/A4.) */
static int bbp_region_ok(const struct bbp_kctx *k, bbp_phys_t phys, uint64_t len)
{
    if (phys == 0 || len == 0)             return 0;
    if (len > BBP_MAX_PHYS)                return 0;
    if (phys > BBP_MAX_PHYS - len)         return 0;   /* phys+len wrap / OOB */
    /* Translation must not wrap uintptr_t (e.g. hostile phys + high HHDM). */
    uintptr_t base = (uintptr_t)phys;
    uintptr_t off  = (uintptr_t)k->hhdm_offset;
    if (base > (uintptr_t)-1 - off)        return 0;   /* base+off wrap */
    uintptr_t v = base + off;
    if (v > (uintptr_t)-1 - (uintptr_t)len) return 0;  /* virt+len wrap */
    return 1;
}

bbp_status_t bbp_verify_header(const struct bbp_header *hdr)
{
    if (!hdr) return BBP_ERR_NULL;
    if (bbp_memcmp(hdr->magic, BBP_HEADER_MAGIC, sizeof(BBP_HEADER_MAGIC) - 1) != 0)
        return BBP_ERR_MAGIC;
    if (hdr->version_major != BBP_VERSION_MAJOR)
        return BBP_ERR_VERSION;
    if (hdr->header_size != sizeof(struct bbp_header))
        return BBP_ERR_SIZE;
    uint64_t got = bbp_crc_skip(hdr, sizeof(struct bbp_header),
                                offsetof(struct bbp_header, checksum));
    if (got != hdr->checksum)
        return BBP_ERR_CHECKSUM;
    return BBP_OK;
}

/* Cap on any single out-of-line blob we will CRC-scan. Bounds the work a
 * malicious producer can induce and keeps the scan inside plausible memory. */
#define BBP_MAX_BLOB (64u * 1024u * 1024u)

bbp_status_t bbp_verify_blob(const struct bbp_kctx *k, bbp_phys_t phys,
                             size_t len, uint64_t expected_crc,
                             int allow_unchecked)
{
    if (!k || phys == 0 || len == 0) return BBP_ERR_NULL;
    if (len > BBP_MAX_BLOB)           return BBP_ERR_SIZE;
    /* Region must be in-bounds and not wrap under HHDM translation (A2/A3). */
    if (!bbp_region_ok(k, phys, (uint64_t)len)) return BBP_ERR_SIZE;

    if (expected_crc == 0) {
        /* Producer did not provide a CRC. Trust only if the caller opts in. */
        return allow_unchecked ? BBP_OK : BBP_ERR_TAG_CHECKSUM;
    }

    const void *p = bbp_phys_to_virt(k, phys);
    uint64_t got = bbp_crc64(p, len);
    return (got == expected_crc) ? BBP_OK : BBP_ERR_TAG_CHECKSUM;
}

bbp_status_t bbp_init_ex(struct bbp_kctx *out, const struct bbp_info *info,
                         bbp_virt_t hhdm_hint)
{
    if (!out || !info) return BBP_ERR_NULL;

    out->info = info;
    out->hhdm_offset = hhdm_hint;
    out->verify_tag_crc = 1;

    if (bbp_memcmp(info->magic, BBP_INFO_MAGIC, sizeof(BBP_INFO_MAGIC) - 1) != 0)
        return BBP_ERR_MAGIC;

    if (info->version_major != BBP_VERSION_MAJOR)
        return BBP_ERR_VERSION;

    /* info_size must at least cover the fixed struct and be sane. */
    if (info->info_size < sizeof(struct bbp_info) ||
        info->info_size > (64u * 1024u * 1024u))
        return BBP_ERR_SIZE;

    uint64_t want = info->checksum;
    uint64_t got  = bbp_crc_skip(info, sizeof(struct bbp_info),
                                 offsetof(struct bbp_info, checksum));
    if (want != got)
        return BBP_ERR_CHECKSUM;

    /* Pick up HHDM offset early so subsequent lookups translate correctly.
     * The first_tag pointer is physical; with hhdm_hint applied the parser
     * can reach the tag list even when it lives outside the identity map.
     * If the HHDM tag is present it overrides the hint with the authoritative
     * value the producer chose. */
    const struct bbp_tag_header *t = bbp_find_tag(out, BBP_TAG_HHDM);
    if (t) {
        const struct bbp_tag_hhdm *h = (const struct bbp_tag_hhdm *)t;
        out->hhdm_offset = h->offset;
    }
    return BBP_OK;
}

bbp_status_t bbp_init(struct bbp_kctx *out, const struct bbp_info *info)
{
    return bbp_init_ex(out, info, 0);
}

/* Validate ONE tag at physical address `cur` and return its virtual pointer
 * via *out_tag, or NULL on any structural failure. Performs, in order:
 *   1. pointer alignment/non-null         (bbp_tag_ptr_ok)
 *   2. header region in-bounds + no wrap   (bbp_region_ok for the 32B header)
 *   3. tag_size plausibility               (bbp_tag_len_ok)
 *   4. FULL tag region in-bounds + no wrap (bbp_region_ok for tag_size)
 * Only after all four is it safe to read tag_size bytes (CRC). Returns 1 and
 * sets *out_tag on success; returns 0 to STOP the walk (hard corruption).
 * (Audit A4: previously tag_id/tag_size were read before the region check.) */
static int bbp_tag_at(const struct bbp_kctx *k, bbp_phys_t cur,
                      const struct bbp_tag_header **out_tag)
{
    if (!bbp_tag_ptr_ok(cur)) return 0;
    if (!bbp_region_ok(k, cur, sizeof(struct bbp_tag_header))) return 0;

    const struct bbp_tag_header *tag =
        (const struct bbp_tag_header *)bbp_phys_to_virt(k, cur);

    if (!bbp_tag_len_ok(tag)) return 0;
    if (!bbp_region_ok(k, cur, (uint64_t)tag->tag_size)) return 0;

    *out_tag = tag;
    return 1;
}

/* CRC a fully-validated tag. Returns 1 if its checksum matches. */
static int bbp_tag_crc_ok(const struct bbp_tag_header *tag)
{
    uint64_t got = bbp_crc_skip(tag, tag->tag_size,
                                offsetof(struct bbp_tag_header, checksum));
    return got == tag->checksum;
}

const struct bbp_tag_header *bbp_find_tag(const struct bbp_kctx *k, uint64_t tag_id)
{
    if (!k || !k->info) return (void *)0;

    bbp_phys_t cur = k->info->first_tag;
    uint32_t steps = 0;

    while (cur && steps++ < BBP_MAX_TAGS) {
        const struct bbp_tag_header *tag;
        if (!bbp_tag_at(k, cur, &tag)) break;   /* hard corruption: stop */

        if (tag->tag_id == tag_id) {
            if (k->verify_tag_crc && !bbp_tag_crc_ok(tag)) {
                cur = tag->next_tag;            /* corrupt: skip, keep looking */
                continue;
            }
            return tag;
        }
        cur = tag->next_tag;
    }
    return (void *)0;
}

uint32_t bbp_for_each_tag(const struct bbp_kctx *k, bbp_tag_cb cb, void *user)
{
    if (!k || !k->info || !cb) return 0;

    bbp_phys_t cur = k->info->first_tag;
    uint32_t n = 0;       /* tags actually delivered to the callback */
    uint32_t steps = 0;   /* iterations, incl. CRC-skipped tags — bounds the loop */

    while (cur && steps++ < BBP_MAX_TAGS) {
        const struct bbp_tag_header *tag;
        if (!bbp_tag_at(k, cur, &tag)) break;

        /* Same integrity contract as bbp_find_tag: a CRC-failed tag is skipped,
         * never handed to the callback. The `steps` guard (not `n`) bounds the
         * walk, so a cyclic chain of CRC-failing tags still terminates. */
        if (k->verify_tag_crc && !bbp_tag_crc_ok(tag)) {
            cur = tag->next_tag;
            continue;
        }

        n++;
        if (cb(tag, user)) break;
        cur = tag->next_tag;
    }
    return n;
}

const char *bbp_strstatus(bbp_status_t s)
{
    switch (s) {
    case BBP_OK:               return "ok";
    case BBP_ERR_NULL:         return "null info pointer";
    case BBP_ERR_MAGIC:        return "bad magic (not BEAR_INFO/BEAR_BOOT)";
    case BBP_ERR_VERSION:      return "incompatible protocol major version";
    case BBP_ERR_SIZE:         return "implausible info_size";
    case BBP_ERR_CHECKSUM:     return "info CRC64 mismatch";
    case BBP_ERR_TAG_CHECKSUM: return "tag CRC64 mismatch";
    default:                   return "unknown";
    }
}
