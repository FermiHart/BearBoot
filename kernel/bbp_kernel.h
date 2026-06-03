/*
 * bbp_kernel.h — kernel-side helper API for the Bear Boot Protocol.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Drop this + bbp_kernel.c into a freestanding kernel. It validates the
 * handoff struct and lets you find tags by UUID. It is HHDM-aware: once you
 * tell it the direct-map offset, every physical pointer in the tag list is
 * translated for you, so the helpers keep working after you switch CR3.
 */
#ifndef BBP_KERNEL_H
#define BBP_KERNEL_H

#include <bbp/bbp.h>

/* Validation result codes. */
typedef enum {
    BBP_OK = 0,
    BBP_ERR_NULL,            /* info pointer was NULL */
    BBP_ERR_MAGIC,           /* bad "BEAR_INFO" / "BEAR_BOOT" magic */
    BBP_ERR_VERSION,         /* incompatible version_major */
    BBP_ERR_SIZE,            /* info_size implausible */
    BBP_ERR_CHECKSUM,        /* CRC64 mismatch */
    BBP_ERR_TAG_CHECKSUM,    /* a tag failed CRC during iteration */
} bbp_status_t;

/* Opaque-ish context the kernel keeps after a successful handoff. */
struct bbp_kctx {
    const struct bbp_info *info;   /* virtual ptr to validated info */
    bbp_virt_t hhdm_offset;        /* phys->virt offset (0 until known) */
    int verify_tag_crc;            /* 1 = check each tag's CRC on lookup */
};

/* Translate a physical address to a kernel-virtual one using the HHDM
 * offset. Before the offset is known (early boot, identity-mapped) pass
 * offset 0 and this is the identity. */
static inline void *bbp_phys_to_virt(const struct bbp_kctx *k, bbp_phys_t p)
{
    if (p == 0) return (void *)0;
    return (void *)(uintptr_t)(p + k->hhdm_offset);
}

/* Validate the handoff structure (magic, version, size, CRC64).
 * `info` is the pointer the bootloader put in RDI/X0/A0. On BBP_OK, `out`
 * is initialized with hhdm_offset taken from the HHDM tag if present. */
bbp_status_t bbp_init(struct bbp_kctx *out, const struct bbp_info *info);

/* Find the first tag with the given UUID. Returns NULL if absent.
 * When k->verify_tag_crc is set, a tag whose CRC fails is skipped (treated
 * as absent) — a corrupt tag must never be handed to a subsystem. */
const struct bbp_tag_header *bbp_find_tag(const struct bbp_kctx *k, uint64_t tag_id);

/* Iterate every tag. `cb` returns non-zero to stop early. `user` is opaque.
 * Returns the number of tags visited. */
typedef int (*bbp_tag_cb)(const struct bbp_tag_header *tag, void *user);
uint32_t bbp_for_each_tag(const struct bbp_kctx *k, bbp_tag_cb cb, void *user);

/* Convenience accessor for the trailing array of a variable-length tag.
 * Returns a pointer just past the fixed tag struct of `fixed_size` bytes. */
static inline const void *bbp_tag_payload(const struct bbp_tag_header *tag,
                                           size_t fixed_size)
{
    return (const void *)((const uint8_t *)tag + fixed_size);
}

/* SAFE trailing-array accessor. A tag declares its element count in its own
 * body (e.g. memory_map.entry_count), but a corrupt/malicious producer can
 * claim more elements than tag_size actually holds — a consumer that trusts
 * the count walks past the CRC'd region into adjacent memory (OOB read).
 * This clamps the usable count to what physically fits in tag_size and writes
 * it to *out_count. Returns the array base. ALWAYS iterate *out_count, not the
 * raw field. */
static inline const void *bbp_tag_array(const struct bbp_tag_header *tag,
                                        size_t fixed_size, size_t elem_size,
                                        uint32_t claimed, uint32_t *out_count)
{
    uint32_t fit = 0;
    if (elem_size && tag->tag_size > fixed_size) {
        size_t room = (size_t)tag->tag_size - fixed_size;
        size_t n = room / elem_size;
        fit = (n > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)n;
    }
    if (out_count) *out_count = (claimed < fit) ? claimed : fit;
    return (const void *)((const uint8_t *)tag + fixed_size);
}

/* Validate a kernel's Bear Header (magic, version, header_size, CRC64).
 * The bootloader calls this on the header it scraped from .bbp_hdr BEFORE
 * trusting entry_point / requests. v1.0 shipped with no such check. */
bbp_status_t bbp_verify_header(const struct bbp_header *hdr);

/* Verify an OUT-OF-LINE blob referenced by a tag (ADR-0006). `phys` is the
 * physical pointer stored in the tag, `len` its byte length, `expected_crc`
 * the sibling *_crc field. Returns:
 *   BBP_OK            CRC matches (or expected_crc==0 meaning "unchecked" AND
 *                     the caller passed allow_unchecked != 0),
 *   BBP_ERR_NULL      phys/len zero,
 *   BBP_ERR_SIZE      len exceeds the sane cap,
 *   BBP_ERR_TAG_CHECKSUM  CRC mismatch.
 * The blob is reached HHDM-aware via k. A consumer MUST call this before
 * trusting a measurement log / cmdline / EDID / dtb. */
bbp_status_t bbp_verify_blob(const struct bbp_kctx *k, bbp_phys_t phys,
                             size_t len, uint64_t expected_crc,
                             int allow_unchecked);

/* Like bbp_init, but seeds the HHDM offset from a caller-supplied hint when
 * the producer placed the tag list OUTSIDE the bootloader's identity map
 * (the HHDM chicken-and-egg: you may need the offset to read the HHDM tag).
 * Pass hint=0 for identity-mapped handoff (same as bbp_init). */
bbp_status_t bbp_init_ex(struct bbp_kctx *out, const struct bbp_info *info,
                         bbp_virt_t hhdm_hint);

/* Human-readable status string (static storage). */
const char *bbp_strstatus(bbp_status_t s);

#endif /* BBP_KERNEL_H */
