/*
 * bbp_build.h — bootloader-side Bear Boot Protocol tag builder.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * The bootloader carves a scratch arena out of memory it owns, appends tags
 * into it, then finalizes into a bbp_info. Every tag's CRC64 is sealed when
 * appended; the info CRC is sealed at finalize. All pointers written are
 * PHYSICAL (== arena address, since the loader runs identity-mapped).
 */
#ifndef BBP_BUILD_H
#define BBP_BUILD_H

#include <bbp/bbp.h>

struct bbp_builder {
    uint8_t   *arena;       /* virtual base of scratch (== phys when identity) */
    bbp_phys_t arena_phys;  /* physical base of arena */
    size_t     capacity;    /* bytes available */
    size_t     used;        /* bytes consumed */
    struct bbp_tag_header *last; /* last appended tag (for next_tag chaining) */
    bbp_phys_t first_phys;  /* phys of first tag, 0 until first append */
    uint32_t   tag_count;
    int        overflow;    /* set if any append exceeded capacity */
};

/* Initialize a builder over [arena, arena+capacity). arena_phys is the
 * physical address corresponding to arena (equal when identity-mapped). */
void bbp_builder_init(struct bbp_builder *b, void *arena,
                      bbp_phys_t arena_phys, size_t capacity);

/* Reserve `total_size` bytes for a tag of `tag_id`/`tag_version`, zero it,
 * stamp the tag_header, chain it after the previous tag, and return a
 * writable pointer to the tag. Returns NULL on overflow (and sets b->overflow).
 * The caller fills the body + any trailing array, then calls bbp_seal_tag(). */
void *bbp_alloc_tag(struct bbp_builder *b, uint64_t tag_id,
                    uint16_t tag_version, size_t total_size);

/* Optionally seal a tag's CRC64 early. NOTE: bbp_builder_finalize() re-seals
 * every tag authoritatively once the next_tag chain is complete, so calling
 * this is not required — it is kept for callers that want a valid CRC on a
 * tag before the list is finalized (e.g. incremental hashing). */
void bbp_seal_tag(struct bbp_builder *b, void *tag);

/* Append a NUL-terminated string into the arena, returns its phys addr
 * (helper for cmdline / metadata blobs). 0 on overflow. */
bbp_phys_t bbp_arena_strdup(struct bbp_builder *b, const char *s, uint32_t *out_len);

/* Append an arbitrary blob, returns its phys addr (8-byte aligned). */
bbp_phys_t bbp_arena_blob(struct bbp_builder *b, const void *data, size_t len);

/* Finalize: populate `info` (caller pre-fills bootloader_name/version/uuid/
 * timestamps/architecture/cpu_count), wire first_tag/tag_count/info_size,
 * re-seal EVERY tag's CRC (now that the next_tag chain is complete) and the
 * info CRC. Returns the physical address of `info` for the jump.
 *
 * PRECONDITION (ADR-0008): for `info_size` to be correct, `info` MUST sit
 * immediately before the builder arena and be contiguous with it (the
 * reference efi_main.c places info at the arena front). `info_size` is an
 * informational span only — never a security bound on tag pointers. */
bbp_phys_t bbp_builder_finalize(struct bbp_builder *b, struct bbp_info *info,
                                bbp_phys_t info_phys);

/* Compute the CRC64/XZ of a Bear Header with checksum=0, used by a post-link
 * stamping pass after entry_point / requests have been patched in. Returns
 * the value to store in hdr->checksum (does NOT write it). */
uint64_t bbp_header_crc(const struct bbp_header *hdr);

#endif /* BBP_BUILD_H */
