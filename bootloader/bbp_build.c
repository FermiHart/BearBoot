/*
 * bbp_build.c — bootloader-side Bear Boot Protocol tag builder.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 */
#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "bbp_build.h"

static void bbp_memzero(void *p, size_t n)
{
    uint8_t *b = (uint8_t *)p;
    while (n--) *b++ = 0;
}

static void bbp_memcpy(void *d, const void *s, size_t n)
{
    uint8_t *dd = (uint8_t *)d; const uint8_t *ss = (const uint8_t *)s;
    while (n--) *dd++ = *ss++;
}

#define BBP_BUILDER_MAX_TAG  (16u * 1024u * 1024u)
#define BBP_BUILDER_MAX_INFO (64u * 1024u * 1024u)
#define BBP_BUILDER_MAX_PHYS (1ULL << 48)
#define BBP_BUILDER_MAX_TAGS 1024u
#define BBP_BUILDER_SIZE_MAX ((size_t)-1)
#define BBP_BUILDER_U32_MAX  ((uint32_t)-1)

/* CRC64 over a struct with its 8-byte checksum field zeroed. */
static uint64_t bbp_crc_skip(const void *base, size_t len, size_t off)
{
    static const uint8_t zeros[8] = {0};
    uint64_t c = bbp_crc64_init();
    c = bbp_crc64_update(c, base, off);
    c = bbp_crc64_update(c, zeros, 8);
    c = bbp_crc64_update(c, (const uint8_t *)base + off + 8, len - off - 8);
    return bbp_crc64_final(c);
}

void bbp_builder_init(struct bbp_builder *b, void *arena,
                      bbp_phys_t arena_phys, size_t capacity)
{
    if (!b) return;
    b->arena      = (uint8_t *)arena;
    b->arena_phys = arena_phys;
    b->capacity   = capacity;
    b->used       = 0;
    b->last       = (void *)0;
    b->first_phys = 0;
    b->tag_count  = 0;
    b->overflow   = 0;
    if (arena)
        bbp_memzero(arena, capacity);
    else if (capacity)
        b->overflow = 1;
    if (arena && (arena_phys == 0 || (arena_phys & 7u) != 0
                  || arena_phys >= BBP_BUILDER_MAX_PHYS))
        b->overflow = 1;
}

/* Bump-allocate `len` bytes (8-byte aligned), return virtual ptr or NULL. */
static void *arena_bump(struct bbp_builder *b, size_t len, bbp_phys_t *out_phys)
{
    if (!b || !b->arena || b->overflow
        || b->used > BBP_BUILDER_SIZE_MAX - 7u) {
        if (b) b->overflow = 1;
        return (void *)0;
    }
    size_t start = (b->used + 7u) & ~(size_t)7u;
    /* Overflow-safe bound: check against remaining room, never compute
     * start+len (which can wrap on a huge untrusted len). */
    if (start > b->capacity || len > b->capacity - start) {
        b->overflow = 1; return (void *)0;
    }
    if (b->arena_phys > BBP_BUILDER_MAX_PHYS
        || (bbp_phys_t)start > BBP_BUILDER_MAX_PHYS - b->arena_phys) {
        b->overflow = 1; return (void *)0;
    }
    bbp_phys_t phys = b->arena_phys + (bbp_phys_t)start;
    if (len > BBP_BUILDER_MAX_PHYS - phys) {
        b->overflow = 1; return (void *)0;
    }
    void *p = b->arena + start;
    if (out_phys) *out_phys = phys;
    b->used = start + len;
    return p;
}

void *bbp_alloc_tag(struct bbp_builder *b, uint64_t tag_id,
                    uint16_t tag_version, size_t total_size)
{
    if (!b || total_size < sizeof(struct bbp_tag_header)
        || total_size > BBP_BUILDER_MAX_TAG
        || total_size > BBP_BUILDER_U32_MAX
        || b->tag_count >= BBP_BUILDER_MAX_TAGS) {
        if (b) b->overflow = 1;
        return (void *)0;
    }

    bbp_phys_t phys;
    struct bbp_tag_header *tag =
        (struct bbp_tag_header *)arena_bump(b, total_size, &phys);
    if (!tag) return (void *)0;

    tag->tag_id     = tag_id;
    tag->tag_size   = (uint32_t)total_size;
    tag->tag_version= tag_version;
    tag->flags      = BBP_TF_NONE;
    tag->next_tag   = 0;
    tag->checksum   = 0;

    if (b->last) b->last->next_tag = phys;
    else         b->first_phys     = phys;

    b->last = tag;
    b->tag_count++;
    return tag;
}

void bbp_seal_tag(struct bbp_builder *b, void *tag)
{
    (void)b;
    struct bbp_tag_header *h = (struct bbp_tag_header *)tag;
    h->checksum = bbp_crc_skip(h, h->tag_size,
                               offsetof(struct bbp_tag_header, checksum));
}

/* Translate a phys addr inside the builder arena to its virtual pointer. */
static void *builder_phys_to_virt(struct bbp_builder *b, bbp_phys_t p)
{
    return b->arena + (size_t)(p - b->arena_phys);
}

bbp_phys_t bbp_arena_strdup_n(struct bbp_builder *b, const char *s,
                              size_t source_bytes, uint32_t *out_len)
{
    size_t len = 0;
    if (out_len) *out_len = 0;
    if (!b || !s || source_bytes == 0) {
        if (b) b->overflow = 1;
        return 0;
    }
    while (len < source_bytes && s[len]) len++;
    if (len == source_bytes || len > BBP_BUILDER_U32_MAX) {
        b->overflow = 1;
        return 0;
    }
    bbp_phys_t phys;
    void *p = arena_bump(b, len + 1, &phys);
    if (!p) return 0;
    bbp_memcpy(p, s, len);
    ((uint8_t *)p)[len] = 0;
    if (out_len) *out_len = (uint32_t)len;
    return phys;
}

bbp_phys_t bbp_arena_strdup(struct bbp_builder *b, const char *s, uint32_t *out_len)
{
    return bbp_arena_strdup_n(b, s, BBP_BUILDER_SIZE_MAX, out_len);
}

bbp_phys_t bbp_arena_blob(struct bbp_builder *b, const void *data, size_t len)
{
    if (!b || (!data && len != 0)) {
        if (b) b->overflow = 1;
        return 0;
    }
    if (len == 0) return 0;
    bbp_phys_t phys;
    void *p = arena_bump(b, len, &phys);
    if (!p) return 0;
    bbp_memcpy(p, data, len);
    return phys;
}

bbp_phys_t bbp_builder_finalize(struct bbp_builder *b, struct bbp_info *info,
                                 bbp_phys_t info_phys)
{
    if (!b || !info) return 0;
    if (b->overflow || b->tag_count > BBP_BUILDER_MAX_TAGS
        || b->used > b->capacity
        || b->used > BBP_BUILDER_MAX_INFO - sizeof(struct bbp_info)) {
        b->overflow = 1;
        return 0;
    }
    /* Re-seal EVERY tag now that the chain (next_tag) is fully wired. A tag's
     * next_tag is written when its successor is appended, AFTER any earlier
     * bbp_seal_tag() call — so the authoritative CRC can only be computed once
     * the list is complete. Walk the arena from the first tag and seal each. */
    bbp_phys_t cur = b->first_phys;
    while (cur) {
        struct bbp_tag_header *h =
            (struct bbp_tag_header *)builder_phys_to_virt(b, cur);
        h->checksum = bbp_crc_skip(h, h->tag_size,
                                   offsetof(struct bbp_tag_header, checksum));
        cur = h->next_tag;
    }

    info->version_major = BBP_VERSION_MAJOR;
    info->version_minor = BBP_VERSION_MINOR;
    bbp_memzero(info->magic, sizeof(info->magic));
    bbp_memcpy(info->magic, BBP_INFO_MAGIC, sizeof(BBP_INFO_MAGIC) - 1);

    info->tag_count    = b->tag_count;
    info->first_tag    = b->first_phys;
    /* info_size spans the info struct plus everything in the arena. */
    info->info_size    = (uint32_t)(sizeof(struct bbp_info) + b->used);
    info->checksum     = 0;
    info->checksum     = bbp_crc_skip(info, sizeof(struct bbp_info),
                                      offsetof(struct bbp_info, checksum));
    return info_phys;
}

uint64_t bbp_header_crc(const struct bbp_header *hdr)
{
    return bbp_crc_skip(hdr, sizeof(struct bbp_header),
                        offsetof(struct bbp_header, checksum));
}
