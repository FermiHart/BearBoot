/* SPDX-License-Identifier: BSD-3-Clause */
/* Experimental BBP v2 capsule framing. Not a frozen or deployed boot ABI. */
#ifndef BBP_V2_H
#define BBP_V2_H

#include <stddef.h>
#include <stdint.h>

#define BBP_V2_VERSION_MAJOR 2u
#define BBP_V2_VERSION_MINOR 0u
#define BBP_V2_MAGIC_BYTES { 'B', 'B', 'P', '2', 'C', 'A', 'P', 0 }

#define BBP_V2_HEADER_SIZE    64u
#define BBP_V2_DIRENT_SIZE    48u
#define BBP_V2_MAX_ENTRIES    1024u
#define BBP_V2_MAX_ALIGNMENT  4096u
#define BBP_V2_MAX_EXTENT     (64u * 1024u * 1024u)
#define BBP_V2_MAX_CRC_WORK   (96u * 1024u * 1024u)

/* Wire fields are little-endian. Consumers must not dereference these packed
 * integer members on strict-alignment or big-endian targets; use the parser. */
struct bbp_v2_header {
    uint8_t  magic[8];
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t header_size;
    uint16_t directory_entry_size;
    uint32_t flags;
    uint32_t entry_count;
    uint64_t total_size;
    uint64_t directory_offset;
    uint64_t checksum;
    uint64_t reserved0;
    uint64_t reserved1;
} __attribute__((packed));

struct bbp_v2_directory_entry {
    uint64_t type;
    uint32_t flags;
    uint16_t version;
    uint16_t reserved0;
    uint64_t offset;
    uint64_t size;
    uint64_t checksum;
    uint32_t alignment;
    uint32_t reserved1;
} __attribute__((packed));

_Static_assert(sizeof(struct bbp_v2_header) == BBP_V2_HEADER_SIZE,
               "bbp_v2_header ABI");
_Static_assert(offsetof(struct bbp_v2_header, magic) == 0,
               "bbp_v2_header.magic ABI");
_Static_assert(offsetof(struct bbp_v2_header, version_major) == 8,
               "bbp_v2_header.version_major ABI");
_Static_assert(offsetof(struct bbp_v2_header, version_minor) == 10,
               "bbp_v2_header.version_minor ABI");
_Static_assert(offsetof(struct bbp_v2_header, header_size) == 12,
               "bbp_v2_header.header_size ABI");
_Static_assert(offsetof(struct bbp_v2_header, directory_entry_size) == 14,
               "bbp_v2_header.directory_entry_size ABI");
_Static_assert(offsetof(struct bbp_v2_header, flags) == 16,
               "bbp_v2_header.flags ABI");
_Static_assert(offsetof(struct bbp_v2_header, entry_count) == 20,
               "bbp_v2_header.entry_count ABI");
_Static_assert(offsetof(struct bbp_v2_header, total_size) == 24,
               "bbp_v2_header.total_size ABI");
_Static_assert(offsetof(struct bbp_v2_header, directory_offset) == 32,
               "bbp_v2_header.directory_offset ABI");
_Static_assert(offsetof(struct bbp_v2_header, checksum) == 40,
               "bbp_v2_header.checksum ABI");
_Static_assert(offsetof(struct bbp_v2_header, reserved0) == 48,
               "bbp_v2_header.reserved0 ABI");
_Static_assert(offsetof(struct bbp_v2_header, reserved1) == 56,
               "bbp_v2_header.reserved1 ABI");
_Static_assert(sizeof(struct bbp_v2_directory_entry) == BBP_V2_DIRENT_SIZE,
               "bbp_v2_directory_entry ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, type) == 0,
               "bbp_v2_directory_entry.type ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, flags) == 8,
               "bbp_v2_directory_entry.flags ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, version) == 12,
               "bbp_v2_directory_entry.version ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, reserved0) == 14,
               "bbp_v2_directory_entry.reserved0 ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, offset) == 16,
               "bbp_v2_directory_entry.offset ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, size) == 24,
               "bbp_v2_directory_entry.size ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, checksum) == 32,
               "bbp_v2_directory_entry.checksum ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, alignment) == 40,
               "bbp_v2_directory_entry.alignment ABI");
_Static_assert(offsetof(struct bbp_v2_directory_entry, reserved1) == 44,
               "bbp_v2_directory_entry.reserved1 ABI");

/* Directory flags used by the v1 bridge. Other entry types remain opaque to
 * the core parser and are accepted without a registry dependency. */
#define BBP_V2_EF_EXTERNAL_PHYS (1u << 0)
#define BBP_V2_EF_V1_WIRE       (1u << 1)

typedef enum bbp_v2_status {
    BBP_V2_OK = 0,
    BBP_V2_ERR_NULL,
    BBP_V2_ERR_MAGIC,
    BBP_V2_ERR_VERSION,
    BBP_V2_ERR_FORMAT,
    BBP_V2_ERR_EXTENT,
    BBP_V2_ERR_OVERFLOW,
    BBP_V2_ERR_COUNT,
    BBP_V2_ERR_ALIGNMENT,
    BBP_V2_ERR_OVERLAP,
    BBP_V2_ERR_PADDING,
    BBP_V2_ERR_CRC,
    BBP_V2_ERR_WORK,
    BBP_V2_ERR_CAPACITY,
    BBP_V2_ERR_POLICY,
    BBP_V2_ERR_SOURCE
} bbp_v2_status_t;

struct bbp_v2_view {
    const uint8_t *data;
    size_t total_size;
    size_t directory_offset;
    uint32_t flags;
    uint32_t entry_count;
};

struct bbp_v2_entry_view {
    uint64_t type;
    uint32_t flags;
    uint16_t version;
    uint32_t alignment;
    uint64_t offset;
    size_t size;
    uint64_t checksum;
    const uint8_t *data;
};

struct bbp_v2_build_entry {
    uint64_t type;
    uint32_t flags;
    uint16_t version;
    uint32_t alignment;
    const void *data;
    size_t size;
};

typedef void (*bbp_v2_digest_update_fn)(void *state, const void *data,
                                         size_t size);

/* Successful views borrow capsule storage. The complete supplied extent must
 * remain readable and immutable while a view or derived entry is in use. */
bbp_v2_status_t bbp_v2_parse(const void *capsule, size_t extent,
                              struct bbp_v2_view *out);
bbp_v2_status_t bbp_v2_get_entry(const struct bbp_v2_view *view,
                                 uint32_t index,
                                 struct bbp_v2_entry_view *out);
/* Aliases involving written and errors that prevent proving its disjointness
 * leave written unchanged; other failures set it to zero. */
bbp_v2_status_t bbp_v2_build(void *output, size_t capacity,
                              const struct bbp_v2_build_entry *entries,
                              uint32_t entry_count, size_t *written);
/* The update callback must not mutate the borrowed capsule extent. */
bbp_v2_status_t bbp_v2_digest(const struct bbp_v2_view *view,
                               bbp_v2_digest_update_fn update, void *state);
const char *bbp_v2_strstatus(bbp_v2_status_t status);

#endif
