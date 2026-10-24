/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef BBP_BRIDGE_H
#define BBP_BRIDGE_H

#include <bbp/bbp.h>
#include <bbp/bbp_v2.h>

#define BBP_V2_ENTRY_V1_INFO UINT64_C(0x000100000000fff0)
#define BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS (1u << 0)

/* A normalized copy of the non-linkage fields in bbp_info. */
struct bbp_v2_v1_info_payload {
    uint8_t bootloader_name[32];
    uint8_t bootloader_version[16];
    uint8_t bootloader_uuid[16];
    uint64_t bootloader_start_ts;
    uint64_t kernel_load_ts;
    uint64_t handoff_ts;
    uint16_t architecture;
    uint16_t cpu_count;
    uint32_t reserved;
    uint64_t next_context;
} __attribute__((packed));

_Static_assert(sizeof(struct bbp_v2_v1_info_payload) == 104,
               "bbp_v2_v1_info_payload ABI");
_Static_assert(offsetof(struct bbp_v2_v1_info_payload, next_context) == 96,
               "bbp_v2_v1_info_payload.next_context ABI");

typedef const void *(*bbp_v2_phys_map_fn)(void *user, bbp_phys_t address,
                                           size_t size);

/* info and every span returned by map must remain immutable for the complete
 * conversion. map must cover exactly the requested physical byte range. */
struct bbp_v2_v1_source {
    const struct bbp_info *info;
    bbp_v2_phys_map_fn map;
    void *map_user;
};

struct bbp_v2_bridge_report {
    uint32_t tag_count;
    /* Includes normalized INFO when its next_context is nonzero. */
    uint32_t external_reference_entries;
};

/* Caller-owned bounded scratch. It is intentionally explicit: bridge calls
 * never allocate and never hide a large stack frame in early boot code.
 * It must not overlap the source, destination, or result controls. */
struct bbp_v2_bridge_workspace {
    bbp_phys_t visited[BBP_V2_MAX_ENTRIES];
    struct bbp_v2_build_entry entries[BBP_V2_MAX_ENTRIES + 1u];
    struct bbp_v2_v1_info_payload info_payload;
};

bbp_v2_status_t bbp_v2_from_v1(
    const struct bbp_v2_v1_source *source, uint32_t policy,
    struct bbp_v2_bridge_workspace *workspace,
    void *output, size_t capacity, size_t *written,
    struct bbp_v2_bridge_report *report);

bbp_v2_status_t bbp_v2_to_v1(
    const struct bbp_v2_view *source, uint32_t policy,
    void *output, size_t capacity, bbp_phys_t output_phys,
    size_t *written, struct bbp_v2_bridge_report *report);

#endif
