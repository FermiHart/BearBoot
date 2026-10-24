/* SPDX-License-Identifier: BSD-3-Clause */
/* Experimental BBP v2 Profile 0 semantics. Not a frozen wire ABI. */
#ifndef BBP_V2_PROFILE_H
#define BBP_V2_PROFILE_H

#include <bbp/bbp_v2.h>

#define BBP_V2_P0_BOOT_IDENTITY  0x4242503200000001ull
#define BBP_V2_P0_MEMORY_MAP     0x4242503200000002ull
#define BBP_V2_P0_KERNEL_ADDRESS 0x4242503200000003ull
#define BBP_V2_P0_DEVICETREE     0x4242503200000004ull
#define BBP_V2_P0_VERSION 1u
#define BBP_V2_P0_MEMORY_ENTRY_SIZE 32u

struct bbp_v2_p0_identity {
    uint16_t architecture;
    uint16_t reserved0;
    uint32_t cpu_count;
    uint32_t flags;
    uint32_t reserved1;
} __attribute__((packed));

struct bbp_v2_p0_memory_header {
    uint32_t entry_count;
    uint32_t entry_size;
} __attribute__((packed));

struct bbp_v2_p0_memory_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t attributes;
    uint32_t numa_node;
    uint32_t reserved;
} __attribute__((packed));

struct bbp_v2_p0_kernel_address {
    uint64_t physical_base;
    uint64_t virtual_base;
} __attribute__((packed));

struct bbp_v2_p0_devicetree_header {
    uint32_t flags;
    uint32_t dtb_size;
} __attribute__((packed));

_Static_assert(sizeof(struct bbp_v2_p0_identity) == 16, "p0 identity ABI");
_Static_assert(offsetof(struct bbp_v2_p0_identity, architecture) == 0,
               "p0 identity architecture ABI");
_Static_assert(offsetof(struct bbp_v2_p0_identity, reserved0) == 2,
               "p0 identity reserved0 ABI");
_Static_assert(offsetof(struct bbp_v2_p0_identity, cpu_count) == 4,
               "p0 identity cpu_count ABI");
_Static_assert(offsetof(struct bbp_v2_p0_identity, flags) == 8,
               "p0 identity flags ABI");
_Static_assert(offsetof(struct bbp_v2_p0_identity, reserved1) == 12,
               "p0 identity reserved1 ABI");
_Static_assert(sizeof(struct bbp_v2_p0_memory_header) == 8,
               "p0 memory header ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_header, entry_count) == 0,
               "p0 memory header count ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_header, entry_size) == 4,
               "p0 memory header stride ABI");
_Static_assert(sizeof(struct bbp_v2_p0_memory_entry) == 32,
               "p0 memory entry ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, base) == 0,
               "p0 memory entry base ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, length) == 8,
               "p0 memory entry length ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, type) == 16,
               "p0 memory entry type ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, attributes) == 20,
               "p0 memory entry attributes ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, numa_node) == 24,
               "p0 memory entry numa ABI");
_Static_assert(offsetof(struct bbp_v2_p0_memory_entry, reserved) == 28,
               "p0 memory entry reserved ABI");
_Static_assert(sizeof(struct bbp_v2_p0_kernel_address) == 16,
               "p0 kernel ABI");
_Static_assert(offsetof(struct bbp_v2_p0_kernel_address, physical_base) == 0,
               "p0 kernel physical ABI");
_Static_assert(offsetof(struct bbp_v2_p0_kernel_address, virtual_base) == 8,
               "p0 kernel virtual ABI");
_Static_assert(sizeof(struct bbp_v2_p0_devicetree_header) == 8,
               "p0 Device Tree header ABI");
_Static_assert(offsetof(struct bbp_v2_p0_devicetree_header, flags) == 0,
               "p0 Device Tree flags ABI");
_Static_assert(offsetof(struct bbp_v2_p0_devicetree_header, dtb_size) == 4,
               "p0 Device Tree size ABI");

struct bbp_v2_p0_view {
    uint16_t architecture;
    uint32_t cpu_count;
    uint32_t memory_entry_count;
    uint64_t kernel_physical_base;
    uint64_t kernel_virtual_base;
    const uint8_t *dtb;
    uint32_t dtb_size;
};

/* Revalidates the complete borrowed capsule before applying Profile 0. Failure
 * leaves out unchanged. A successful out->dtb borrows the capsule extent. */
bbp_v2_status_t bbp_v2_p0_validate(const struct bbp_v2_view *capsule,
                                    struct bbp_v2_p0_view *out);

#endif
