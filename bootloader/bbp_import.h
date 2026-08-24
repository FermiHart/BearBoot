/*
 * bbp_import.h - bounded boot-source importers for the BBP builder.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_IMPORT_H
#define BBP_IMPORT_H

#include <stdint.h>
#include <stddef.h>

#include "bbp_build.h"

#define BBP_IMPORT_MAX_TAG_SIZE (16u * 1024u * 1024u)
#define BBP_IMPORT_MAX_PHYS     (1ULL << 48)
#define BBP_IMPORT_MAX_TAGS     1024u
#define BBP_IMPORT_MAX_ARENA    (64u * 1024u * 1024u - sizeof(struct bbp_info))
#define BBP_IMPORT_SIZE_MAX     ((size_t)-1)
#define BBP_IMPORT_U16_MAX      ((uint16_t)-1)
#define BBP_IMPORT_U32_MAX      ((uint32_t)-1)
#define BBP_IMPORT_U64_MAX      ((uint64_t)-1)
#define BBP_IMPORT_UINTPTR_MAX  ((uintptr_t)-1)

typedef enum bbp_import_status {
    BBP_IMPORT_OK = 0,
    BBP_IMPORT_ERR_NULL,
    BBP_IMPORT_ERR_FLAGS,
    BBP_IMPORT_ERR_BUILDER,
    BBP_IMPORT_ERR_CAPACITY,
    BBP_IMPORT_ERR_COUNT,
    BBP_IMPORT_ERR_OVERFLOW,
    BBP_IMPORT_ERR_RANGE,
    BBP_IMPORT_ERR_FRAMING,
    BBP_IMPORT_ERR_DUPLICATE,
    BBP_IMPORT_ERR_STRING,
    BBP_IMPORT_ERR_UNSUPPORTED,
    BBP_IMPORT_ERR_NON_FINAL
} bbp_import_status;

enum bbp_import_presence {
    BBP_IMPORT_HAS_HHDM           = 1ULL << 0,
    BBP_IMPORT_HAS_MEMORY_MAP     = 1ULL << 1,
    BBP_IMPORT_HAS_KERNEL_ADDRESS = 1ULL << 2,
    BBP_IMPORT_HAS_SMP            = 1ULL << 3,
    BBP_IMPORT_HAS_CMDLINE        = 1ULL << 4,
    BBP_IMPORT_HAS_FRAMEBUFFER    = 1ULL << 5,
    BBP_IMPORT_HAS_ACPI           = 1ULL << 6,
    BBP_IMPORT_HAS_EFI            = 1ULL << 7,
    BBP_IMPORT_HAS_SMBIOS         = 1ULL << 8
};

struct bbp_import_string {
    const uint8_t *data;
    size_t bytes;                 /* includes exactly one trailing NUL */
};

struct bbp_import_framebuffer {
    bbp_phys_t address;
    uint64_t total_size;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t pixel_format;        /* BBP_FB_* */
    uint16_t color_depth;         /* bits per channel */
    uint16_t flags;               /* BBP_FB_FLAG_* */
};

struct bbp_import_acpi {
    bbp_phys_t rsdp_address;
    bbp_phys_t xsdt_address;
    uint32_t oem_id;
    uint16_t acpi_version;
    uint16_t flags;               /* BBP_ACPI_FLAG_* */
};

struct bbp_limine_mmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;                /* Limine values 0..7; unknown is reserved */
};

struct bbp_limine_cpu {
    uint32_t processor_id;
    uint32_t apic_id;
};

struct bbp_limine_snapshot {
    uint64_t present;             /* BBP_IMPORT_HAS_* */
    bbp_virt_t hhdm_offset;
    bbp_phys_t kernel_physical_base;
    bbp_virt_t kernel_virtual_base;

    const struct bbp_limine_mmap_entry *memory_map;
    uint64_t memory_map_count;

    const struct bbp_limine_cpu *cpus;
    uint64_t cpu_count;
    uint32_t bsp_apic_id;
    uint8_t x2apic;
    uint8_t reserved0[3];

    struct bbp_import_string command_line;
    struct bbp_import_framebuffer framebuffer;
    struct bbp_import_acpi acpi;
};

struct bbp_multiboot2_snapshot {
    const void *mbi;
    size_t mapped_bytes;
    uint64_t present;             /* optional HHDM/KERNEL_ADDRESS sideband */
    bbp_virt_t hhdm_offset;
    bbp_phys_t kernel_physical_base;
    bbp_virt_t kernel_virtual_base;
};

struct bbp_uefi_snapshot {
    uint64_t present;             /* BBP_IMPORT_HAS_* */
    bbp_virt_t hhdm_offset;
    bbp_phys_t kernel_physical_base;
    bbp_virt_t kernel_virtual_base;

    const void *memory_map;
    size_t memory_map_bytes;
    uint64_t descriptor_stride;
    uint32_t descriptor_version;
    uint8_t memory_map_final;     /* captured after the successful EBS map */
    uint8_t reserved0[3];

    bbp_phys_t system_table;
    struct bbp_import_string command_line;
    struct bbp_import_framebuffer framebuffer;
    struct bbp_import_acpi acpi;
    bbp_phys_t smbios_32;
    bbp_phys_t smbios_64;
};

bbp_import_status bbp_import_limine(struct bbp_builder *builder,
                                    const struct bbp_limine_snapshot *snapshot);
bbp_import_status bbp_import_multiboot2(struct bbp_builder *builder,
                                        const struct bbp_multiboot2_snapshot *snapshot);

/* This consumes a normalized UEFI snapshot. Despite the historical function
 * name, it does not parse a PI HOB binary or dereference firmware structures. */
bbp_import_status bbp_import_uefi_hobs(struct bbp_builder *builder,
                                       const struct bbp_uefi_snapshot *snapshot);

const char *bbp_import_strstatus(bbp_import_status status);

/* Shared implementation support. Importers finish a complete plan before
 * calling any builder function, making every reported error failure-atomic. */
struct bbp_import_plan {
    size_t used;
    uint32_t tag_count;
};

bbp_import_status bbp_import_plan_begin(const struct bbp_builder *builder,
                                        struct bbp_import_plan *plan);
bbp_import_status bbp_import_plan_tag(const struct bbp_builder *builder,
                                      struct bbp_import_plan *plan, size_t bytes);
bbp_import_status bbp_import_plan_blob(const struct bbp_builder *builder,
                                       struct bbp_import_plan *plan, size_t bytes);
bbp_import_status bbp_import_array_tag_size(size_t fixed, uint64_t count,
                                            size_t element, size_t *out);
bbp_import_status bbp_import_validate_string(struct bbp_import_string string);
bbp_import_status bbp_import_validate_framebuffer(
    const struct bbp_import_framebuffer *framebuffer);
int bbp_import_phys_address_valid(bbp_phys_t address, int allow_zero);
int bbp_import_phys_range_valid(bbp_phys_t base, uint64_t length);
int bbp_import_ranges_overlap(const void *left, size_t left_bytes,
                              const void *right, size_t right_bytes);
size_t bbp_import_utf8_prefix(const uint8_t *text, size_t bytes, size_t limit);
void bbp_import_memcpy(void *destination, const void *source, size_t bytes);
void bbp_import_memzero(void *destination, size_t bytes);

#endif /* BBP_IMPORT_H */
