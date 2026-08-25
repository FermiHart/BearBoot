/*
 * elf64_loader.h - bounded, firmware-independent ELF64 load planner.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_UEFI_ELF64_LOADER_H
#define BBP_UEFI_ELF64_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define BBP_ELF64_MAX_PROGRAM_HEADERS 32u
#define BBP_ELF64_MAX_LOAD_SEGMENTS 16u
#define BBP_ELF64_PAGE_SIZE 4096u

#define BBP_ELF64_PF_X 0x1u
#define BBP_ELF64_PF_W 0x2u
#define BBP_ELF64_PF_R 0x4u

typedef enum bbp_elf64_status {
    BBP_ELF64_OK = 0,
    BBP_ELF64_ERR_ARGUMENT,
    BBP_ELF64_ERR_TRUNCATED,
    BBP_ELF64_ERR_FORMAT,
    BBP_ELF64_ERR_PROGRAM_HEADERS,
    BBP_ELF64_ERR_SEGMENT_LIMIT,
    BBP_ELF64_ERR_FILE_RANGE,
    BBP_ELF64_ERR_MEMORY_SIZE,
    BBP_ELF64_ERR_OVERFLOW,
    BBP_ELF64_ERR_ALIGNMENT,
    BBP_ELF64_ERR_ADDRESS,
    BBP_ELF64_ERR_PHYSICAL_LIMIT,
    BBP_ELF64_ERR_PAGE_OVERLAP,
    BBP_ELF64_ERR_WX,
    BBP_ELF64_ERR_ENTRY
} bbp_elf64_status;

struct bbp_elf64_segment_plan {
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t memory_size;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint64_t page_base;
    uint64_t page_count;
    uint64_t alignment;
    uint32_t flags;
};

struct bbp_elf64_plan {
    uint64_t entry;
    uint64_t physical_base;
    uint64_t physical_end;
    size_t segment_count;
    struct bbp_elf64_segment_plan segments[BBP_ELF64_MAX_LOAD_SEGMENTS];
};

/* physical_end is exclusive. On failure, plan is left byte-for-byte intact. */
bbp_elf64_status bbp_elf64_plan(const void *image, size_t image_size,
                                struct bbp_elf64_plan *plan);

#endif /* BBP_UEFI_ELF64_LOADER_H */
