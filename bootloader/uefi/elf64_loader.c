/*
 * elf64_loader.c - bounded, allocation-free ELF64 load planner.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "elf64_loader.h"

#define ELF64_HEADER_SIZE 64u
#define ELF64_PROGRAM_HEADER_SIZE 56u
#define ELF64_PT_LOAD 1u
#define ELF64_ET_EXEC 2u
#define ELF64_EM_X86_64 62u
#define ELF64_EV_CURRENT 1u
#define ELF64_PHYSICAL_LIMIT UINT64_C(0x0001000000000000)
#define ELF64_LOWER_CANONICAL_END UINT64_C(0x0000800000000000)
#define ELF64_UPPER_CANONICAL_START UINT64_C(0xffff800000000000)

static uint16_t read16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] |
                      ((uint16_t)bytes[1] << 8));
}

static uint32_t read32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t read64(const uint8_t *bytes)
{
    uint64_t value = 0u;
    unsigned i;

    for (i = 0u; i < 8u; i++)
        value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

static int add_u64(uint64_t left, uint64_t right, uint64_t *sum)
{
    if (left > UINT64_MAX - right) return 0;
    *sum = left + right;
    return 1;
}

static unsigned canonical_region(uint64_t address)
{
    if (address < ELF64_LOWER_CANONICAL_END) return 1u;
    if (address >= ELF64_UPPER_CANONICAL_START) return 2u;
    return 0u;
}

static int canonical_range(uint64_t start, uint64_t end)
{
    unsigned start_region = canonical_region(start);

    if (start_region == 0u) return 0;
    if (start == end) return 1;
    return canonical_region(end - 1u) == start_region;
}

static int power_of_two(uint64_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static int ranges_overlap(uint64_t first_start, uint64_t first_end,
                          uint64_t second_start, uint64_t second_end)
{
    return first_start < second_end && second_start < first_end;
}

static void publish_plan(struct bbp_elf64_plan *destination,
                         const struct bbp_elf64_plan *source)
{
    size_t i;

    destination->entry = source->entry;
    destination->physical_base = source->physical_base;
    destination->physical_end = source->physical_end;
    destination->segment_count = source->segment_count;
    for (i = 0u; i < source->segment_count; i++) {
        destination->segments[i].file_offset =
            source->segments[i].file_offset;
        destination->segments[i].file_size = source->segments[i].file_size;
        destination->segments[i].memory_size =
            source->segments[i].memory_size;
        destination->segments[i].virtual_address =
            source->segments[i].virtual_address;
        destination->segments[i].physical_address =
            source->segments[i].physical_address;
        destination->segments[i].page_base = source->segments[i].page_base;
        destination->segments[i].page_count = source->segments[i].page_count;
        destination->segments[i].alignment = source->segments[i].alignment;
        destination->segments[i].flags = source->segments[i].flags;
    }
}

bbp_elf64_status bbp_elf64_plan(const void *image, size_t image_size,
                                struct bbp_elf64_plan *plan)
{
    const uint8_t *bytes = (const uint8_t *)image;
    struct bbp_elf64_plan candidate;
    uint64_t program_offset;
    uint64_t program_bytes;
    uint64_t program_end;
    uint64_t entry;
    uint16_t program_count;
    unsigned entry_covered = 0u;
    unsigned have_envelope = 0u;
    unsigned i;

    if (image == NULL || plan == NULL) return BBP_ELF64_ERR_ARGUMENT;
    if (image_size < ELF64_HEADER_SIZE) return BBP_ELF64_ERR_TRUNCATED;
    if (bytes[0] != 0x7fu || bytes[1] != (uint8_t)'E' ||
        bytes[2] != (uint8_t)'L' || bytes[3] != (uint8_t)'F' ||
        bytes[4] != 2u || bytes[5] != 1u || bytes[6] != ELF64_EV_CURRENT ||
        read16(bytes + 16u) != ELF64_ET_EXEC ||
        read16(bytes + 18u) != ELF64_EM_X86_64 ||
        read32(bytes + 20u) != ELF64_EV_CURRENT ||
        read16(bytes + 52u) != ELF64_HEADER_SIZE)
        return BBP_ELF64_ERR_FORMAT;

    entry = read64(bytes + 24u);
    if (canonical_region(entry) == 0u) return BBP_ELF64_ERR_ADDRESS;
    program_offset = read64(bytes + 32u);
    program_count = read16(bytes + 56u);
    if (read16(bytes + 54u) != ELF64_PROGRAM_HEADER_SIZE ||
        program_count == 0u ||
        program_count > BBP_ELF64_MAX_PROGRAM_HEADERS)
        return BBP_ELF64_ERR_PROGRAM_HEADERS;

    program_bytes = (uint64_t)program_count * ELF64_PROGRAM_HEADER_SIZE;
    if (!add_u64(program_offset, program_bytes, &program_end))
        return BBP_ELF64_ERR_OVERFLOW;
    if (program_end > (uint64_t)image_size)
        return BBP_ELF64_ERR_TRUNCATED;

    candidate.entry = entry;
    candidate.physical_base = 0u;
    candidate.physical_end = 0u;
    candidate.segment_count = 0u;

    for (i = 0u; i < program_count; i++) {
        const uint8_t *header = bytes + (size_t)program_offset +
                                (size_t)i * ELF64_PROGRAM_HEADER_SIZE;
        struct bbp_elf64_segment_plan *segment;
        uint32_t type = read32(header);
        uint32_t flags;
        uint64_t file_offset;
        uint64_t virtual_address;
        uint64_t physical_address;
        uint64_t file_size;
        uint64_t memory_size;
        uint64_t alignment;
        uint64_t file_end;
        uint64_t virtual_end;
        uint64_t physical_end;
        uint64_t page_end;
        size_t previous;

        if (type != ELF64_PT_LOAD) continue;
        if (candidate.segment_count == BBP_ELF64_MAX_LOAD_SEGMENTS)
            return BBP_ELF64_ERR_SEGMENT_LIMIT;

        flags = read32(header + 4u);
        file_offset = read64(header + 8u);
        virtual_address = read64(header + 16u);
        physical_address = read64(header + 24u);
        file_size = read64(header + 32u);
        memory_size = read64(header + 40u);
        alignment = read64(header + 48u);

        if (file_size > memory_size) return BBP_ELF64_ERR_MEMORY_SIZE;
        if ((flags & (BBP_ELF64_PF_W | BBP_ELF64_PF_X)) ==
            (BBP_ELF64_PF_W | BBP_ELF64_PF_X))
            return BBP_ELF64_ERR_WX;
        if (alignment > 1u) {
            uint64_t mask;
            if (!power_of_two(alignment)) return BBP_ELF64_ERR_ALIGNMENT;
            mask = alignment - 1u;
            if ((file_offset & mask) != (virtual_address & mask) ||
                (file_offset & mask) != (physical_address & mask))
                return BBP_ELF64_ERR_ALIGNMENT;
        }

        if (!add_u64(file_offset, file_size, &file_end) ||
            !add_u64(virtual_address, memory_size, &virtual_end) ||
            !add_u64(physical_address, memory_size, &physical_end))
            return BBP_ELF64_ERR_OVERFLOW;
        if (((virtual_address ^ physical_address) &
             (BBP_ELF64_PAGE_SIZE - 1u)) != 0u)
            return BBP_ELF64_ERR_ALIGNMENT;
        if (file_end > (uint64_t)image_size)
            return BBP_ELF64_ERR_FILE_RANGE;
        if (!canonical_range(virtual_address, virtual_end))
            return BBP_ELF64_ERR_ADDRESS;
        if (physical_address >= ELF64_PHYSICAL_LIMIT ||
            physical_end > ELF64_PHYSICAL_LIMIT)
            return BBP_ELF64_ERR_PHYSICAL_LIMIT;

        segment = &candidate.segments[candidate.segment_count];
        segment->file_offset = file_offset;
        segment->file_size = file_size;
        segment->memory_size = memory_size;
        segment->virtual_address = virtual_address;
        segment->physical_address = physical_address;
        segment->alignment = alignment;
        segment->flags = flags;
        segment->page_base = physical_address &
                             ~((uint64_t)BBP_ELF64_PAGE_SIZE - 1u);
        if (memory_size == 0u) {
            page_end = segment->page_base;
        } else {
            page_end = (physical_end + BBP_ELF64_PAGE_SIZE - 1u) &
                       ~((uint64_t)BBP_ELF64_PAGE_SIZE - 1u);
        }
        segment->page_count =
            (page_end - segment->page_base) / BBP_ELF64_PAGE_SIZE;

        if (segment->page_count != 0u) {
            for (previous = 0u; previous < candidate.segment_count;
                 previous++) {
                const struct bbp_elf64_segment_plan *other =
                    &candidate.segments[previous];
                uint64_t other_end = other->page_base +
                    other->page_count * BBP_ELF64_PAGE_SIZE;
                if (other->page_count != 0u &&
                    ranges_overlap(segment->page_base, page_end,
                                   other->page_base, other_end))
                    return BBP_ELF64_ERR_PAGE_OVERLAP;
            }
            if (!have_envelope ||
                segment->page_base < candidate.physical_base)
                candidate.physical_base = segment->page_base;
            if (!have_envelope || page_end > candidate.physical_end)
                candidate.physical_end = page_end;
            have_envelope = 1u;
        }

        if ((flags & BBP_ELF64_PF_X) != 0u &&
            entry >= virtual_address && entry < virtual_end)
            entry_covered = 1u;
        candidate.segment_count++;
    }

    if (!entry_covered) return BBP_ELF64_ERR_ENTRY;
    publish_plan(plan, &candidate);
    return BBP_ELF64_OK;
}
