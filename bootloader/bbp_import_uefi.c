/*
 * bbp_import_uefi.c - normalized post-EBS UEFI snapshot to BBP translation.
 *
 * This is deliberately not a PI HOB binary parser.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <bbp/bbp_crc64.h>

#include "bbp_import.h"

#define UEFI_ALLOWED (BBP_IMPORT_HAS_HHDM | BBP_IMPORT_HAS_MEMORY_MAP \
    | BBP_IMPORT_HAS_KERNEL_ADDRESS | BBP_IMPORT_HAS_CMDLINE \
    | BBP_IMPORT_HAS_FRAMEBUFFER | BBP_IMPORT_HAS_ACPI \
    | BBP_IMPORT_HAS_EFI | BBP_IMPORT_HAS_SMBIOS)

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64(const uint8_t *p)
{
    return (uint64_t)read_u32(p) | ((uint64_t)read_u32(p + 4) << 32);
}

static uint32_t uefi_memory_type(uint32_t type)
{
    switch (type) {
    case 1: /* LoaderCode */
    case 2: /* LoaderData */
    case 3: /* BootServicesCode */
    case 4: /* BootServicesData */
        return BBP_MEM_BOOTLOADER_RECLAIM;
    case 7:  return BBP_MEM_USABLE;           /* ConventionalMemory */
    case 8:  return BBP_MEM_BAD_MEMORY;       /* UnusableMemory */
    case 9:  return BBP_MEM_ACPI_RECLAIMABLE;
    case 10: return BBP_MEM_ACPI_NVS;
    case 11: /* MemoryMappedIO */
    case 12: return BBP_MEM_DEVICE_IO;         /* MemoryMappedIOPortSpace */
    case 14: return BBP_MEM_PERSISTENT;
    default: return BBP_MEM_RESERVED;
    }
}

static uint32_t uefi_attributes(uint64_t attributes)
{
    const uint64_t EFI_MEMORY_UC = 1ULL << 0;
    const uint64_t EFI_MEMORY_WC = 1ULL << 1;
    const uint64_t EFI_MEMORY_WT = 1ULL << 2;
    const uint64_t EFI_MEMORY_WB = 1ULL << 3;
    const uint64_t EFI_MEMORY_UCE = 1ULL << 4;
    const uint64_t EFI_MEMORY_RP = 1ULL << 13;
    const uint64_t EFI_MEMORY_XP = 1ULL << 14;
    const uint64_t EFI_MEMORY_RO = 1ULL << 17;
    uint32_t result = 0;
    if ((attributes & EFI_MEMORY_RP) == 0) result |= BBP_MEM_ATTR_READABLE;
    if ((attributes & EFI_MEMORY_RO) == 0)
        result |= BBP_MEM_ATTR_WRITABLE;
    if ((attributes & EFI_MEMORY_XP) == 0) result |= BBP_MEM_ATTR_EXECUTABLE;
    if ((attributes & (EFI_MEMORY_WB | EFI_MEMORY_WT)) != 0)
        result |= BBP_MEM_ATTR_CACHED;
    if ((attributes & EFI_MEMORY_WC) != 0)
        result |= BBP_MEM_ATTR_WRITE_COMBINE;
    if ((attributes & (EFI_MEMORY_UC | EFI_MEMORY_UCE)) != 0)
        result |= BBP_MEM_ATTR_UNCACHED;
    return result;
}

static bbp_import_status validate_acpi(const struct bbp_import_acpi *acpi)
{
    if (!bbp_import_phys_address_valid(acpi->rsdp_address, 0)
        || !bbp_import_phys_address_valid(acpi->xsdt_address, 1))
        return BBP_IMPORT_ERR_RANGE;
    if ((acpi->flags & ~(uint16_t)(BBP_ACPI_FLAG_XSDT_AVAILABLE
          | BBP_ACPI_FLAG_SPCR_AVAILABLE)) != 0)
        return BBP_IMPORT_ERR_FLAGS;
    if (((acpi->flags & BBP_ACPI_FLAG_XSDT_AVAILABLE) != 0)
        != (acpi->xsdt_address != 0))
        return BBP_IMPORT_ERR_FLAGS;
    return BBP_IMPORT_OK;
}

static bbp_import_status validate_memory_map(const struct bbp_uefi_snapshot *s,
                                             uint64_t *out_count)
{
    uint64_t count;
    if (s->memory_map == NULL || s->memory_map_bytes == 0)
        return BBP_IMPORT_ERR_NULL;
    if (!s->memory_map_final)
        return BBP_IMPORT_ERR_NON_FINAL;
    if (s->descriptor_stride < 40
        || s->descriptor_stride > BBP_IMPORT_U32_MAX
        || s->descriptor_stride > BBP_IMPORT_SIZE_MAX
        || s->descriptor_version != 1)
        return BBP_IMPORT_ERR_UNSUPPORTED;
    if (s->memory_map_bytes > BBP_IMPORT_U32_MAX
        || s->memory_map_bytes % (size_t)s->descriptor_stride != 0)
        return BBP_IMPORT_ERR_FRAMING;
    count = s->memory_map_bytes / (size_t)s->descriptor_stride;
    if (count == 0 || count > BBP_IMPORT_U32_MAX)
        return BBP_IMPORT_ERR_COUNT;
    for (uint64_t i = 0; i < count; i++) {
        const uint8_t *entry = (const uint8_t *)s->memory_map
                             + (size_t)i * (size_t)s->descriptor_stride;
        uint64_t base = read_u64(entry + 8);
        uint64_t pages = read_u64(entry + 24);
        uint64_t length;
        if (pages == 0 || pages > BBP_IMPORT_U64_MAX / 4096u)
            return BBP_IMPORT_ERR_OVERFLOW;
        length = pages * 4096u;
        if (!bbp_import_phys_range_valid(base, length))
            return BBP_IMPORT_ERR_RANGE;
    }
    *out_count = count;
    return BBP_IMPORT_OK;
}

static void emit_hhdm(struct bbp_builder *builder, bbp_virt_t offset)
{
    struct bbp_tag_hhdm *tag = (struct bbp_tag_hhdm *)bbp_alloc_tag(
        builder, BBP_TAG_HHDM, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->offset = offset;
}

static void emit_memory_map(struct bbp_builder *builder,
                            const struct bbp_uefi_snapshot *snapshot,
                            uint32_t count, size_t tag_size)
{
    struct bbp_tag_memory_map *tag =
        (struct bbp_tag_memory_map *)bbp_alloc_tag(
            builder, BBP_TAG_MEMORY_MAP, 1, tag_size);
    struct bbp_memory_entry *entries;
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       tag_size - sizeof(tag->header));
    tag->entry_count = count;
    tag->entry_size = sizeof(*entries);
    entries = (struct bbp_memory_entry *)((uint8_t *)tag + sizeof(*tag));
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *source = (const uint8_t *)snapshot->memory_map
                              + (size_t)i * (size_t)snapshot->descriptor_stride;
        entries[i].base = read_u64(source + 8);
        entries[i].length = read_u64(source + 24) * 4096u;
        entries[i].type = uefi_memory_type(read_u32(source));
        entries[i].attributes = uefi_attributes(read_u64(source + 32));
    }
}

static void emit_kernel_address(struct bbp_builder *builder,
                                const struct bbp_uefi_snapshot *snapshot)
{
    struct bbp_tag_kernel_address *tag =
        (struct bbp_tag_kernel_address *)bbp_alloc_tag(
            builder, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->physical_base = snapshot->kernel_physical_base;
    tag->virtual_base = snapshot->kernel_virtual_base;
}

static void emit_cmdline(struct bbp_builder *builder,
                         struct bbp_import_string string)
{
    bbp_phys_t physical = bbp_arena_blob(builder, string.data, string.bytes);
    struct bbp_tag_cmdline *tag = (struct bbp_tag_cmdline *)bbp_alloc_tag(
        builder, BBP_TAG_CMDLINE, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->string = physical;
    tag->length = (uint32_t)(string.bytes - 1u);
    tag->string_crc = bbp_crc64(string.data, string.bytes - 1u);
}

static void emit_framebuffer(struct bbp_builder *builder,
                             const struct bbp_import_framebuffer *source)
{
    size_t bytes = sizeof(struct bbp_tag_framebuffer)
                 + sizeof(struct bbp_display_info);
    struct bbp_tag_framebuffer *tag =
        (struct bbp_tag_framebuffer *)bbp_alloc_tag(
            builder, BBP_TAG_FRAMEBUFFER, 1, bytes);
    struct bbp_display_info *display;
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       bytes - sizeof(tag->header));
    tag->address = source->address;
    tag->display_count = 1;
    tag->flags = source->flags;
    tag->pitch = source->pitch;
    tag->total_size = source->total_size;
    display = (struct bbp_display_info *)((uint8_t *)tag + sizeof(*tag));
    display->width = (uint16_t)source->width;
    display->height = (uint16_t)source->height;
    display->color_depth = source->color_depth;
    display->pixel_format = source->pixel_format;
}

static void emit_acpi(struct bbp_builder *builder,
                      const struct bbp_import_acpi *source)
{
    struct bbp_tag_acpi *tag = (struct bbp_tag_acpi *)bbp_alloc_tag(
        builder, BBP_TAG_ACPI, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->rsdp_address = source->rsdp_address;
    tag->xsdt_address = source->xsdt_address;
    tag->oem_id = source->oem_id;
    tag->acpi_version = source->acpi_version;
    tag->flags = source->flags;
}

static void emit_efi(struct bbp_builder *builder,
                     const struct bbp_uefi_snapshot *snapshot)
{
    bbp_phys_t map = bbp_arena_blob(builder, snapshot->memory_map,
                                    snapshot->memory_map_bytes);
    struct bbp_tag_efi *tag = (struct bbp_tag_efi *)bbp_alloc_tag(
        builder, BBP_TAG_EFI, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->system_table = snapshot->system_table;
    tag->memory_map = map;
    tag->memory_map_size = (uint32_t)snapshot->memory_map_bytes;
    tag->descriptor_size = (uint32_t)snapshot->descriptor_stride;
    tag->descriptor_version = snapshot->descriptor_version;
}

static void emit_smbios(struct bbp_builder *builder,
                        const struct bbp_uefi_snapshot *snapshot)
{
    struct bbp_tag_smbios *tag = (struct bbp_tag_smbios *)bbp_alloc_tag(
        builder, BBP_TAG_SMBIOS, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->entry_32bit = snapshot->smbios_32;
    tag->entry_64bit = snapshot->smbios_64;
}

bbp_import_status bbp_import_uefi_hobs(struct bbp_builder *builder,
                                       const struct bbp_uefi_snapshot *snapshot)
{
    struct bbp_import_plan plan;
    bbp_import_status status;
    uint64_t map_count = 0;
    size_t map_tag_size = 0;
    int needs_map;

    if (builder == NULL || snapshot == NULL)
        return BBP_IMPORT_ERR_NULL;
    if (bbp_import_ranges_overlap(snapshot, sizeof(*snapshot), builder->arena,
                                  builder->capacity))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & ~UEFI_ALLOWED) != 0)
        return BBP_IMPORT_ERR_FLAGS;
    status = bbp_import_plan_begin(builder, &plan);
    if (status != BBP_IMPORT_OK) return status;
    needs_map = (snapshot->present
        & (BBP_IMPORT_HAS_MEMORY_MAP | BBP_IMPORT_HAS_EFI)) != 0;
    if (needs_map) {
        if (bbp_import_ranges_overlap(snapshot->memory_map,
                snapshot->memory_map_bytes, builder->arena, builder->capacity))
            return BBP_IMPORT_ERR_RANGE;
        status = validate_memory_map(snapshot, &map_count);
        if (status != BBP_IMPORT_OK) return status;
    }
    if ((snapshot->present & BBP_IMPORT_HAS_MEMORY_MAP) != 0) {
        status = bbp_import_array_tag_size(sizeof(struct bbp_tag_memory_map),
            map_count, sizeof(struct bbp_memory_entry), &map_tag_size);
        if (status != BBP_IMPORT_OK) return status;
    }
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0
        && (!bbp_import_phys_address_valid(snapshot->kernel_physical_base, 1)
            || snapshot->kernel_virtual_base == 0))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & BBP_IMPORT_HAS_CMDLINE) != 0) {
        if (bbp_import_ranges_overlap(snapshot->command_line.data,
                snapshot->command_line.bytes, builder->arena,
                builder->capacity))
            return BBP_IMPORT_ERR_RANGE;
        status = bbp_import_validate_string(snapshot->command_line);
        if (status != BBP_IMPORT_OK) return status;
    }
    if ((snapshot->present & BBP_IMPORT_HAS_FRAMEBUFFER) != 0) {
        status = bbp_import_validate_framebuffer(&snapshot->framebuffer);
        if (status != BBP_IMPORT_OK) return status;
    }
    if ((snapshot->present & BBP_IMPORT_HAS_ACPI) != 0) {
        status = validate_acpi(&snapshot->acpi);
        if (status != BBP_IMPORT_OK) return status;
    }
    if ((snapshot->present & BBP_IMPORT_HAS_EFI) != 0
        && !bbp_import_phys_address_valid(snapshot->system_table, 0))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & BBP_IMPORT_HAS_SMBIOS) != 0) {
        if ((snapshot->smbios_32 == 0 && snapshot->smbios_64 == 0)
            || !bbp_import_phys_address_valid(snapshot->smbios_32, 1)
            || !bbp_import_phys_address_valid(snapshot->smbios_64, 1))
            return BBP_IMPORT_ERR_RANGE;
    }

#define PLAN_TAG(bytes) do { \
    status = bbp_import_plan_tag(builder, &plan, (bytes)); \
    if (status != BBP_IMPORT_OK) return status; \
} while (0)
    if ((snapshot->present & BBP_IMPORT_HAS_HHDM) != 0)
        PLAN_TAG(sizeof(struct bbp_tag_hhdm));
    if ((snapshot->present & BBP_IMPORT_HAS_MEMORY_MAP) != 0)
        PLAN_TAG(map_tag_size);
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0)
        PLAN_TAG(sizeof(struct bbp_tag_kernel_address));
    if ((snapshot->present & BBP_IMPORT_HAS_CMDLINE) != 0) {
        status = bbp_import_plan_blob(builder, &plan,
                                      snapshot->command_line.bytes);
        if (status != BBP_IMPORT_OK) return status;
        PLAN_TAG(sizeof(struct bbp_tag_cmdline));
    }
    if ((snapshot->present & BBP_IMPORT_HAS_FRAMEBUFFER) != 0)
        PLAN_TAG(sizeof(struct bbp_tag_framebuffer)
                 + sizeof(struct bbp_display_info));
    if ((snapshot->present & BBP_IMPORT_HAS_ACPI) != 0)
        PLAN_TAG(sizeof(struct bbp_tag_acpi));
    if ((snapshot->present & BBP_IMPORT_HAS_EFI) != 0) {
        status = bbp_import_plan_blob(builder, &plan,
                                      snapshot->memory_map_bytes);
        if (status != BBP_IMPORT_OK) return status;
        PLAN_TAG(sizeof(struct bbp_tag_efi));
    }
    if ((snapshot->present & BBP_IMPORT_HAS_SMBIOS) != 0)
        PLAN_TAG(sizeof(struct bbp_tag_smbios));
#undef PLAN_TAG

    if ((snapshot->present & BBP_IMPORT_HAS_HHDM) != 0)
        emit_hhdm(builder, snapshot->hhdm_offset);
    if ((snapshot->present & BBP_IMPORT_HAS_MEMORY_MAP) != 0)
        emit_memory_map(builder, snapshot, (uint32_t)map_count, map_tag_size);
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0)
        emit_kernel_address(builder, snapshot);
    if ((snapshot->present & BBP_IMPORT_HAS_CMDLINE) != 0)
        emit_cmdline(builder, snapshot->command_line);
    if ((snapshot->present & BBP_IMPORT_HAS_FRAMEBUFFER) != 0)
        emit_framebuffer(builder, &snapshot->framebuffer);
    if ((snapshot->present & BBP_IMPORT_HAS_ACPI) != 0)
        emit_acpi(builder, &snapshot->acpi);
    if ((snapshot->present & BBP_IMPORT_HAS_EFI) != 0)
        emit_efi(builder, snapshot);
    if ((snapshot->present & BBP_IMPORT_HAS_SMBIOS) != 0)
        emit_smbios(builder, snapshot);
    return BBP_IMPORT_OK;
}
