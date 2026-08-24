/*
 * bbp_import_limine.c - normalized Limine response to BBP translation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <bbp/bbp_crc64.h>

#include "bbp_import.h"

#define LIMINE_ALLOWED (BBP_IMPORT_HAS_HHDM | BBP_IMPORT_HAS_MEMORY_MAP \
    | BBP_IMPORT_HAS_KERNEL_ADDRESS | BBP_IMPORT_HAS_SMP \
    | BBP_IMPORT_HAS_CMDLINE | BBP_IMPORT_HAS_FRAMEBUFFER \
    | BBP_IMPORT_HAS_ACPI)

static uint32_t limine_memory_type(uint64_t type)
{
    static const uint32_t types[8] = {
        BBP_MEM_USABLE,
        BBP_MEM_RESERVED,
        BBP_MEM_ACPI_RECLAIMABLE,
        BBP_MEM_ACPI_NVS,
        BBP_MEM_BAD_MEMORY,
        BBP_MEM_BOOTLOADER_RECLAIM,
        BBP_MEM_KERNEL_AND_MODULES,
        BBP_MEM_FRAMEBUFFER
    };
    return type < 8 ? types[type] : BBP_MEM_RESERVED;
}

static uint32_t limine_memory_attributes(uint32_t type)
{
    switch (type) {
    case BBP_MEM_USABLE:
    case BBP_MEM_BOOTLOADER_RECLAIM:
    case BBP_MEM_KERNEL_AND_MODULES:
    case BBP_MEM_FRAMEBUFFER:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE;
    case BBP_MEM_ACPI_RECLAIMABLE:
    case BBP_MEM_ACPI_NVS:
        return BBP_MEM_ATTR_READABLE;
    default:
        return 0;
    }
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

static void emit_hhdm(struct bbp_builder *builder, bbp_virt_t offset)
{
    struct bbp_tag_hhdm *tag = (struct bbp_tag_hhdm *)bbp_alloc_tag(
        builder, BBP_TAG_HHDM, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->offset = offset;
}

static void emit_kernel_address(struct bbp_builder *builder,
                                const struct bbp_limine_snapshot *snapshot)
{
    struct bbp_tag_kernel_address *tag =
        (struct bbp_tag_kernel_address *)bbp_alloc_tag(
            builder, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->physical_base = snapshot->kernel_physical_base;
    tag->virtual_base = snapshot->kernel_virtual_base;
}

static void emit_memory_map(struct bbp_builder *builder,
                            const struct bbp_limine_snapshot *snapshot,
                            size_t tag_size)
{
    uint32_t count = (uint32_t)snapshot->memory_map_count;
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
        entries[i].base = snapshot->memory_map[i].base;
        entries[i].length = snapshot->memory_map[i].length;
        entries[i].type = limine_memory_type(snapshot->memory_map[i].type);
        entries[i].attributes = limine_memory_attributes(entries[i].type);
    }
}

static void emit_smp(struct bbp_builder *builder,
                     const struct bbp_limine_snapshot *snapshot,
                     size_t tag_size)
{
    uint32_t count = (uint32_t)snapshot->cpu_count;
    struct bbp_tag_smp *tag = (struct bbp_tag_smp *)bbp_alloc_tag(
        builder, BBP_TAG_SMP, 1, tag_size);
    struct bbp_cpu_info *cpus;
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       tag_size - sizeof(tag->header));
    tag->cpu_count = count;
    tag->bsp_id = snapshot->bsp_apic_id;
    tag->flags = snapshot->x2apic ? BBP_SMP_FLAG_X2APIC : 0;
    cpus = (struct bbp_cpu_info *)((uint8_t *)tag + sizeof(*tag));
    for (uint32_t i = 0; i < count; i++) {
        cpus[i].processor_id = snapshot->cpus[i].processor_id;
        cpus[i].apic_id = snapshot->cpus[i].apic_id;
        cpus[i].state = snapshot->cpus[i].apic_id == snapshot->bsp_apic_id
                      ? BBP_CPU_STATE_RUNNING : BBP_CPU_STATE_STOPPED;
    }
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

bbp_import_status bbp_import_limine(struct bbp_builder *builder,
                                    const struct bbp_limine_snapshot *snapshot)
{
    struct bbp_import_plan plan;
    bbp_import_status status;
    size_t memory_map_size = 0;
    size_t smp_size = 0;

    if (builder == NULL || snapshot == NULL)
        return BBP_IMPORT_ERR_NULL;
    if (bbp_import_ranges_overlap(snapshot, sizeof(*snapshot), builder->arena,
                                  builder->capacity))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & ~LIMINE_ALLOWED) != 0)
        return BBP_IMPORT_ERR_FLAGS;
    status = bbp_import_plan_begin(builder, &plan);
    if (status != BBP_IMPORT_OK)
        return status;
    if ((snapshot->present & BBP_IMPORT_HAS_MEMORY_MAP) != 0) {
        if (snapshot->memory_map == NULL || snapshot->memory_map_count == 0)
            return BBP_IMPORT_ERR_NULL;
        status = bbp_import_array_tag_size(sizeof(struct bbp_tag_memory_map),
            snapshot->memory_map_count, sizeof(struct bbp_memory_entry),
            &memory_map_size);
        if (status != BBP_IMPORT_OK) return status;
        if (bbp_import_ranges_overlap(snapshot->memory_map,
                (size_t)snapshot->memory_map_count
                    * sizeof(*snapshot->memory_map),
                builder->arena, builder->capacity))
            return BBP_IMPORT_ERR_RANGE;
        for (uint64_t i = 0; i < snapshot->memory_map_count; i++) {
            if (!bbp_import_phys_range_valid(snapshot->memory_map[i].base,
                                             snapshot->memory_map[i].length))
                return BBP_IMPORT_ERR_RANGE;
        }
    }
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0
        && (!bbp_import_phys_address_valid(snapshot->kernel_physical_base, 1)
            || snapshot->kernel_virtual_base == 0))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & BBP_IMPORT_HAS_SMP) != 0) {
        int bsp_found = 0;
        if (snapshot->cpus == NULL || snapshot->cpu_count == 0)
            return BBP_IMPORT_ERR_NULL;
        if (snapshot->x2apic > 1)
            return BBP_IMPORT_ERR_FLAGS;
        status = bbp_import_array_tag_size(sizeof(struct bbp_tag_smp),
            snapshot->cpu_count, sizeof(struct bbp_cpu_info), &smp_size);
        if (status != BBP_IMPORT_OK) return status;
        if (bbp_import_ranges_overlap(snapshot->cpus,
                (size_t)snapshot->cpu_count * sizeof(*snapshot->cpus),
                builder->arena, builder->capacity))
            return BBP_IMPORT_ERR_RANGE;
        for (uint64_t i = 0; i < snapshot->cpu_count; i++) {
            if (snapshot->cpus[i].apic_id == snapshot->bsp_apic_id)
                bsp_found = 1;
            for (uint64_t j = 0; j < i; j++) {
                if (snapshot->cpus[i].apic_id == snapshot->cpus[j].apic_id)
                    return BBP_IMPORT_ERR_DUPLICATE;
            }
        }
        if (!bsp_found)
            return BBP_IMPORT_ERR_RANGE;
    }
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

#define PLAN_TAG_IF(flag, bytes) do { \
    if ((snapshot->present & (flag)) != 0) { \
        status = bbp_import_plan_tag(builder, &plan, (bytes)); \
        if (status != BBP_IMPORT_OK) return status; \
    } \
} while (0)
    PLAN_TAG_IF(BBP_IMPORT_HAS_HHDM, sizeof(struct bbp_tag_hhdm));
    PLAN_TAG_IF(BBP_IMPORT_HAS_MEMORY_MAP, memory_map_size);
    PLAN_TAG_IF(BBP_IMPORT_HAS_KERNEL_ADDRESS,
                sizeof(struct bbp_tag_kernel_address));
    PLAN_TAG_IF(BBP_IMPORT_HAS_SMP, smp_size);
    if ((snapshot->present & BBP_IMPORT_HAS_CMDLINE) != 0) {
        status = bbp_import_plan_blob(builder, &plan,
                                      snapshot->command_line.bytes);
        if (status != BBP_IMPORT_OK) return status;
    }
    PLAN_TAG_IF(BBP_IMPORT_HAS_CMDLINE, sizeof(struct bbp_tag_cmdline));
    PLAN_TAG_IF(BBP_IMPORT_HAS_FRAMEBUFFER,
                sizeof(struct bbp_tag_framebuffer)
                + sizeof(struct bbp_display_info));
    PLAN_TAG_IF(BBP_IMPORT_HAS_ACPI, sizeof(struct bbp_tag_acpi));
#undef PLAN_TAG_IF

    if ((snapshot->present & BBP_IMPORT_HAS_HHDM) != 0)
        emit_hhdm(builder, snapshot->hhdm_offset);
    if ((snapshot->present & BBP_IMPORT_HAS_MEMORY_MAP) != 0)
        emit_memory_map(builder, snapshot, memory_map_size);
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0)
        emit_kernel_address(builder, snapshot);
    if ((snapshot->present & BBP_IMPORT_HAS_SMP) != 0)
        emit_smp(builder, snapshot, smp_size);
    if ((snapshot->present & BBP_IMPORT_HAS_CMDLINE) != 0)
        emit_cmdline(builder, snapshot->command_line);
    if ((snapshot->present & BBP_IMPORT_HAS_FRAMEBUFFER) != 0)
        emit_framebuffer(builder, &snapshot->framebuffer);
    if ((snapshot->present & BBP_IMPORT_HAS_ACPI) != 0)
        emit_acpi(builder, &snapshot->acpi);
    return BBP_IMPORT_OK;
}
