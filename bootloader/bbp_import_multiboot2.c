/*
 * bbp_import_multiboot2.c - bounded Multiboot2 information parser.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <bbp/bbp_crc64.h>

#include "bbp_import.h"

#define MB2_END         0u
#define MB2_CMDLINE     1u
#define MB2_MODULE      3u
#define MB2_MMAP        6u
#define MB2_FRAMEBUFFER 8u
#define MB2_ACPI_OLD    14u
#define MB2_ACPI_NEW    15u

struct mb2_scan {
    const uint8_t *data;
    size_t total;
    size_t cmdline_offset;
    size_t cmdline_bytes;
    size_t mmap_offset;
    uint64_t mmap_count;
    uint32_t mmap_stride;
    uint64_t module_count;
    size_t framebuffer_offset;
    struct bbp_import_framebuffer framebuffer;
    size_t acpi_offset;
    size_t acpi_bytes;
    uint64_t acpi_xsdt;
    uint32_t acpi_oem_id;
    uint16_t acpi_version;
};

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64(const uint8_t *p)
{
    return (uint64_t)read_u32(p) | ((uint64_t)read_u32(p + 4) << 32);
}

static int checksum_zero(const uint8_t *data, size_t bytes)
{
    uint8_t sum = 0;
    while (bytes-- != 0)
        sum = (uint8_t)(sum + *data++);
    return sum == 0;
}

static int signature_is_rsdp(const uint8_t *data)
{
    static const uint8_t signature[8] = {'R','S','D',' ','P','T','R',' '};
    for (size_t i = 0; i < sizeof(signature); i++) {
        if (data[i] != signature[i]) return 0;
    }
    return 1;
}

static bbp_import_status exact_string(const uint8_t *data, size_t bytes)
{
    struct bbp_import_string string;
    string.data = data;
    string.bytes = bytes;
    return bbp_import_validate_string(string);
}

static bbp_import_status parse_framebuffer(const uint8_t *tag, uint32_t size,
                                           struct bbp_import_framebuffer *out)
{
    uint8_t red_position;
    uint8_t red_size;
    uint8_t green_position;
    uint8_t green_size;
    uint8_t blue_position;
    uint8_t blue_size;
    uint8_t bpp;
    uint64_t total;

    if (size != 38)
        return BBP_IMPORT_ERR_FRAMING;
    if (tag[29] != 1)
        return BBP_IMPORT_ERR_UNSUPPORTED;
    if (tag[30] != 0 || tag[31] != 0)
        return BBP_IMPORT_ERR_FRAMING;
    bpp = tag[28];
    red_position = tag[32]; red_size = tag[33];
    green_position = tag[34]; green_size = tag[35];
    blue_position = tag[36]; blue_size = tag[37];

    if (bpp == 24 && red_position == 0 && red_size == 8
        && green_position == 8 && green_size == 8
        && blue_position == 16 && blue_size == 8) {
        out->pixel_format = BBP_FB_RGB888;
        out->color_depth = 8;
    } else if (bpp == 32 && red_position == 0 && red_size == 8
        && green_position == 8 && green_size == 8
        && blue_position == 16 && blue_size == 8) {
        out->pixel_format = BBP_FB_RGBA8888;
        out->color_depth = 8;
    } else if (bpp == 32 && red_position == 16 && red_size == 8
        && green_position == 8 && green_size == 8
        && blue_position == 0 && blue_size == 8) {
        out->pixel_format = BBP_FB_BGRA8888;
        out->color_depth = 8;
    } else if (bpp == 16 && red_position == 11 && red_size == 5
        && green_position == 5 && green_size == 6
        && blue_position == 0 && blue_size == 5) {
        out->pixel_format = BBP_FB_RGB565;
        out->color_depth = 5;
    } else {
        return BBP_IMPORT_ERR_UNSUPPORTED;
    }

    out->address = read_u64(tag + 8);
    out->pitch = read_u32(tag + 16);
    out->width = read_u32(tag + 20);
    out->height = read_u32(tag + 24);
    out->flags = 0;
    total = (uint64_t)out->pitch * out->height;
    out->total_size = total;
    return bbp_import_validate_framebuffer(out);
}

static bbp_import_status parse_acpi(const uint8_t *rsdp, size_t bytes,
                                    int is_new, struct mb2_scan *scan)
{
    uint32_t length;
    if (bytes < 20 || !signature_is_rsdp(rsdp)
        || !checksum_zero(rsdp, 20))
        return BBP_IMPORT_ERR_FRAMING;
    if (!is_new) {
        if (bytes != 20 || rsdp[15] != 0)
            return BBP_IMPORT_ERR_FRAMING;
        length = 20;
        scan->acpi_xsdt = 0;
    } else {
        if (bytes < 36 || rsdp[15] < 2)
            return BBP_IMPORT_ERR_FRAMING;
        length = read_u32(rsdp + 20);
        if (length < 36 || length != bytes || !checksum_zero(rsdp, length))
            return BBP_IMPORT_ERR_FRAMING;
        scan->acpi_xsdt = read_u64(rsdp + 24);
        if (!bbp_import_phys_address_valid(scan->acpi_xsdt, 1))
            return BBP_IMPORT_ERR_RANGE;
    }
    scan->acpi_bytes = length;
    scan->acpi_oem_id = read_u32(rsdp + 9);
    scan->acpi_version = (uint16_t)((uint16_t)rsdp[15] << 8);
    return BBP_IMPORT_OK;
}

static bbp_import_status scan_mbi(const struct bbp_multiboot2_snapshot *snapshot,
                                  struct mb2_scan *scan)
{
    const uint8_t *data = (const uint8_t *)snapshot->mbi;
    uint32_t total32;
    size_t offset;
    int saw_cmdline = 0, saw_mmap = 0, saw_framebuffer = 0;
    int saw_acpi_old = 0, saw_acpi_new = 0;
    size_t old_acpi_offset = 0, old_acpi_bytes = 0;
    uint64_t old_acpi_xsdt = 0;
    uint32_t old_acpi_oem = 0;
    uint16_t old_acpi_version = 0;
    size_t new_acpi_offset = 0, new_acpi_bytes = 0;
    uint64_t new_acpi_xsdt = 0;
    uint32_t new_acpi_oem = 0;
    uint16_t new_acpi_version = 0;

    if (data == NULL || snapshot->mapped_bytes < 16)
        return BBP_IMPORT_ERR_NULL;
    total32 = read_u32(data);
    if (total32 < 16 || (total32 & 7u) != 0
        || total32 > snapshot->mapped_bytes || read_u32(data + 4) != 0)
        return BBP_IMPORT_ERR_FRAMING;
    bbp_import_memzero(scan, sizeof(*scan));
    scan->data = data;
    scan->total = total32;
    scan->cmdline_offset = BBP_IMPORT_SIZE_MAX;
    scan->mmap_offset = BBP_IMPORT_SIZE_MAX;
    scan->framebuffer_offset = BBP_IMPORT_SIZE_MAX;
    scan->acpi_offset = BBP_IMPORT_SIZE_MAX;

    offset = 8;
    while (offset < scan->total) {
        uint32_t type;
        uint32_t size;
        size_t padded;
        if (scan->total - offset < 8)
            return BBP_IMPORT_ERR_FRAMING;
        type = read_u32(data + offset);
        size = read_u32(data + offset + 4);
        if (size < 8 || size > scan->total - offset)
            return BBP_IMPORT_ERR_FRAMING;
        if (type == MB2_END) {
            if (size != 8 || offset + 8 != scan->total)
                return BBP_IMPORT_ERR_FRAMING;
            if (saw_acpi_new) {
                scan->acpi_offset = new_acpi_offset;
                scan->acpi_bytes = new_acpi_bytes;
                scan->acpi_xsdt = new_acpi_xsdt;
                scan->acpi_oem_id = new_acpi_oem;
                scan->acpi_version = new_acpi_version;
            } else if (saw_acpi_old) {
                scan->acpi_offset = old_acpi_offset;
                scan->acpi_bytes = old_acpi_bytes;
                scan->acpi_xsdt = old_acpi_xsdt;
                scan->acpi_oem_id = old_acpi_oem;
                scan->acpi_version = old_acpi_version;
            }
            return BBP_IMPORT_OK;
        }
        padded = ((size_t)size + 7u) & ~(size_t)7u;
        if (padded > scan->total - offset)
            return BBP_IMPORT_ERR_FRAMING;

        if (type == MB2_CMDLINE) {
            bbp_import_status status;
            if (saw_cmdline++) return BBP_IMPORT_ERR_DUPLICATE;
            status = exact_string(data + offset + 8, size - 8u);
            if (status != BBP_IMPORT_OK) return status;
            scan->cmdline_offset = offset + 8;
            scan->cmdline_bytes = size - 8u;
        } else if (type == MB2_MODULE) {
            bbp_import_status status;
            uint32_t start, end;
            if (size < 17) return BBP_IMPORT_ERR_FRAMING;
            start = read_u32(data + offset + 8);
            end = read_u32(data + offset + 12);
            if (end <= start || !bbp_import_phys_range_valid(start,
                                                              (uint64_t)end - start))
                return BBP_IMPORT_ERR_RANGE;
            status = exact_string(data + offset + 16, size - 16u);
            if (status != BBP_IMPORT_OK) return status;
            if (scan->module_count == BBP_IMPORT_U32_MAX)
                return BBP_IMPORT_ERR_COUNT;
            scan->module_count++;
        } else if (type == MB2_MMAP) {
            uint32_t stride;
            uint32_t version;
            uint64_t count;
            if (saw_mmap++) return BBP_IMPORT_ERR_DUPLICATE;
            if (size < 16) return BBP_IMPORT_ERR_FRAMING;
            stride = read_u32(data + offset + 8);
            version = read_u32(data + offset + 12);
            if (stride < 24 || (stride & 7u) != 0 || version != 0
                || ((size - 16u) % stride) != 0)
                return BBP_IMPORT_ERR_FRAMING;
            count = (size - 16u) / stride;
            if (count == 0 || count > BBP_IMPORT_U32_MAX)
                return BBP_IMPORT_ERR_COUNT;
            for (uint64_t i = 0; i < count; i++) {
                const uint8_t *entry = data + offset + 16 + (size_t)i * stride;
                if (!bbp_import_phys_range_valid(read_u64(entry),
                                                  read_u64(entry + 8)))
                    return BBP_IMPORT_ERR_RANGE;
            }
            scan->mmap_offset = offset;
            scan->mmap_count = count;
            scan->mmap_stride = stride;
        } else if (type == MB2_FRAMEBUFFER) {
            bbp_import_status status;
            if (saw_framebuffer++) return BBP_IMPORT_ERR_DUPLICATE;
            status = parse_framebuffer(data + offset, size, &scan->framebuffer);
            if (status != BBP_IMPORT_OK) return status;
            scan->framebuffer_offset = offset;
        } else if (type == MB2_ACPI_OLD || type == MB2_ACPI_NEW) {
            bbp_import_status status;
            int is_new = type == MB2_ACPI_NEW;
            if ((is_new && saw_acpi_new++) || (!is_new && saw_acpi_old++))
                return BBP_IMPORT_ERR_DUPLICATE;
            status = parse_acpi(data + offset + 8, size - 8u, is_new, scan);
            if (status != BBP_IMPORT_OK) return status;
            if (is_new) {
                new_acpi_offset = offset + 8;
                new_acpi_bytes = scan->acpi_bytes;
                new_acpi_xsdt = scan->acpi_xsdt;
                new_acpi_oem = scan->acpi_oem_id;
                new_acpi_version = scan->acpi_version;
            } else {
                old_acpi_offset = offset + 8;
                old_acpi_bytes = scan->acpi_bytes;
                old_acpi_xsdt = scan->acpi_xsdt;
                old_acpi_oem = scan->acpi_oem_id;
                old_acpi_version = scan->acpi_version;
            }
        }
        offset += padded;
    }
    return BBP_IMPORT_ERR_FRAMING; /* a valid MBI returns at its end tag */
}

static uint32_t mb2_memory_type(uint32_t type)
{
    switch (type) {
    case 1: return BBP_MEM_USABLE;
    case 3: return BBP_MEM_ACPI_RECLAIMABLE;
    case 4: return BBP_MEM_ACPI_NVS;
    case 5: return BBP_MEM_BAD_MEMORY;
    default: return BBP_MEM_RESERVED;
    }
}

static uint32_t mb2_memory_attributes(uint32_t type)
{
    switch (type) {
    case BBP_MEM_USABLE:
        return BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE;
    case BBP_MEM_ACPI_RECLAIMABLE:
    case BBP_MEM_ACPI_NVS:
        return BBP_MEM_ATTR_READABLE;
    default:
        return 0;
    }
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
                            const struct mb2_scan *scan, size_t tag_size)
{
    const uint8_t *source = scan->data + scan->mmap_offset + 16;
    struct bbp_tag_memory_map *tag =
        (struct bbp_tag_memory_map *)bbp_alloc_tag(
            builder, BBP_TAG_MEMORY_MAP, 1, tag_size);
    struct bbp_memory_entry *entries;
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       tag_size - sizeof(tag->header));
    tag->entry_count = (uint32_t)scan->mmap_count;
    tag->entry_size = sizeof(*entries);
    entries = (struct bbp_memory_entry *)((uint8_t *)tag + sizeof(*tag));
    for (uint32_t i = 0; i < tag->entry_count; i++) {
        const uint8_t *entry = source + (size_t)i * scan->mmap_stride;
        entries[i].base = read_u64(entry);
        entries[i].length = read_u64(entry + 8);
        entries[i].type = mb2_memory_type(read_u32(entry + 16));
        entries[i].attributes = mb2_memory_attributes(entries[i].type);
    }
}

static void emit_kernel_address(struct bbp_builder *builder,
                                const struct bbp_multiboot2_snapshot *snapshot)
{
    struct bbp_tag_kernel_address *tag =
        (struct bbp_tag_kernel_address *)bbp_alloc_tag(
            builder, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->physical_base = snapshot->kernel_physical_base;
    tag->virtual_base = snapshot->kernel_virtual_base;
}

static void emit_cmdline(struct bbp_builder *builder, const struct mb2_scan *scan)
{
    const uint8_t *source = scan->data + scan->cmdline_offset;
    bbp_phys_t physical = bbp_arena_blob(builder, source, scan->cmdline_bytes);
    struct bbp_tag_cmdline *tag = (struct bbp_tag_cmdline *)bbp_alloc_tag(
        builder, BBP_TAG_CMDLINE, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->string = physical;
    tag->length = (uint32_t)(scan->cmdline_bytes - 1u);
    tag->string_crc = bbp_crc64(source, scan->cmdline_bytes - 1u);
}

static void emit_modules(struct bbp_builder *builder, const struct mb2_scan *scan,
                         size_t tag_size)
{
    struct bbp_tag_modules *tag = (struct bbp_tag_modules *)bbp_alloc_tag(
        builder, BBP_TAG_MODULES, 1, tag_size);
    struct bbp_module_entry *modules;
    size_t offset = 8;
    uint32_t index = 0;
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       tag_size - sizeof(tag->header));
    tag->module_count = (uint32_t)scan->module_count;
    modules = (struct bbp_module_entry *)((uint8_t *)tag + sizeof(*tag));
    while (offset < scan->total && index < tag->module_count) {
        uint32_t type = read_u32(scan->data + offset);
        uint32_t size = read_u32(scan->data + offset + 4);
        if (type == MB2_MODULE) {
            size_t name_bytes = size - 17u;
            size_t copied = bbp_import_utf8_prefix(scan->data + offset + 16,
                                                   name_bytes, 63);
            modules[index].base_address = read_u32(scan->data + offset + 8);
            modules[index].size = (uint64_t)read_u32(scan->data + offset + 12)
                                - read_u32(scan->data + offset + 8);
            bbp_import_memcpy(modules[index].name,
                              scan->data + offset + 16, copied);
            modules[index].name[copied] = 0;
            index++;
        }
        offset += ((size_t)size + 7u) & ~(size_t)7u;
    }
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
    tag->pitch = source->pitch;
    tag->total_size = source->total_size;
    display = (struct bbp_display_info *)((uint8_t *)tag + sizeof(*tag));
    display->width = (uint16_t)source->width;
    display->height = (uint16_t)source->height;
    display->color_depth = source->color_depth;
    display->pixel_format = source->pixel_format;
}

static void emit_acpi(struct bbp_builder *builder, const struct mb2_scan *scan)
{
    bbp_phys_t rsdp = bbp_arena_blob(builder,
        scan->data + scan->acpi_offset, scan->acpi_bytes);
    struct bbp_tag_acpi *tag = (struct bbp_tag_acpi *)bbp_alloc_tag(
        builder, BBP_TAG_ACPI, 1, sizeof(*tag));
    bbp_import_memzero((uint8_t *)tag + sizeof(tag->header),
                       sizeof(*tag) - sizeof(tag->header));
    tag->rsdp_address = rsdp;
    tag->xsdt_address = scan->acpi_xsdt;
    tag->oem_id = scan->acpi_oem_id;
    tag->acpi_version = scan->acpi_version;
    if (scan->acpi_xsdt != 0)
        tag->flags = BBP_ACPI_FLAG_XSDT_AVAILABLE;
}

bbp_import_status bbp_import_multiboot2(struct bbp_builder *builder,
                                        const struct bbp_multiboot2_snapshot *snapshot)
{
    struct bbp_import_plan plan;
    struct mb2_scan scan;
    bbp_import_status status;
    size_t mmap_size = 0;
    size_t modules_size = 0;
    const uint64_t sideband = BBP_IMPORT_HAS_HHDM
                            | BBP_IMPORT_HAS_KERNEL_ADDRESS;

    if (builder == NULL || snapshot == NULL)
        return BBP_IMPORT_ERR_NULL;
    if (bbp_import_ranges_overlap(snapshot, sizeof(*snapshot), builder->arena,
                                  builder->capacity))
        return BBP_IMPORT_ERR_RANGE;
    if ((snapshot->present & ~sideband) != 0)
        return BBP_IMPORT_ERR_FLAGS;
    status = bbp_import_plan_begin(builder, &plan);
    if (status != BBP_IMPORT_OK) return status;
    if (bbp_import_ranges_overlap(snapshot->mbi, snapshot->mapped_bytes,
                                  builder->arena, builder->capacity))
        return BBP_IMPORT_ERR_RANGE;
    status = scan_mbi(snapshot, &scan);
    if (status != BBP_IMPORT_OK) return status;
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0
        && (!bbp_import_phys_address_valid(snapshot->kernel_physical_base, 1)
            || snapshot->kernel_virtual_base == 0))
        return BBP_IMPORT_ERR_RANGE;

    if (scan.mmap_offset != BBP_IMPORT_SIZE_MAX) {
        status = bbp_import_array_tag_size(sizeof(struct bbp_tag_memory_map),
            scan.mmap_count, sizeof(struct bbp_memory_entry), &mmap_size);
        if (status != BBP_IMPORT_OK) return status;
    }
    if (scan.module_count != 0) {
        status = bbp_import_array_tag_size(sizeof(struct bbp_tag_modules),
            scan.module_count, sizeof(struct bbp_module_entry), &modules_size);
        if (status != BBP_IMPORT_OK) return status;
    }

#define PLAN(bytes) do { \
    status = bbp_import_plan_tag(builder, &plan, (bytes)); \
    if (status != BBP_IMPORT_OK) return status; \
} while (0)
    if ((snapshot->present & BBP_IMPORT_HAS_HHDM) != 0)
        PLAN(sizeof(struct bbp_tag_hhdm));
    if (scan.mmap_offset != BBP_IMPORT_SIZE_MAX) PLAN(mmap_size);
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0)
        PLAN(sizeof(struct bbp_tag_kernel_address));
    if (scan.cmdline_offset != BBP_IMPORT_SIZE_MAX) {
        status = bbp_import_plan_blob(builder, &plan, scan.cmdline_bytes);
        if (status != BBP_IMPORT_OK) return status;
        PLAN(sizeof(struct bbp_tag_cmdline));
    }
    if (scan.module_count != 0) PLAN(modules_size);
    if (scan.framebuffer_offset != BBP_IMPORT_SIZE_MAX)
        PLAN(sizeof(struct bbp_tag_framebuffer)
             + sizeof(struct bbp_display_info));
    if (scan.acpi_offset != BBP_IMPORT_SIZE_MAX) {
        status = bbp_import_plan_blob(builder, &plan, scan.acpi_bytes);
        if (status != BBP_IMPORT_OK) return status;
        PLAN(sizeof(struct bbp_tag_acpi));
    }
#undef PLAN

    if ((snapshot->present & BBP_IMPORT_HAS_HHDM) != 0)
        emit_hhdm(builder, snapshot->hhdm_offset);
    if (scan.mmap_offset != BBP_IMPORT_SIZE_MAX)
        emit_memory_map(builder, &scan, mmap_size);
    if ((snapshot->present & BBP_IMPORT_HAS_KERNEL_ADDRESS) != 0)
        emit_kernel_address(builder, snapshot);
    if (scan.cmdline_offset != BBP_IMPORT_SIZE_MAX)
        emit_cmdline(builder, &scan);
    if (scan.module_count != 0)
        emit_modules(builder, &scan, modules_size);
    if (scan.framebuffer_offset != BBP_IMPORT_SIZE_MAX)
        emit_framebuffer(builder, &scan.framebuffer);
    if (scan.acpi_offset != BBP_IMPORT_SIZE_MAX)
        emit_acpi(builder, &scan);
    return BBP_IMPORT_OK;
}
