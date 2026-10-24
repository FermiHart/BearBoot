/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_crc64.h>
#include "bbp_bridge.h"

#define V1_MAX_TAG_SIZE (16u * 1024u * 1024u)
#define V1_MAX_INFO_SIZE (64u * 1024u * 1024u)
#define V1_MAX_PHYS (UINT64_C(1) << 48)

static const uint8_t v1_info_magic[16] = BBP_INFO_MAGIC;

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8u * i);
    return value;
}

static void put16(uint8_t *p, uint16_t value)
{
    unsigned i;
    for (i = 0; i < 2; i++) p[i] = (uint8_t)(value >> (8u * i));
}

static void put32(uint8_t *p, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8u * i));
}

static void put64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8u * i));
}

static void bytes_zero(void *data, size_t size)
{
    uint8_t *p = (uint8_t *)data;
    while (size--) *p++ = 0;
}

static void bytes_copy(void *destination, const void *source, size_t size)
{
    uint8_t *d = (uint8_t *)destination;
    const uint8_t *s = (const uint8_t *)source;
    while (size--) *d++ = *s++;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    while (size--) {
        if (*a++ != *b++) return 0;
    }
    return 1;
}

static int memory_ranges_overlap(const void *a_pointer, size_t a_size,
                                 const void *b_pointer, size_t b_size)
{
    uintptr_t a = (uintptr_t)a_pointer;
    uintptr_t b = (uintptr_t)b_pointer;
    if (a_size > (uintptr_t)-1 - a || b_size > (uintptr_t)-1 - b) return 1;
    return a < b + b_size && b < a + a_size;
}

static uint64_t crc_skip(const uint8_t *data, size_t size, size_t offset)
{
    static const uint8_t zero[8] = {0};
    uint64_t crc;
    if (size < offset + 8u) return 0;
    crc = bbp_crc64_init();
    crc = bbp_crc64_update(crc, data, offset);
    crc = bbp_crc64_update(crc, zero, sizeof(zero));
    crc = bbp_crc64_update(crc, data + offset + 8u, size - offset - 8u);
    return bbp_crc64_final(crc);
}

static uint64_t capsule_crc(const uint8_t *data, size_t size)
{
    return crc_skip(data, size, 40);
}

static int array_fits(size_t total, size_t base, uint32_t count, size_t stride)
{
    if (base > total) return 0;
    return (size_t)count <= (total - base) / stride;
}

static int array_is_exact(size_t total, size_t base, uint32_t count,
                          size_t stride)
{
    if (!array_fits(total, base, count, stride)) return 0;
    return (total - base) / stride == count &&
           (total - base) % stride == 0;
}

/* Returns -1 for a malformed known tag, 0 for a self-contained tag, and 1
 * when conversion can only preserve physical references as external values. */
static int tag_external_references(const uint8_t *tag, size_t size)
{
    uint64_t id = get64(tag);
    uint32_t count, i;
    int opaque = get16(tag + 12) != 1u || get16(tag + 14) != BBP_TF_NONE;

    switch (id) {
    case BBP_TAG_HHDM:
        if (size < sizeof(struct bbp_tag_hhdm)) return -1;
        return opaque || size != sizeof(struct bbp_tag_hhdm);
    case BBP_TAG_KERNEL_ADDRESS:
        if (size < sizeof(struct bbp_tag_kernel_address)) return -1;
        return opaque || size != sizeof(struct bbp_tag_kernel_address);
    case BBP_TAG_MEMORY_MAP:
        if (size < sizeof(struct bbp_tag_memory_map)) return -1;
        count = get32(tag + 32);
        if (get32(tag + 36) < sizeof(struct bbp_memory_entry) ||
            !array_fits(size, sizeof(struct bbp_tag_memory_map), count,
                         get32(tag + 36))) return -1;
        return opaque || get32(tag + 36) != sizeof(struct bbp_memory_entry) ||
               !array_is_exact(size, sizeof(struct bbp_tag_memory_map), count,
                               get32(tag + 36));
    case BBP_TAG_CMDLINE:
        if (size < sizeof(struct bbp_tag_cmdline)) return -1;
        return get64(tag + 32) != 0 || opaque ||
               size != sizeof(struct bbp_tag_cmdline);
    case BBP_TAG_ACPI:
        if (size < sizeof(struct bbp_tag_acpi)) return -1;
        return get64(tag + 32) != 0 || get64(tag + 40) != 0 || opaque ||
               size != sizeof(struct bbp_tag_acpi);
    case BBP_TAG_SMBIOS:
        if (size < sizeof(struct bbp_tag_smbios)) return -1;
        return get64(tag + 32) != 0 || get64(tag + 40) != 0 || opaque ||
               size != sizeof(struct bbp_tag_smbios);
    case BBP_TAG_EFI:
        if (size < sizeof(struct bbp_tag_efi)) return -1;
        return get64(tag + 32) != 0 || get64(tag + 40) != 0 || opaque ||
               size != sizeof(struct bbp_tag_efi);
    case BBP_TAG_DEVICETREE:
        if (size < sizeof(struct bbp_tag_devicetree)) return -1;
        return get64(tag + 32) != 0 || get64(tag + 56) != 0 || opaque ||
               size != sizeof(struct bbp_tag_devicetree);
    case BBP_TAG_SECURITY:
        if (size < sizeof(struct bbp_tag_security)) return -1;
        return get64(tag + 32) != 0 || get64(tag + 64) != 0 ||
               get64(tag + 80) != 0 || get64(tag + 96) != 0 || opaque ||
               size != sizeof(struct bbp_tag_security);
    case BBP_TAG_FRAMEBUFFER:
        if (size < sizeof(struct bbp_tag_framebuffer)) return -1;
        count = get16(tag + 40);
        if (!array_fits(size, sizeof(struct bbp_tag_framebuffer), count,
                        sizeof(struct bbp_display_info))) return -1;
        if (get64(tag + 32) != 0 || get64(tag + 56) != 0) return 1;
        for (i = 0; i < count; i++) {
            const uint8_t *display = tag + sizeof(struct bbp_tag_framebuffer) +
                                     (size_t)i * sizeof(struct bbp_display_info);
            if (get64(display + 32) != 0) return 1;
        }
        return opaque || !array_is_exact(
            size, sizeof(struct bbp_tag_framebuffer), count,
            sizeof(struct bbp_display_info));
    case BBP_TAG_SMP:
        if (size < sizeof(struct bbp_tag_smp)) return -1;
        count = get32(tag + 32);
        if (!array_fits(size, sizeof(struct bbp_tag_smp), count,
                        sizeof(struct bbp_cpu_info))) return -1;
        for (i = 0; i < count; i++) {
            const uint8_t *cpu = tag + sizeof(struct bbp_tag_smp) +
                                 (size_t)i * sizeof(struct bbp_cpu_info);
            if (get64(cpu + 32) != 0) return 1;
        }
        return opaque || !array_is_exact(size, sizeof(struct bbp_tag_smp),
                                         count, sizeof(struct bbp_cpu_info));
    case BBP_TAG_MODULES:
        if (size < sizeof(struct bbp_tag_modules)) return -1;
        count = get32(tag + 32);
        if (!array_fits(size, sizeof(struct bbp_tag_modules), count,
                        sizeof(struct bbp_module_entry))) return -1;
        for (i = 0; i < count; i++) {
            const uint8_t *module = tag + sizeof(struct bbp_tag_modules) +
                                    (size_t)i * sizeof(struct bbp_module_entry);
            if (get64(module) != 0 || get64(module + 96) != 0) return 1;
        }
        return opaque || !array_is_exact(
            size, sizeof(struct bbp_tag_modules), count,
            sizeof(struct bbp_module_entry));
    case BBP_TAG_PCIE:
        if (size < sizeof(struct bbp_tag_pcie)) return -1;
        count = get32(tag + 40);
        if (!array_fits(size, sizeof(struct bbp_tag_pcie), count,
                        sizeof(struct bbp_pcie_device))) return -1;
        if (get64(tag + 32) != 0) return 1;
        for (i = 0; i < count; i++) {
            const uint8_t *device = tag + sizeof(struct bbp_tag_pcie) +
                                    (size_t)i * sizeof(struct bbp_pcie_device);
            uint32_t bar_count = get32(device + 16);
            uint32_t j;
            if (bar_count > 6u) return -1;
            for (j = 0; j < 6u; j++) {
                if (get64(device + 24u + (size_t)j *
                          sizeof(struct bbp_pcie_bar)) != 0) return 1;
            }
        }
        return opaque || !array_is_exact(
            size, sizeof(struct bbp_tag_pcie), count,
            sizeof(struct bbp_pcie_device));
    case BBP_TAG_METRICS:
        if (size < sizeof(struct bbp_tag_metrics)) return -1;
        count = get32(tag + 40);
        if (!array_fits(size, sizeof(struct bbp_tag_metrics), count,
                        sizeof(struct bbp_boot_phase))) return -1;
        return opaque || !array_is_exact(
            size, sizeof(struct bbp_tag_metrics), count,
            sizeof(struct bbp_boot_phase));
    case BBP_TAG_HYPERVISOR:
        if (size < sizeof(struct bbp_tag_hypervisor)) return -1;
        return opaque || size != sizeof(struct bbp_tag_hypervisor);
    default:
        /* An opaque v1 body cannot honestly be claimed pointer-free. */
        return 1;
    }
}

static void normalize_info(struct bbp_v2_v1_info_payload *out,
                           const uint8_t *info)
{
    uint8_t *p = (uint8_t *)out;
    bytes_zero(out, sizeof(*out));
    bytes_copy(p, info + 24, 32);
    bytes_copy(p + 32, info + 56, 16);
    bytes_copy(p + 48, info + 72, 16);
    put64(p + 64, get64(info + 88));
    put64(p + 72, get64(info + 96));
    put64(p + 80, get64(info + 104));
    put16(p + 88, get16(info + 112));
    put16(p + 90, get16(info + 114));
    put64(p + 96, get64(info + 128));
}

bbp_v2_status_t bbp_v2_from_v1(
    const struct bbp_v2_v1_source *source, uint32_t policy,
    struct bbp_v2_bridge_workspace *workspace,
    void *output, size_t capacity, size_t *written,
    struct bbp_v2_bridge_report *report)
{
    const uint8_t *info;
    uint32_t tag_count, external_count = 0, i;
    uint64_t current;
    size_t built = 0, projected, payload_work;
    size_t source_crc_work = sizeof(struct bbp_info);
    bbp_v2_status_t status;
    struct bbp_v2_bridge_report candidate;

    if (!source || !source->info || !workspace || !output || !written)
        return BBP_V2_ERR_NULL;
    if ((policy & ~BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS) != 0)
        return BBP_V2_ERR_POLICY;
    if (memory_ranges_overlap(output, capacity, written, sizeof(*written)) ||
        memory_ranges_overlap(output, capacity, workspace,
                              sizeof(*workspace)) ||
        memory_ranges_overlap(output, capacity, source, sizeof(*source)) ||
        memory_ranges_overlap(workspace, sizeof(*workspace), source,
                              sizeof(*source)) ||
        (report &&
         (memory_ranges_overlap(output, capacity, report, sizeof(*report)) ||
          memory_ranges_overlap(written, sizeof(*written), report,
                                sizeof(*report)) ||
          memory_ranges_overlap(workspace, sizeof(*workspace), report,
                                sizeof(*report)) ||
          memory_ranges_overlap(source, sizeof(*source), report,
                                sizeof(*report)))) ||
        memory_ranges_overlap(workspace, sizeof(*workspace), written,
                              sizeof(*written)) ||
        memory_ranges_overlap(source, sizeof(*source), written,
                              sizeof(*written)))
        return BBP_V2_ERR_SOURCE;
    info = (const uint8_t *)source->info;
    if (memory_ranges_overlap(info, sizeof(struct bbp_info), output, capacity) ||
        memory_ranges_overlap(info, sizeof(struct bbp_info), workspace,
                              sizeof(*workspace)) ||
        memory_ranges_overlap(info, sizeof(struct bbp_info), written,
                              sizeof(*written)) ||
        (report && memory_ranges_overlap(info, sizeof(struct bbp_info), report,
                                         sizeof(*report))))
        return BBP_V2_ERR_SOURCE;
    if (!bytes_equal(info, v1_info_magic, sizeof(v1_info_magic)) ||
        get16(info + 16) != BBP_VERSION_MAJOR ||
        get16(info + 18) != BBP_VERSION_MINOR)
        return BBP_V2_ERR_SOURCE;
    if (get32(info + 20) < sizeof(struct bbp_info) ||
        get32(info + 20) > V1_MAX_INFO_SIZE ||
        crc_skip(info, sizeof(struct bbp_info), 136) != get64(info + 136))
        return BBP_V2_ERR_SOURCE;
    tag_count = get32(info + 116);
    if (tag_count > BBP_V2_MAX_ENTRIES - 1u) return BBP_V2_ERR_COUNT;
    current = get64(info + 120);
    if ((tag_count == 0) != (current == 0) ||
        (current != 0 && ((current & 7u) != 0 || !source->map)))
        return BBP_V2_ERR_SOURCE;
    if (get64(info + 128) != 0 &&
        (policy & BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS) == 0)
        return BBP_V2_ERR_POLICY;

    /* Prove every mapped source span disjoint from mutable call storage before
     * the workspace is touched. The immutable map contract then permits the
     * normal validating pass below to populate descriptors safely. */
    projected = BBP_V2_HEADER_SIZE +
                (size_t)(tag_count + 1u) * BBP_V2_DIRENT_SIZE;
    projected = (projected + 7u) & ~(size_t)7u;
    projected += sizeof(struct bbp_v2_v1_info_payload);
    payload_work = sizeof(struct bbp_v2_v1_info_payload);
    for (i = 0; i < tag_count; i++) {
        const uint8_t *mapped_header, *tag;
        uint8_t header[sizeof(struct bbp_tag_header)];
        uint32_t size;

        if (current == 0 || (current & 7u) != 0 ||
            current >= V1_MAX_PHYS ||
            sizeof(header) > V1_MAX_PHYS - current)
            return BBP_V2_ERR_SOURCE;
        mapped_header = (const uint8_t *)source->map(
            source->map_user, current, sizeof(struct bbp_tag_header));
        if (!mapped_header ||
            memory_ranges_overlap(mapped_header, sizeof(header), workspace,
                                  sizeof(*workspace)) ||
            memory_ranges_overlap(mapped_header, sizeof(header), output,
                                  capacity) ||
            memory_ranges_overlap(mapped_header, sizeof(header), written,
                                  sizeof(*written)) ||
            memory_ranges_overlap(mapped_header, sizeof(header), source,
                                  sizeof(*source)) ||
            (report && memory_ranges_overlap(mapped_header, sizeof(header),
                                             report, sizeof(*report))))
            return BBP_V2_ERR_SOURCE;
        bytes_copy(header, mapped_header, sizeof(header));
        size = get32(header + 8);
        if (size < sizeof(struct bbp_tag_header) || size > V1_MAX_TAG_SIZE ||
            size > V1_MAX_PHYS - current)
            return BBP_V2_ERR_SOURCE;
        projected = (projected + 7u) & ~(size_t)7u;
        if (size > (size_t)-1 - projected) return BBP_V2_ERR_OVERFLOW;
        projected += size;
        if (size > BBP_V2_MAX_CRC_WORK - payload_work)
            return BBP_V2_ERR_WORK;
        payload_work += size;
        if (projected > BBP_V2_MAX_EXTENT) return BBP_V2_ERR_EXTENT;
        if (projected > BBP_V2_MAX_CRC_WORK - payload_work)
            return BBP_V2_ERR_WORK;
        if (size > (BBP_V2_MAX_CRC_WORK - source_crc_work) / 2u)
            return BBP_V2_ERR_WORK;
        source_crc_work += (size_t)size * 2u;
        tag = (const uint8_t *)source->map(source->map_user, current, size);
        if (!tag || !bytes_equal(tag, header, sizeof(header)) ||
            memory_ranges_overlap(tag, size, workspace, sizeof(*workspace)) ||
            memory_ranges_overlap(tag, size, output, capacity) ||
            memory_ranges_overlap(tag, size, written, sizeof(*written)) ||
            memory_ranges_overlap(tag, size, source, sizeof(*source)) ||
            (report && memory_ranges_overlap(tag, size, report,
                                             sizeof(*report))) ||
            crc_skip(tag, size, 24) != get64(tag + 24))
            return BBP_V2_ERR_SOURCE;
        current = get64(tag + 16);
    }
    if (current != 0) return BBP_V2_ERR_SOURCE;
    current = get64(info + 120);

    normalize_info(&workspace->info_payload, info);
    workspace->entries[0].type = BBP_V2_ENTRY_V1_INFO;
    workspace->entries[0].flags = 0;
    workspace->entries[0].version = BBP_VERSION_MINOR;
    workspace->entries[0].alignment = 8;
    workspace->entries[0].data = &workspace->info_payload;
    workspace->entries[0].size = sizeof(workspace->info_payload);
    if (get64(info + 128) != 0) {
        workspace->entries[0].flags |= BBP_V2_EF_EXTERNAL_PHYS;
        external_count++;
    }

    for (i = 0; i < tag_count; i++) {
        const uint8_t *mapped_header, *tag;
        uint8_t header[sizeof(struct bbp_tag_header)];
        uint32_t size, j;
        uint64_t next;
        int external;

        if (current == 0 || (current & 7u) != 0 ||
            current >= V1_MAX_PHYS ||
            sizeof(header) > V1_MAX_PHYS - current)
            return BBP_V2_ERR_SOURCE;
        for (j = 0; j < i; j++) {
            if (workspace->visited[j] == current) return BBP_V2_ERR_SOURCE;
        }
        mapped_header = (const uint8_t *)source->map(
            source->map_user, current, sizeof(struct bbp_tag_header));
        if (!mapped_header ||
            memory_ranges_overlap(mapped_header, sizeof(header), workspace,
                                  sizeof(*workspace)) ||
            memory_ranges_overlap(mapped_header, sizeof(header), output,
                                  capacity) ||
            memory_ranges_overlap(mapped_header, sizeof(header), written,
                                  sizeof(*written)) ||
            memory_ranges_overlap(mapped_header, sizeof(header), source,
                                  sizeof(*source)) ||
            (report && memory_ranges_overlap(mapped_header, sizeof(header),
                                             report, sizeof(*report))))
            return BBP_V2_ERR_SOURCE;
        bytes_copy(header, mapped_header, sizeof(header));
        size = get32(header + 8);
        if (size < sizeof(struct bbp_tag_header) || size > V1_MAX_TAG_SIZE)
            return BBP_V2_ERR_SOURCE;
        if (size > V1_MAX_PHYS - current) return BBP_V2_ERR_SOURCE;
        for (j = 0; j < i; j++) {
            uint64_t prior = workspace->visited[j];
            uint64_t prior_size = workspace->entries[j + 1u].size;
            if (current < prior + prior_size && prior < current + size)
                return BBP_V2_ERR_SOURCE;
        }
        tag = (const uint8_t *)source->map(source->map_user, current, size);
        if (!tag || !bytes_equal(tag, header, sizeof(header)) ||
            memory_ranges_overlap(tag, size, workspace, sizeof(*workspace)) ||
            memory_ranges_overlap(tag, size, output, capacity) ||
            memory_ranges_overlap(tag, size, written, sizeof(*written)) ||
            memory_ranges_overlap(tag, size, source, sizeof(*source)) ||
            (report && memory_ranges_overlap(tag, size, report,
                                             sizeof(*report))) ||
            crc_skip(tag, size, 24) != get64(tag + 24))
            return BBP_V2_ERR_SOURCE;
        external = tag_external_references(tag, size);
        if (external < 0) return BBP_V2_ERR_SOURCE;
        if (external && (policy & BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS) == 0)
            return BBP_V2_ERR_POLICY;

        workspace->visited[i] = current;
        workspace->entries[i + 1u].type = get64(tag);
        workspace->entries[i + 1u].flags = BBP_V2_EF_V1_WIRE |
            (external ? BBP_V2_EF_EXTERNAL_PHYS : 0u);
        workspace->entries[i + 1u].version = get16(tag + 12);
        workspace->entries[i + 1u].alignment = 8;
        workspace->entries[i + 1u].data = tag;
        workspace->entries[i + 1u].size = size;
        if (external) external_count++;
        next = get64(tag + 16);
        current = next;
    }
    if (current != 0) return BBP_V2_ERR_SOURCE;

    status = bbp_v2_build(output, capacity, workspace->entries,
                          tag_count + 1u, &built);
    if (status != BBP_V2_OK) return status;

    /* Normalize v1 linkage only after all fallible work has completed. */
    for (i = 0; i < tag_count; i++) {
        uint8_t *entry = (uint8_t *)output + BBP_V2_HEADER_SIZE +
                         (size_t)(i + 1u) * BBP_V2_DIRENT_SIZE;
        uint8_t *tag = (uint8_t *)output + (size_t)get64(entry + 16);
        size_t size = (size_t)get64(entry + 24);
        put64(tag + 16, 0);
        put64(tag + 24, 0);
        put64(entry + 32, bbp_crc64(tag, size));
    }
    put64((uint8_t *)output + 40, 0);
    put64((uint8_t *)output + 40, capsule_crc((const uint8_t *)output, built));

    candidate.tag_count = tag_count;
    candidate.external_reference_entries = external_count;
    if (report) *report = candidate;
    *written = built;
    return BBP_V2_OK;
}

static void restore_info(uint8_t *info, const uint8_t *payload,
                         uint32_t tag_count, uint64_t first_tag,
                         uint32_t total_size)
{
    bytes_zero(info, sizeof(struct bbp_info));
    bytes_copy(info, v1_info_magic, sizeof(v1_info_magic));
    put16(info + 16, BBP_VERSION_MAJOR);
    put16(info + 18, BBP_VERSION_MINOR);
    put32(info + 20, total_size);
    bytes_copy(info + 24, payload, 32);
    bytes_copy(info + 56, payload + 32, 16);
    bytes_copy(info + 72, payload + 48, 16);
    put64(info + 88, get64(payload + 64));
    put64(info + 96, get64(payload + 72));
    put64(info + 104, get64(payload + 80));
    put16(info + 112, get16(payload + 88));
    put16(info + 114, get16(payload + 90));
    put32(info + 116, tag_count);
    put64(info + 120, first_tag);
    put64(info + 128, get64(payload + 96));
    put64(info + 136, crc_skip(info, sizeof(struct bbp_info), 136));
}

bbp_v2_status_t bbp_v2_to_v1(
    const struct bbp_v2_view *source, uint32_t policy,
    void *output_pointer, size_t capacity, bbp_phys_t output_phys,
    size_t *written, struct bbp_v2_bridge_report *report)
{
    struct bbp_v2_view checked;
    struct bbp_v2_entry_view info_entry;
    struct bbp_v2_bridge_report candidate;
    uint8_t *output = (uint8_t *)output_pointer;
    size_t cursor = sizeof(struct bbp_info), total;
    uint32_t i, tag_count, external_count = 0;
    bbp_v2_status_t status;

    if (!source || !source->data || !output || !written)
        return BBP_V2_ERR_NULL;
    if ((policy & ~BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS) != 0)
        return BBP_V2_ERR_POLICY;
    if (memory_ranges_overlap(source, sizeof(*source), written,
                              sizeof(*written)) ||
        (report &&
         (memory_ranges_overlap(written, sizeof(*written), report,
                                sizeof(*report)) ||
          memory_ranges_overlap(source, sizeof(*source), report,
                                sizeof(*report)))))
        return BBP_V2_ERR_SOURCE;
    status = bbp_v2_parse(source->data, source->total_size, &checked);
    if (status != BBP_V2_OK) return status;
    if (checked.entry_count == 0) return BBP_V2_ERR_SOURCE;
    (void)bbp_v2_get_entry(&checked, 0, &info_entry);
    if (info_entry.type != BBP_V2_ENTRY_V1_INFO ||
        info_entry.version != BBP_VERSION_MINOR ||
        info_entry.size != sizeof(struct bbp_v2_v1_info_payload) ||
        (info_entry.flags & ~BBP_V2_EF_EXTERNAL_PHYS) != 0)
        return BBP_V2_ERR_SOURCE;
    if (get32(info_entry.data + 92) != 0 ||
        ((get64(info_entry.data + 96) != 0) !=
         ((info_entry.flags & BBP_V2_EF_EXTERNAL_PHYS) != 0)))
        return BBP_V2_ERR_SOURCE;
    if ((info_entry.flags & BBP_V2_EF_EXTERNAL_PHYS) != 0) external_count++;
    tag_count = checked.entry_count - 1u;

    for (i = 0; i < tag_count; i++) {
        struct bbp_v2_entry_view entry;
        int external;
        (void)bbp_v2_get_entry(&checked, i + 1u, &entry);
        if ((entry.flags & BBP_V2_EF_V1_WIRE) == 0 ||
            (entry.flags & ~(BBP_V2_EF_V1_WIRE |
                             BBP_V2_EF_EXTERNAL_PHYS)) != 0 ||
            entry.size < sizeof(struct bbp_tag_header) ||
            entry.size > V1_MAX_TAG_SIZE ||
            get64(entry.data) != entry.type ||
            get32(entry.data + 8) != entry.size ||
            get16(entry.data + 12) != entry.version ||
            get64(entry.data + 16) != 0 || get64(entry.data + 24) != 0)
            return BBP_V2_ERR_SOURCE;
        external = tag_external_references(entry.data, entry.size);
        if (external < 0 ||
            ((external != 0) !=
             ((entry.flags & BBP_V2_EF_EXTERNAL_PHYS) != 0)))
            return BBP_V2_ERR_SOURCE;
        if ((entry.flags & BBP_V2_EF_EXTERNAL_PHYS) != 0) external_count++;
        if (cursor > (size_t)-1 - 7u) return BBP_V2_ERR_OVERFLOW;
        cursor = (cursor + 7u) & ~(size_t)7u;
        if (entry.size > (size_t)-1 - cursor) return BBP_V2_ERR_OVERFLOW;
        cursor += entry.size;
        if (cursor > V1_MAX_INFO_SIZE) return BBP_V2_ERR_EXTENT;
    }
    if (external_count != 0 &&
        (policy & BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS) == 0)
        return BBP_V2_ERR_POLICY;
    total = cursor;
    if (total > capacity) return BBP_V2_ERR_CAPACITY;
    if (output_phys == 0 || (output_phys & 7u) != 0 ||
        output_phys >= V1_MAX_PHYS || total > V1_MAX_PHYS - output_phys)
        return BBP_V2_ERR_OVERFLOW;
    if (memory_ranges_overlap(output, total, checked.data, checked.total_size))
        return BBP_V2_ERR_SOURCE;
    if (memory_ranges_overlap(output, total, written, sizeof(*written)) ||
        memory_ranges_overlap(output, total, source, sizeof(*source)) ||
        memory_ranges_overlap(checked.data, checked.total_size, written,
                              sizeof(*written)) ||
        (report &&
         (memory_ranges_overlap(output, total, report, sizeof(*report)) ||
          memory_ranges_overlap(checked.data, checked.total_size, report,
                                sizeof(*report)))))
        return BBP_V2_ERR_SOURCE;

    bytes_zero(output, total);
    cursor = sizeof(struct bbp_info);
    for (i = 0; i < tag_count; i++) {
        struct bbp_v2_entry_view entry;
        uint8_t *tag;
        uint64_t next;
        (void)bbp_v2_get_entry(&checked, i + 1u, &entry);
        cursor = (cursor + 7u) & ~(size_t)7u;
        tag = output + cursor;
        bytes_copy(tag, entry.data, entry.size);
        next = (i + 1u < tag_count)
            ? output_phys + (uint64_t)((cursor + entry.size + 7u) & ~(size_t)7u)
            : 0;
        put64(tag + 16, next);
        put64(tag + 24, 0);
        put64(tag + 24, crc_skip(tag, entry.size, 24));
        cursor += entry.size;
    }
    restore_info(output, info_entry.data, tag_count,
                 tag_count ? output_phys + sizeof(struct bbp_info) : 0,
                 (uint32_t)total);

    candidate.tag_count = tag_count;
    candidate.external_reference_entries = external_count;
    if (report) *report = candidate;
    *written = total;
    return BBP_V2_OK;
}
