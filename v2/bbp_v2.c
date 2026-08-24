/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_crc64.h>
#include <bbp/bbp_v2.h>

static const uint8_t bbp_v2_magic[8] = BBP_V2_MAGIC_BYTES;

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

static int bytes_are_zero(const uint8_t *p, size_t size)
{
    while (size--) {
        if (*p++ != 0) return 0;
    }
    return 1;
}

static int power_of_two(uint32_t value)
{
    return value != 0 && (value & (value - 1u)) == 0;
}

static int span_overlaps(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    return a < b + bs && b < a + as;
}

static const uint8_t *directory_entry(const uint8_t *capsule,
                                      size_t directory_offset, uint32_t index)
{
    return capsule + directory_offset + (size_t)index * BBP_V2_DIRENT_SIZE;
}

static uint64_t crc_with_zero_checksum(const uint8_t *capsule, size_t extent)
{
    static const uint8_t zero[8] = {0};
    uint64_t crc = bbp_crc64_init();
    crc = bbp_crc64_update(crc, capsule, 40);
    crc = bbp_crc64_update(crc, zero, sizeof(zero));
    crc = bbp_crc64_update(crc, capsule + 48, extent - 48);
    return bbp_crc64_final(crc);
}

static bbp_v2_status_t validate_padding(const uint8_t *capsule, size_t extent,
                                        size_t directory_offset,
                                        uint32_t entry_count)
{
    uint64_t cursor = 0;
    uint32_t step;
    uint32_t span_count = entry_count + 1u + (entry_count != 0 ? 1u : 0u);

    /* Selection over at most 1026 spans avoids allocation and keeps work
     * bounded by the public entry cap. Overlap checks have already passed. */
    for (step = 0; step < span_count; step++) {
        uint64_t best_start = (uint64_t)extent;
        uint64_t best_size = 0;
        uint32_t i;

        if (cursor == 0) {
            best_start = 0;
            best_size = BBP_V2_HEADER_SIZE;
        }
        if (entry_count != 0 && (uint64_t)directory_offset >= cursor &&
            (uint64_t)directory_offset < best_start) {
            best_start = (uint64_t)directory_offset;
            best_size = (uint64_t)entry_count * BBP_V2_DIRENT_SIZE;
        }
        for (i = 0; i < entry_count; i++) {
            const uint8_t *entry = directory_entry(capsule, directory_offset, i);
            uint64_t start = get64(entry + 16);
            if (start >= cursor && start < best_start) {
                best_start = start;
                best_size = get64(entry + 24);
            }
        }
        if (best_size == 0) return BBP_V2_ERR_FORMAT;
        if (best_start > cursor &&
            !bytes_are_zero(capsule + (size_t)cursor,
                            (size_t)(best_start - cursor)))
            return BBP_V2_ERR_PADDING;
        cursor = best_start + best_size;
    }
    if (cursor < (uint64_t)extent &&
        !bytes_are_zero(capsule + (size_t)cursor,
                        extent - (size_t)cursor))
        return BBP_V2_ERR_PADDING;
    return BBP_V2_OK;
}

bbp_v2_status_t bbp_v2_parse(const void *capsule_pointer, size_t extent,
                             struct bbp_v2_view *out)
{
    const uint8_t *capsule = (const uint8_t *)capsule_pointer;
    struct bbp_v2_view candidate;
    uint64_t total_size, directory_offset, directory_size, crc_work;
    uint32_t entry_count, i;
    bbp_v2_status_t status;

    if (!capsule || !out) return BBP_V2_ERR_NULL;
    if (extent < BBP_V2_HEADER_SIZE || extent > BBP_V2_MAX_EXTENT)
        return BBP_V2_ERR_EXTENT;
    if (!bytes_equal(capsule, bbp_v2_magic, sizeof(bbp_v2_magic)))
        return BBP_V2_ERR_MAGIC;
    if (get16(capsule + 8) != BBP_V2_VERSION_MAJOR ||
        get16(capsule + 10) != BBP_V2_VERSION_MINOR)
        return BBP_V2_ERR_VERSION;
    if (get16(capsule + 12) != BBP_V2_HEADER_SIZE ||
        get16(capsule + 14) != BBP_V2_DIRENT_SIZE ||
        get32(capsule + 16) != 0 ||
        get64(capsule + 48) != 0 || get64(capsule + 56) != 0)
        return BBP_V2_ERR_FORMAT;

    total_size = get64(capsule + 24);
    if (total_size != (uint64_t)extent || total_size > BBP_V2_MAX_EXTENT)
        return BBP_V2_ERR_EXTENT;
    entry_count = get32(capsule + 20);
    if (entry_count > BBP_V2_MAX_ENTRIES) return BBP_V2_ERR_COUNT;
    directory_offset = get64(capsule + 32);
    if ((directory_offset & 7u) != 0)
        return BBP_V2_ERR_ALIGNMENT;
    if (entry_count == 0 &&
        (directory_offset != BBP_V2_HEADER_SIZE ||
         total_size != BBP_V2_HEADER_SIZE))
        return BBP_V2_ERR_FORMAT;
    directory_size = (uint64_t)entry_count * BBP_V2_DIRENT_SIZE;
    if (directory_offset < BBP_V2_HEADER_SIZE ||
        directory_offset > total_size ||
        directory_size > total_size - directory_offset)
        return BBP_V2_ERR_OVERFLOW;

    crc_work = total_size;
    for (i = 0; i < entry_count; i++) {
        const uint8_t *entry = directory_entry(
            capsule, (size_t)directory_offset, i);
        uint64_t offset = get64(entry + 16);
        uint64_t size = get64(entry + 24);
        uint32_t alignment = get32(entry + 40);
        uint32_t j;

        if (get16(entry + 14) != 0 || get32(entry + 44) != 0)
            return BBP_V2_ERR_FORMAT;
        if (!power_of_two(alignment) || alignment > BBP_V2_MAX_ALIGNMENT ||
            (offset & (uint64_t)(alignment - 1u)) != 0)
            return BBP_V2_ERR_ALIGNMENT;
        if (size == 0) return BBP_V2_ERR_FORMAT;
        if (offset > total_size || size > total_size - offset)
            return BBP_V2_ERR_OVERFLOW;
        if (span_overlaps(offset, size, 0, BBP_V2_HEADER_SIZE) ||
            span_overlaps(offset, size, directory_offset, directory_size))
            return BBP_V2_ERR_OVERLAP;
        for (j = 0; j < i; j++) {
            const uint8_t *prior = directory_entry(
                capsule, (size_t)directory_offset, j);
            if (span_overlaps(offset, size, get64(prior + 16),
                              get64(prior + 24)))
                return BBP_V2_ERR_OVERLAP;
        }
        if (size > BBP_V2_MAX_CRC_WORK - crc_work)
            return BBP_V2_ERR_WORK;
        crc_work += size;
    }

    status = validate_padding(capsule, extent, (size_t)directory_offset,
                              entry_count);
    if (status != BBP_V2_OK) return status;

    /* No checksum-controlled length or offset is used until every span above
     * has been proven inside the mandatory total extent. */
    if (crc_with_zero_checksum(capsule, extent) != get64(capsule + 40))
        return BBP_V2_ERR_CRC;
    for (i = 0; i < entry_count; i++) {
        const uint8_t *entry = directory_entry(
            capsule, (size_t)directory_offset, i);
        uint64_t offset = get64(entry + 16);
        uint64_t size = get64(entry + 24);
        if (bbp_crc64(capsule + (size_t)offset, (size_t)size) !=
            get64(entry + 32))
            return BBP_V2_ERR_CRC;
    }

    candidate.data = capsule;
    candidate.total_size = extent;
    candidate.directory_offset = (size_t)directory_offset;
    candidate.flags = get32(capsule + 16);
    candidate.entry_count = entry_count;
    *out = candidate;
    return BBP_V2_OK;
}

bbp_v2_status_t bbp_v2_get_entry(const struct bbp_v2_view *view,
                                 uint32_t index,
                                 struct bbp_v2_entry_view *out)
{
    const uint8_t *entry;
    struct bbp_v2_entry_view candidate;
    uint64_t directory_size, offset, size;
    if (!view || !view->data || !out) return BBP_V2_ERR_NULL;
    if (view->entry_count > BBP_V2_MAX_ENTRIES ||
        index >= view->entry_count) return BBP_V2_ERR_COUNT;
    directory_size = (uint64_t)view->entry_count * BBP_V2_DIRENT_SIZE;
    if (view->total_size < BBP_V2_HEADER_SIZE ||
        view->total_size > BBP_V2_MAX_EXTENT ||
        view->directory_offset < BBP_V2_HEADER_SIZE ||
        view->directory_offset > view->total_size ||
        directory_size > view->total_size - view->directory_offset)
        return BBP_V2_ERR_EXTENT;
    entry = directory_entry(view->data, view->directory_offset, index);
    offset = get64(entry + 16);
    size = get64(entry + 24);
    if (offset > view->total_size || size > view->total_size - offset)
        return BBP_V2_ERR_EXTENT;
    candidate.type = get64(entry);
    candidate.flags = get32(entry + 8);
    candidate.version = get16(entry + 12);
    candidate.offset = offset;
    candidate.size = (size_t)size;
    candidate.checksum = get64(entry + 32);
    candidate.alignment = get32(entry + 40);
    candidate.data = view->data + (size_t)candidate.offset;
    *out = candidate;
    return BBP_V2_OK;
}

static int align_up(size_t value, uint32_t alignment, size_t *out)
{
    size_t mask = (size_t)alignment - 1u;
    if (value > (size_t)-1 - mask) return 0;
    *out = (value + mask) & ~mask;
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

bbp_v2_status_t bbp_v2_build(void *output_pointer, size_t capacity,
                             const struct bbp_v2_build_entry *entries,
                             uint32_t entry_count, size_t *written)
{
    uint8_t *output = (uint8_t *)output_pointer;
    size_t cursor, total, payload_work = 0;
    uint32_t i;
    static const uint8_t magic[8] = BBP_V2_MAGIC_BYTES;

    if (written) *written = 0;
    if (!output || !written || (entry_count != 0 && !entries))
        return BBP_V2_ERR_NULL;
    if (entry_count > BBP_V2_MAX_ENTRIES) return BBP_V2_ERR_COUNT;
    cursor = BBP_V2_HEADER_SIZE + (size_t)entry_count * BBP_V2_DIRENT_SIZE;
    for (i = 0; i < entry_count; i++) {
        if (!entries[i].data || entries[i].size == 0)
            return BBP_V2_ERR_NULL;
        if (!power_of_two(entries[i].alignment) ||
            entries[i].alignment > BBP_V2_MAX_ALIGNMENT)
            return BBP_V2_ERR_ALIGNMENT;
        if (!align_up(cursor, entries[i].alignment, &cursor) ||
            entries[i].size > (size_t)-1 - cursor)
            return BBP_V2_ERR_OVERFLOW;
        cursor += entries[i].size;
        if (entries[i].size > BBP_V2_MAX_CRC_WORK - payload_work)
            return BBP_V2_ERR_WORK;
        payload_work += entries[i].size;
        if (cursor > BBP_V2_MAX_EXTENT) return BBP_V2_ERR_EXTENT;
    }
    total = cursor;
    if (total > BBP_V2_MAX_CRC_WORK - payload_work)
        return BBP_V2_ERR_WORK;
    if (total > capacity) return BBP_V2_ERR_CAPACITY;
    for (i = 0; i < entry_count; i++) {
        if (memory_ranges_overlap(output, total, entries[i].data,
                                  entries[i].size))
            return BBP_V2_ERR_SOURCE;
    }

    bytes_zero(output, total);
    bytes_copy(output, magic, sizeof(magic));
    put16(output + 8, BBP_V2_VERSION_MAJOR);
    put16(output + 10, BBP_V2_VERSION_MINOR);
    put16(output + 12, BBP_V2_HEADER_SIZE);
    put16(output + 14, BBP_V2_DIRENT_SIZE);
    put32(output + 16, 0);
    put32(output + 20, entry_count);
    put64(output + 24, (uint64_t)total);
    put64(output + 32, BBP_V2_HEADER_SIZE);

    cursor = BBP_V2_HEADER_SIZE + (size_t)entry_count * BBP_V2_DIRENT_SIZE;
    for (i = 0; i < entry_count; i++) {
        uint8_t *entry = output + BBP_V2_HEADER_SIZE +
                         (size_t)i * BBP_V2_DIRENT_SIZE;
        (void)align_up(cursor, entries[i].alignment, &cursor);
        bytes_copy(output + cursor, entries[i].data, entries[i].size);
        put64(entry, entries[i].type);
        put32(entry + 8, entries[i].flags);
        put16(entry + 12, entries[i].version);
        put64(entry + 16, (uint64_t)cursor);
        put64(entry + 24, (uint64_t)entries[i].size);
        put64(entry + 32, bbp_crc64(output + cursor, entries[i].size));
        put32(entry + 40, entries[i].alignment);
        cursor += entries[i].size;
    }
    put64(output + 40, crc_with_zero_checksum(output, total));
    *written = total;
    return BBP_V2_OK;
}

bbp_v2_status_t bbp_v2_digest(const struct bbp_v2_view *view,
                              bbp_v2_digest_update_fn update, void *state)
{
    static const uint8_t domain[16] = {
        'B', 'B', 'P', '-', 'V', '2', '-', 'D',
        'I', 'G', 'E', 'S', 'T', 0, 0, 1
    };
    struct bbp_v2_view checked;
    uint8_t envelope[16], frame[32];
    uint32_t i;
    bbp_v2_status_t status;

    if (!view || !view->data || !update) return BBP_V2_ERR_NULL;
    status = bbp_v2_parse(view->data, view->total_size, &checked);
    if (status != BBP_V2_OK) return status;
    bytes_zero(envelope, sizeof(envelope));
    put16(envelope, BBP_V2_VERSION_MAJOR);
    put16(envelope + 2, BBP_V2_VERSION_MINOR);
    put32(envelope + 4, checked.flags);
    put32(envelope + 8, checked.entry_count);
    update(state, domain, sizeof(domain));
    update(state, envelope, sizeof(envelope));
    for (i = 0; i < checked.entry_count; i++) {
        struct bbp_v2_entry_view entry;
        (void)bbp_v2_get_entry(&checked, i, &entry);
        bytes_zero(frame, sizeof(frame));
        put64(frame, entry.type);
        put32(frame + 8, entry.flags);
        put16(frame + 12, entry.version);
        put64(frame + 16, (uint64_t)entry.size);
        update(state, frame, sizeof(frame));
        update(state, entry.data, entry.size);
    }
    return BBP_V2_OK;
}

const char *bbp_v2_strstatus(bbp_v2_status_t status)
{
    switch (status) {
    case BBP_V2_OK: return "ok";
    case BBP_V2_ERR_NULL: return "null argument";
    case BBP_V2_ERR_MAGIC: return "bad magic";
    case BBP_V2_ERR_VERSION: return "unsupported version";
    case BBP_V2_ERR_FORMAT: return "invalid reserved or framing field";
    case BBP_V2_ERR_EXTENT: return "invalid total extent";
    case BBP_V2_ERR_OVERFLOW: return "integer overflow or out-of-bounds span";
    case BBP_V2_ERR_COUNT: return "entry count limit";
    case BBP_V2_ERR_ALIGNMENT: return "invalid alignment";
    case BBP_V2_ERR_OVERLAP: return "overlapping spans";
    case BBP_V2_ERR_PADDING: return "nonzero padding";
    case BBP_V2_ERR_CRC: return "CRC-64/XZ mismatch";
    case BBP_V2_ERR_WORK: return "validation work limit";
    case BBP_V2_ERR_CAPACITY: return "output capacity";
    case BBP_V2_ERR_POLICY: return "bridge policy";
    case BBP_V2_ERR_SOURCE: return "invalid or overlapping source";
    default: return "unknown";
    }
}
