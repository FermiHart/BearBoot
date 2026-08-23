/*
 * bbp_import.c - common validation and exact builder-capacity planning.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbp_import.h"

static int add_size(size_t left, size_t right, size_t *out)
{
    if (right > BBP_IMPORT_SIZE_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int align8(size_t value, size_t *out)
{
    if (value > BBP_IMPORT_SIZE_MAX - 7u)
        return 0;
    *out = (value + 7u) & ~(size_t)7u;
    return 1;
}

void bbp_import_memcpy(void *destination, const void *source, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    const uint8_t *s = (const uint8_t *)source;
    while (bytes-- != 0)
        *d++ = *s++;
}

void bbp_import_memzero(void *destination, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    while (bytes-- != 0)
        *d++ = 0;
}

int bbp_import_phys_address_valid(bbp_phys_t address, int allow_zero)
{
    return (allow_zero || address != 0) && address < BBP_IMPORT_MAX_PHYS;
}

int bbp_import_phys_range_valid(bbp_phys_t base, uint64_t length)
{
    return length != 0 && base < BBP_IMPORT_MAX_PHYS
        && length <= BBP_IMPORT_MAX_PHYS - base;
}

int bbp_import_ranges_overlap(const void *left, size_t left_bytes,
                              const void *right, size_t right_bytes)
{
    uintptr_t a = (uintptr_t)left;
    uintptr_t b = (uintptr_t)right;
    if (left_bytes > BBP_IMPORT_UINTPTR_MAX - a
        || right_bytes > BBP_IMPORT_UINTPTR_MAX - b)
        return 1;
    return a < b + right_bytes && b < a + left_bytes;
}

bbp_import_status bbp_import_plan_begin(const struct bbp_builder *builder,
                                        struct bbp_import_plan *plan)
{
    uintptr_t arena_address;
    if (builder == NULL || plan == NULL)
        return BBP_IMPORT_ERR_NULL;
    arena_address = (uintptr_t)builder->arena;
    if (builder->arena == NULL || builder->overflow != 0
        || builder->used > builder->capacity
        || builder->used > BBP_IMPORT_MAX_ARENA
        || builder->tag_count > BBP_IMPORT_MAX_TAGS
        || builder->arena_phys == 0
        || (builder->arena_phys & 7u) != 0
        || (arena_address & 7u) != 0
        || builder->capacity > BBP_IMPORT_UINTPTR_MAX - arena_address)
        return BBP_IMPORT_ERR_BUILDER;
    if (builder->arena_phys >= BBP_IMPORT_MAX_PHYS
        || builder->capacity > BBP_IMPORT_MAX_PHYS - builder->arena_phys)
        return BBP_IMPORT_ERR_BUILDER;
    if (builder->tag_count == 0) {
        if (builder->last != NULL || builder->first_phys != 0)
            return BBP_IMPORT_ERR_BUILDER;
    } else {
        uintptr_t last = (uintptr_t)builder->last;
        if (builder->last == NULL || builder->first_phys == 0
            || (builder->first_phys & 7u) != 0
            || builder->first_phys < builder->arena_phys
            || builder->first_phys - builder->arena_phys >= builder->used
            || last < arena_address || (last & 7u) != 0
            || (size_t)(last - arena_address) > builder->used
            || sizeof(struct bbp_tag_header) > builder->used
                 - (size_t)(last - arena_address)
            || builder->last->next_tag != 0)
            return BBP_IMPORT_ERR_BUILDER;
    }
    plan->used = builder->used;
    plan->tag_count = builder->tag_count;
    return BBP_IMPORT_OK;
}

static bbp_import_status plan_allocation(const struct bbp_builder *builder,
                                         struct bbp_import_plan *plan,
                                         size_t bytes)
{
    size_t start;
    size_t end;
    if (!align8(plan->used, &start) || !add_size(start, bytes, &end))
        return BBP_IMPORT_ERR_OVERFLOW;
    if (end > builder->capacity || end > BBP_IMPORT_MAX_ARENA)
        return BBP_IMPORT_ERR_CAPACITY;
    if ((uint64_t)end > BBP_IMPORT_U64_MAX - builder->arena_phys)
        return BBP_IMPORT_ERR_OVERFLOW;
    plan->used = end;
    return BBP_IMPORT_OK;
}

bbp_import_status bbp_import_plan_tag(const struct bbp_builder *builder,
                                      struct bbp_import_plan *plan, size_t bytes)
{
    bbp_import_status status;
    if (bytes < sizeof(struct bbp_tag_header)
        || bytes > BBP_IMPORT_MAX_TAG_SIZE || bytes > BBP_IMPORT_U32_MAX)
        return BBP_IMPORT_ERR_COUNT;
    if (plan->tag_count >= BBP_IMPORT_MAX_TAGS)
        return BBP_IMPORT_ERR_COUNT;
    status = plan_allocation(builder, plan, bytes);
    if (status == BBP_IMPORT_OK)
        plan->tag_count++;
    return status;
}

bbp_import_status bbp_import_plan_blob(const struct bbp_builder *builder,
                                       struct bbp_import_plan *plan, size_t bytes)
{
    if (bytes == 0)
        return BBP_IMPORT_ERR_RANGE;
    return plan_allocation(builder, plan, bytes);
}

bbp_import_status bbp_import_array_tag_size(size_t fixed, uint64_t count,
                                            size_t element, size_t *out)
{
    size_t payload;
    if (out == NULL)
        return BBP_IMPORT_ERR_NULL;
    if (count > BBP_IMPORT_U32_MAX || element == 0)
        return BBP_IMPORT_ERR_COUNT;
    if (count > (uint64_t)BBP_IMPORT_SIZE_MAX)
        return BBP_IMPORT_ERR_COUNT;
    if ((size_t)count > (BBP_IMPORT_SIZE_MAX - fixed) / element)
        return BBP_IMPORT_ERR_OVERFLOW;
    payload = (size_t)count * element;
    *out = fixed + payload;
    if (*out > BBP_IMPORT_MAX_TAG_SIZE || *out > BBP_IMPORT_U32_MAX)
        return BBP_IMPORT_ERR_COUNT;
    return BBP_IMPORT_OK;
}

static int utf8_cont(uint8_t byte)
{
    return (byte & 0xc0u) == 0x80u;
}

static size_t utf8_sequence(const uint8_t *text, size_t remaining)
{
    uint8_t a;
    if (remaining == 0)
        return 0;
    a = text[0];
    if (a < 0x80u)
        return a == 0 ? 0 : 1;
    if (a >= 0xc2u && a <= 0xdfu && remaining >= 2 && utf8_cont(text[1]))
        return 2;
    if (a == 0xe0u && remaining >= 3 && text[1] >= 0xa0u
        && text[1] <= 0xbfu && utf8_cont(text[2]))
        return 3;
    if (((a >= 0xe1u && a <= 0xecu) || (a >= 0xeeu && a <= 0xefu))
        && remaining >= 3 && utf8_cont(text[1]) && utf8_cont(text[2]))
        return 3;
    if (a == 0xedu && remaining >= 3 && text[1] >= 0x80u
        && text[1] <= 0x9fu && utf8_cont(text[2]))
        return 3;
    if (a == 0xf0u && remaining >= 4 && text[1] >= 0x90u
        && text[1] <= 0xbfu && utf8_cont(text[2]) && utf8_cont(text[3]))
        return 4;
    if (a >= 0xf1u && a <= 0xf3u && remaining >= 4
        && utf8_cont(text[1]) && utf8_cont(text[2]) && utf8_cont(text[3]))
        return 4;
    if (a == 0xf4u && remaining >= 4 && text[1] >= 0x80u
        && text[1] <= 0x8fu && utf8_cont(text[2]) && utf8_cont(text[3]))
        return 4;
    return 0;
}

bbp_import_status bbp_import_validate_string(struct bbp_import_string string)
{
    size_t offset = 0;
    size_t content;
    if (string.data == NULL || string.bytes == 0)
        return BBP_IMPORT_ERR_STRING;
    if (string.bytes > BBP_IMPORT_U32_MAX)
        return BBP_IMPORT_ERR_COUNT;
    if (string.data[string.bytes - 1u] != 0)
        return BBP_IMPORT_ERR_STRING;
    content = string.bytes - 1u;
    while (offset < content) {
        size_t sequence = utf8_sequence(string.data + offset, content - offset);
        if (sequence == 0)
            return BBP_IMPORT_ERR_STRING;
        offset += sequence;
    }
    return BBP_IMPORT_OK;
}

size_t bbp_import_utf8_prefix(const uint8_t *text, size_t bytes, size_t limit)
{
    size_t offset = 0;
    while (offset < bytes) {
        size_t sequence = utf8_sequence(text + offset, bytes - offset);
        if (sequence == 0 || sequence > limit - offset)
            break;
        offset += sequence;
    }
    return offset;
}

bbp_import_status bbp_import_validate_framebuffer(
    const struct bbp_import_framebuffer *framebuffer)
{
    uint32_t bytes_per_pixel;
    uint64_t row_bytes;
    uint64_t required;
    if (framebuffer == NULL)
        return BBP_IMPORT_ERR_NULL;
    switch (framebuffer->pixel_format) {
    case BBP_FB_RGB888:
        bytes_per_pixel = 3;
        if (framebuffer->color_depth != 8) return BBP_IMPORT_ERR_UNSUPPORTED;
        break;
    case BBP_FB_RGBA8888:
    case BBP_FB_BGRA8888:
        bytes_per_pixel = 4;
        if (framebuffer->color_depth != 8) return BBP_IMPORT_ERR_UNSUPPORTED;
        break;
    case BBP_FB_RGB565:
        bytes_per_pixel = 2;
        if (framebuffer->color_depth != 5) return BBP_IMPORT_ERR_UNSUPPORTED;
        break;
    case BBP_FB_RGBA1010102:
        bytes_per_pixel = 4;
        if (framebuffer->color_depth != 10) return BBP_IMPORT_ERR_UNSUPPORTED;
        break;
    case BBP_FB_RGBX_FP16:
        bytes_per_pixel = 8;
        if (framebuffer->color_depth != 16) return BBP_IMPORT_ERR_UNSUPPORTED;
        break;
    default:
        return BBP_IMPORT_ERR_UNSUPPORTED;
    }
    if (framebuffer->width == 0 || framebuffer->width > BBP_IMPORT_U16_MAX
        || framebuffer->height == 0
        || framebuffer->height > BBP_IMPORT_U16_MAX)
        return BBP_IMPORT_ERR_RANGE;
    row_bytes = (uint64_t)framebuffer->width * bytes_per_pixel;
    if (framebuffer->pitch < row_bytes)
        return BBP_IMPORT_ERR_RANGE;
    required = (uint64_t)framebuffer->pitch * framebuffer->height;
    if (framebuffer->total_size < required
        || !bbp_import_phys_range_valid(framebuffer->address,
                                        framebuffer->total_size))
        return BBP_IMPORT_ERR_RANGE;
    if ((framebuffer->flags & ~(BBP_FB_FLAG_DOUBLE_BUFFERED
          | BBP_FB_FLAG_ROTATED_90 | BBP_FB_FLAG_ROTATED_180
          | BBP_FB_FLAG_ROTATED_270)) != 0)
        return BBP_IMPORT_ERR_FLAGS;
    {
        uint16_t rotation = framebuffer->flags
            & (BBP_FB_FLAG_ROTATED_90 | BBP_FB_FLAG_ROTATED_180
               | BBP_FB_FLAG_ROTATED_270);
        if (rotation != 0 && (rotation & (uint16_t)(rotation - 1u)) != 0)
            return BBP_IMPORT_ERR_FLAGS;
    }
    return BBP_IMPORT_OK;
}

const char *bbp_import_strstatus(bbp_import_status status)
{
    switch (status) {
    case BBP_IMPORT_OK:              return "ok";
    case BBP_IMPORT_ERR_NULL:        return "null input";
    case BBP_IMPORT_ERR_FLAGS:       return "invalid presence or option flags";
    case BBP_IMPORT_ERR_BUILDER:     return "invalid builder state";
    case BBP_IMPORT_ERR_CAPACITY:    return "insufficient builder arena";
    case BBP_IMPORT_ERR_COUNT:       return "count or object exceeds protocol limit";
    case BBP_IMPORT_ERR_OVERFLOW:    return "integer overflow";
    case BBP_IMPORT_ERR_RANGE:       return "invalid address or range";
    case BBP_IMPORT_ERR_FRAMING:     return "malformed source framing";
    case BBP_IMPORT_ERR_DUPLICATE:   return "duplicate singleton or identifier";
    case BBP_IMPORT_ERR_STRING:      return "unterminated or invalid UTF-8 string";
    case BBP_IMPORT_ERR_UNSUPPORTED: return "unsupported source value";
    case BBP_IMPORT_ERR_NON_FINAL:   return "UEFI memory map is not final";
    default:                         return "unknown importer status";
    }
}
