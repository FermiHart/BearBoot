/*
 * Firmware-independent BBP v1.1 SECURITY measurement collection.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbp_security_collector.h"

#include "../../../bootloader/bbp_build.h"
#include <bbp/bbp_crc64.h>

#define BBP_SECURITY_MAX_PHYS       (1ULL << 48)
#define BBP_SECURITY_MAX_TAGS       1024u
#define BBP_SECURITY_MAX_ARENA      (64u * 1024u * 1024u - sizeof(struct bbp_info))
#define BBP_SECURITY_ROLLBACK_BYTES \
    (BBP_SECURITY_MAX_MEASUREMENTS * sizeof(struct bbp_measurement) + \
     sizeof(struct bbp_tag_security) + 14u)

struct bbp_security_plan {
    size_t blob_start;
    size_t blob_end;
    size_t tag_start;
    size_t tag_end;
    size_t log_bytes;
};

static void security_memzero(void *destination, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    while (bytes-- != 0u)
        *d++ = 0;
}

static void security_memcpy(void *destination, const void *source, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    const uint8_t *s = (const uint8_t *)source;
    while (bytes-- != 0u)
        *d++ = *s++;
}

static int security_memequal(const void *left, const void *right, size_t bytes)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    while (bytes-- != 0u) {
        if (*a++ != *b++)
            return 0;
    }
    return 1;
}

static int align8(size_t value, size_t *out)
{
    if (value > (size_t)-1 - 7u)
        return 0;
    *out = (value + 7u) & ~(size_t)7u;
    return 1;
}

static int pointer_span_valid(const void *pointer, size_t bytes)
{
    uintptr_t address = (uintptr_t)pointer;
    return pointer != NULL && bytes != 0u && bytes <= UINTPTR_MAX - address;
}

static int spans_overlap(const void *left, size_t left_bytes,
                         const void *right, size_t right_bytes)
{
    uintptr_t a = (uintptr_t)left;
    uintptr_t b = (uintptr_t)right;
    if (!pointer_span_valid(left, left_bytes) ||
        !pointer_span_valid(right, right_bytes))
        return 1;
    return a < b + right_bytes && b < a + left_bytes;
}

static bbp_security_status validate_builder(
    const struct bbp_builder *builder, uint32_t measurement_count,
    struct bbp_security_plan *plan)
{
    uintptr_t arena_address;
    size_t end;

    if (builder == NULL || plan == NULL)
        return BBP_SECURITY_ERR_ARGUMENT;
    arena_address = (uintptr_t)builder->arena;
    if (builder->arena == NULL || builder->overflow != 0 ||
        builder->used > builder->capacity ||
        builder->used > BBP_SECURITY_MAX_ARENA ||
        builder->tag_count > BBP_SECURITY_MAX_TAGS ||
        builder->arena_phys == 0 || (builder->arena_phys & 7u) != 0u ||
        (arena_address & 7u) != 0u ||
        builder->capacity > UINTPTR_MAX - arena_address ||
        builder->arena_phys >= BBP_SECURITY_MAX_PHYS ||
        builder->capacity > BBP_SECURITY_MAX_PHYS - builder->arena_phys)
        return BBP_SECURITY_ERR_BUILDER;

    if (builder->tag_count == 0u) {
        if (builder->last != NULL || builder->first_phys != 0u)
            return BBP_SECURITY_ERR_BUILDER;
    } else {
        uintptr_t last = (uintptr_t)builder->last;
        if (builder->last == NULL || builder->first_phys == 0u ||
            (builder->first_phys & 7u) != 0u ||
            builder->first_phys < builder->arena_phys ||
            builder->first_phys - builder->arena_phys >= builder->used ||
            last < arena_address || (last & 7u) != 0u ||
            (size_t)(last - arena_address) > builder->used ||
            sizeof(struct bbp_tag_header) >
                builder->used - (size_t)(last - arena_address) ||
            builder->last->next_tag != 0u)
            return BBP_SECURITY_ERR_BUILDER;
    }
    if (builder->tag_count >= BBP_SECURITY_MAX_TAGS)
        return BBP_SECURITY_ERR_CAPACITY;

    plan->log_bytes = (size_t)measurement_count *
                      sizeof(struct bbp_measurement);
    if (!align8(builder->used, &plan->blob_start) ||
        plan->log_bytes > (size_t)-1 - plan->blob_start)
        return BBP_SECURITY_ERR_RANGE;
    plan->blob_end = plan->blob_start + plan->log_bytes;
    if (!align8(plan->blob_end, &plan->tag_start) ||
        sizeof(struct bbp_tag_security) > (size_t)-1 - plan->tag_start)
        return BBP_SECURITY_ERR_RANGE;
    end = plan->tag_start + sizeof(struct bbp_tag_security);
    plan->tag_end = end;
    if (end > builder->capacity || end > BBP_SECURITY_MAX_ARENA)
        return BBP_SECURITY_ERR_CAPACITY;
    if ((bbp_phys_t)end > BBP_SECURITY_MAX_PHYS - builder->arena_phys)
        return BBP_SECURITY_ERR_RANGE;
    if (end - plan->blob_start > BBP_SECURITY_ROLLBACK_BYTES)
        return BBP_SECURITY_ERR_RANGE;

    return BBP_SECURITY_OK;
}

static bbp_security_status validate_platform(
    const struct bbp_security_platform *platform)
{
    const struct bbp_secure_boot_info *secure;
    uint32_t known_flags = BBP_TPM_FLAG_ACTIVE |
                           BBP_TPM_FLAG_SUPPORTS_SHA384 |
                           BBP_TPM_FLAG_SUPPORTS_SHA512;
    if (platform == NULL)
        return BBP_SECURITY_ERR_ARGUMENT;
    secure = &platform->secure_boot;
    if (platform->tpm_version != 0x0200u || platform->tpm_interface > 3u ||
        (platform->tpm_flags & BBP_TPM_FLAG_ACTIVE) == 0u ||
        (platform->tpm_flags & ~known_flags) != 0u ||
        platform->tpm_base_address >= BBP_SECURITY_MAX_PHYS)
        return BBP_SECURITY_ERR_RANGE;
    if (secure->mode > 2u || secure->signature_verified > 1u ||
        secure->pk_present > 1u || secure->kek_present > 1u ||
        secure->db_present > 1u || secure->dbx_present > 1u ||
        secure->reserved != 0u)
        return BBP_SECURITY_ERR_RANGE;
    return BBP_SECURITY_OK;
}

static bbp_security_status validate_sources(
    const struct bbp_security_source *sources, uint32_t measurement_count)
{
    uint32_t i;
    if (measurement_count == 0u ||
        measurement_count > BBP_SECURITY_MAX_MEASUREMENTS)
        return BBP_SECURITY_ERR_COUNT;
    if (!pointer_span_valid(sources, (size_t)measurement_count *
                            sizeof(*sources)))
        return BBP_SECURITY_ERR_ARGUMENT;

    for (i = 0u; i < measurement_count; i++) {
        const struct bbp_security_source *source = &sources[i];
        size_t name_index;
        if (source->reserved != 0u)
            return BBP_SECURITY_ERR_RANGE;
        if (source->pcr_index > BBP_SECURITY_MAX_PCR)
            return BBP_SECURITY_ERR_PCR;
        if (source->algorithm != BBP_HASH_SHA256)
            return BBP_SECURITY_ERR_ALGORITHM;
        if (source->hash_length != BBP_SECURITY_SHA256_BYTES)
            return BBP_SECURITY_ERR_HASH_LENGTH;
        if (source->data_length == 0u ||
            source->data_length > BBP_SECURITY_MAX_INPUT_BYTES ||
            !pointer_span_valid(source->data, source->data_length))
            return BBP_SECURITY_ERR_RANGE;
        if (source->component_name_length == 0u ||
            source->component_name_length >=
                sizeof(((struct bbp_measurement *)0)->component_name) ||
            !pointer_span_valid(source->component_name,
                                source->component_name_length))
            return BBP_SECURITY_ERR_NAME;
        for (name_index = 0u;
             name_index < source->component_name_length; name_index++) {
            if (source->component_name[name_index] == 0u)
                return BBP_SECURITY_ERR_NAME;
        }
    }
    return BBP_SECURITY_OK;
}

static void rollback_publish(struct bbp_builder *builder,
                             const struct bbp_builder *before,
                             size_t backup_start, const uint8_t *backup,
                             size_t backup_bytes, bbp_phys_t old_last_next)
{
    security_memcpy(builder->arena + backup_start, backup, backup_bytes);
    if (before->last != NULL)
        before->last->next_tag = old_last_next;
    *builder = *before;
}

static bbp_security_status abort_after_tpm(
    const struct bbp_security_callbacks *callbacks,
    bbp_security_status reason)
{
    callbacks->abort(callbacks->context, reason);
    return BBP_SECURITY_ERR_ABORT_RETURNED;
}

void *bbp_security_builder_allocate(
    void *context, struct bbp_builder *builder,
    bbp_security_arena_object object, const void *source, size_t bytes,
    bbp_phys_t *out_phys)
{
    void *result;
    bbp_phys_t phys;
    (void)context;
    if (builder == NULL || out_phys == NULL)
        return NULL;
    *out_phys = 0u;
    if (object == BBP_SECURITY_ARENA_MEASUREMENTS) {
        phys = bbp_arena_blob(builder, source, bytes);
        if (phys == 0u)
            return NULL;
        result = builder->arena + (size_t)(phys - builder->arena_phys);
    } else if (object == BBP_SECURITY_ARENA_TAG) {
        if (source != NULL || bytes != sizeof(struct bbp_tag_security))
            return NULL;
        result = bbp_alloc_tag(builder, BBP_TAG_SECURITY,
                               BBP_SECURITY_TAG_VERSION, bytes);
        if (result == NULL)
            return NULL;
        phys = builder->arena_phys +
               (bbp_phys_t)((uint8_t *)result - builder->arena);
    } else {
        return NULL;
    }
    *out_phys = phys;
    return result;
}

bbp_security_status bbp_security_collect(
    struct bbp_builder *builder,
    const struct bbp_security_platform *platform,
    const struct bbp_security_source *sources,
    uint32_t measurement_count,
    const struct bbp_security_callbacks *callbacks,
    struct bbp_tag_security **out_tag)
{
    struct bbp_measurement records[BBP_SECURITY_MAX_MEASUREMENTS];
    uint8_t rollback[BBP_SECURITY_ROLLBACK_BYTES];
    struct bbp_security_callbacks operations;
    struct bbp_security_platform platform_copy;
    struct bbp_security_plan plan;
    struct bbp_builder before;
    struct bbp_tag_security *tag;
    void *blob;
    bbp_phys_t blob_phys = 0u;
    bbp_phys_t tag_phys = 0u;
    bbp_phys_t old_last_next = 0u;
    uint64_t log_crc;
    size_t rollback_bytes;
    uint32_t i;
    bbp_security_status status;

    if (callbacks == NULL || callbacks->hash_extend == NULL ||
        callbacks->arena_allocate == NULL || callbacks->abort == NULL ||
        out_tag == NULL)
        return BBP_SECURITY_ERR_ARGUMENT;
    status = validate_sources(sources, measurement_count);
    if (status != BBP_SECURITY_OK)
        return status;
    status = validate_platform(platform);
    if (status != BBP_SECURITY_OK)
        return status;
    status = validate_builder(builder, measurement_count, &plan);
    if (status != BBP_SECURITY_OK)
        return status;
    if (spans_overlap(out_tag, sizeof(*out_tag), builder->arena,
                      builder->capacity))
        return BBP_SECURITY_ERR_RANGE;

    operations = *callbacks;
    platform_copy = *platform;
    before = *builder;
    if (before.last != NULL)
        old_last_next = before.last->next_tag;
    rollback_bytes = plan.tag_end - plan.blob_start;
    security_memcpy(rollback, builder->arena + plan.blob_start,
                    rollback_bytes);
    security_memzero(records, sizeof(records));

    for (i = 0u; i < measurement_count; i++) {
        records[i].pcr_index = sources[i].pcr_index;
        records[i].algorithm = BBP_HASH_SHA256;
        records[i].hash_length = BBP_SECURITY_SHA256_BYTES;
        security_memcpy(records[i].component_name,
                        sources[i].component_name,
                        sources[i].component_name_length);
        if (operations.hash_extend(operations.context,
                sources[i].pcr_index, BBP_HASH_SHA256, sources[i].data,
                sources[i].data_length, records[i].hash) != 0) {
            if (i != 0u)
                return abort_after_tpm(&operations,
                    BBP_SECURITY_ERR_PUBLISH_AFTER_TPM);
            return BBP_SECURITY_ERR_TPM;
        }
    }
    log_crc = bbp_crc64(records, plan.log_bytes);
    if (log_crc == 0u)
        return abort_after_tpm(&operations,
                               BBP_SECURITY_ERR_PUBLISH_AFTER_TPM);

    blob = operations.arena_allocate(operations.context, builder,
        BBP_SECURITY_ARENA_MEASUREMENTS, records, plan.log_bytes, &blob_phys);
    if (blob == NULL || blob != builder->arena + plan.blob_start ||
        blob_phys != builder->arena_phys + (bbp_phys_t)plan.blob_start ||
        builder->used != plan.blob_end ||
        builder->tag_count != before.tag_count ||
        builder->last != before.last ||
        builder->first_phys != before.first_phys || builder->overflow != 0 ||
        !security_memequal(blob, records, plan.log_bytes)) {
        rollback_publish(builder, &before, plan.blob_start, rollback,
                         rollback_bytes, old_last_next);
        return abort_after_tpm(&operations,
                               BBP_SECURITY_ERR_PUBLISH_AFTER_TPM);
    }

    tag = (struct bbp_tag_security *)operations.arena_allocate(
        operations.context, builder, BBP_SECURITY_ARENA_TAG, NULL,
        sizeof(*tag), &tag_phys);
    if (tag == NULL || (void *)tag != builder->arena + plan.tag_start ||
        tag_phys != builder->arena_phys + (bbp_phys_t)plan.tag_start ||
        builder->used != plan.tag_end ||
        builder->tag_count != before.tag_count + 1u ||
        builder->last != &tag->header || builder->overflow != 0 ||
        tag->header.tag_id != BBP_TAG_SECURITY ||
        tag->header.tag_size != sizeof(*tag) ||
        tag->header.tag_version != BBP_SECURITY_TAG_VERSION ||
        tag->header.next_tag != 0u ||
        (before.tag_count == 0u && builder->first_phys != tag_phys) ||
        (before.tag_count != 0u &&
         (builder->first_phys != before.first_phys ||
          before.last->next_tag != tag_phys))) {
        rollback_publish(builder, &before, plan.blob_start, rollback,
                         rollback_bytes, old_last_next);
        return abort_after_tpm(&operations,
                               BBP_SECURITY_ERR_PUBLISH_AFTER_TPM);
    }

    tag->tpm_base_address = platform_copy.tpm_base_address;
    tag->tpm_version = platform_copy.tpm_version;
    tag->tpm_interface = platform_copy.tpm_interface;
    tag->tpm_flags = platform_copy.tpm_flags;
    tag->secure_boot = platform_copy.secure_boot;
    tag->measurement_count = measurement_count;
    tag->measurements = blob_phys;
    tag->measurements_crc = log_crc;
    bbp_seal_tag(builder, tag);
    *out_tag = tag;
    return BBP_SECURITY_OK;
}

const char *bbp_security_strstatus(bbp_security_status status)
{
    switch (status) {
    case BBP_SECURITY_OK:                    return "ok";
    case BBP_SECURITY_ERR_ARGUMENT:          return "invalid argument";
    case BBP_SECURITY_ERR_COUNT:             return "invalid measurement count";
    case BBP_SECURITY_ERR_PCR:               return "invalid PCR index";
    case BBP_SECURITY_ERR_ALGORITHM:         return "unsupported hash algorithm";
    case BBP_SECURITY_ERR_HASH_LENGTH:       return "invalid hash length";
    case BBP_SECURITY_ERR_NAME:              return "invalid component name";
    case BBP_SECURITY_ERR_RANGE:             return "invalid input range";
    case BBP_SECURITY_ERR_BUILDER:           return "invalid builder state";
    case BBP_SECURITY_ERR_CAPACITY:          return "insufficient builder arena";
    case BBP_SECURITY_ERR_TPM:               return "TPM hash/extend failed";
    case BBP_SECURITY_ERR_PUBLISH_AFTER_TPM: return "publish failed after TPM success";
    case BBP_SECURITY_ERR_ABORT_RETURNED:    return "terminal abort hook returned";
    default:                                 return "unknown";
    }
}
