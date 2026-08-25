/*
 * Firmware-independent BBP v1.1 SECURITY measurement collection.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_SECURITY_COLLECTOR_H
#define BBP_SECURITY_COLLECTOR_H

#include <bbp/bbp.h>

struct bbp_builder;

#define BBP_SECURITY_MAX_MEASUREMENTS 32u
#define BBP_SECURITY_SHA256_BYTES     32u
#define BBP_SECURITY_MAX_INPUT_BYTES  (64u * 1024u * 1024u)
#define BBP_SECURITY_MAX_PCR          23u
#define BBP_SECURITY_TAG_VERSION      1u

typedef enum {
    BBP_SECURITY_OK = 0,
    BBP_SECURITY_ERR_ARGUMENT,
    BBP_SECURITY_ERR_COUNT,
    BBP_SECURITY_ERR_PCR,
    BBP_SECURITY_ERR_ALGORITHM,
    BBP_SECURITY_ERR_HASH_LENGTH,
    BBP_SECURITY_ERR_NAME,
    BBP_SECURITY_ERR_RANGE,
    BBP_SECURITY_ERR_BUILDER,
    BBP_SECURITY_ERR_CAPACITY,
    BBP_SECURITY_ERR_TPM,
    BBP_SECURITY_ERR_PUBLISH_AFTER_TPM,
    BBP_SECURITY_ERR_ABORT_RETURNED
} bbp_security_status;

struct bbp_security_source {
    uint32_t pcr_index;
    uint32_t algorithm;
    uint32_t hash_length; /* expected digest size; SHA-256 requires 32 */
    uint32_t reserved;
    const void *data;
    size_t data_length;
    const uint8_t *component_name;
    size_t component_name_length; /* 1..63 bytes, excluding the NUL */
};

struct bbp_security_platform {
    bbp_phys_t tpm_base_address;
    uint16_t tpm_version;
    uint16_t tpm_interface;
    uint32_t tpm_flags;
    struct bbp_secure_boot_info secure_boot;
};

typedef int (*bbp_security_hash_extend_fn)(
    void *context, uint32_t pcr_index, uint32_t algorithm,
    const void *data, size_t data_length,
    uint8_t digest[BBP_SECURITY_SHA256_BYTES]);

typedef enum {
    BBP_SECURITY_ARENA_MEASUREMENTS = 1,
    BBP_SECURITY_ARENA_TAG = 2
} bbp_security_arena_object;

/* The allocator must use the supplied builder. For MEASUREMENTS it copies
 * `source`; for TAG it allocates a BBP_TAG_SECURITY tag and ignores `source`.
 * It returns the writable virtual address and matching physical address. */
typedef void *(*bbp_security_arena_allocate_fn)(
    void *context, struct bbp_builder *builder,
    bbp_security_arena_object object, const void *source, size_t bytes,
    bbp_phys_t *out_phys);

/* Called after an irreversible TPM success if a later operation prevents a
 * complete local record. Firmware integrations must not return from it. */
typedef void (*bbp_security_abort_fn)(void *context,
                                      bbp_security_status reason);

struct bbp_security_callbacks {
    void *context;
    bbp_security_hash_extend_fn hash_extend;
    bbp_security_arena_allocate_fn arena_allocate;
    bbp_security_abort_fn abort;
};

/* Adapter for the real bbp_builder arena API. `context` is unused. */
void *bbp_security_builder_allocate(
    void *context, struct bbp_builder *builder,
    bbp_security_arena_object object, const void *source, size_t bytes,
    bbp_phys_t *out_phys);

bbp_security_status bbp_security_collect(
    struct bbp_builder *builder,
    const struct bbp_security_platform *platform,
    const struct bbp_security_source *sources,
    uint32_t measurement_count,
    const struct bbp_security_callbacks *callbacks,
    struct bbp_tag_security **out_tag);

const char *bbp_security_strstatus(bbp_security_status status);

#endif /* BBP_SECURITY_COLLECTOR_H */
