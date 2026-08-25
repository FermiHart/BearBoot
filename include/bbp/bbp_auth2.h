/* SPDX-License-Identifier: BSD-3-Clause */
/* Experimental RFC 0004 verifier. Not a frozen or deployed boot ABI. */
#ifndef BBP_AUTH2_H
#define BBP_AUTH2_H

#include <stddef.h>
#include <stdint.h>

#define BBP_AUTH2_ALGORITHM_ECDSA_P256_SHA256 1u
#define BBP_AUTH2_ROLE_RELEASE                 1u
#define BBP_AUTH2_ROLE_RECOVERY                2u

#define BBP_AUTH2_MANIFEST_HEADER_SIZE 136u
#define BBP_AUTH2_MANIFEST_ENTRY_SIZE  128u
#define BBP_AUTH2_ENVELOPE_HEADER_SIZE 136u
#define BBP_AUTH2_PUBLIC_KEY_SIZE       65u
#define BBP_AUTH2_KEY_ID_SIZE           32u
#define BBP_AUTH2_SIGNATURE_SIZE        64u
#define BBP_AUTH2_MAX_KEYS              32u
#define BBP_AUTH2_MAX_PAYLOAD_SIZE      (64u * 1024u * 1024u)

#define BBP_AUTH2_ALLOW_RECOVERY (1u << 0)

typedef enum bbp_auth2_status {
    BBP_AUTH2_OK = 0,
    BBP_AUTH2_ERR_NULL,
    BBP_AUTH2_ERR_FORMAT,
    BBP_AUTH2_ERR_EXTENT,
    BBP_AUTH2_ERR_ALGORITHM,
    BBP_AUTH2_ERR_POLICY,
    BBP_AUTH2_ERR_GENERATION,
    BBP_AUTH2_ERR_KEY,
    BBP_AUTH2_ERR_SIGNATURE,
    BBP_AUTH2_ERR_ALIAS
} bbp_auth2_status_t;

struct bbp_auth2_manifest_view {
    const uint8_t *data;
    size_t size;
    uint64_t security_generation;
    uint32_t key_count;
};

struct bbp_auth2_verified_envelope {
    const uint8_t *payload;
    size_t payload_size;
    uint64_t security_generation;
    uint8_t signer_key_id[BBP_AUTH2_KEY_ID_SIZE];
    uint16_t role;
};

/* Successful results borrow the supplied manifest/envelope storage. All input
 * extents must remain readable and immutable from the start of verification
 * until every returned view is discarded. Callers must snapshot mutable or
 * DMA-visible input into caller-owned protected storage, or otherwise exclude
 * concurrent mutation; const qualification alone does not provide this. */
bbp_auth2_status_t bbp_auth2_verify_manifest(
    const void *manifest, size_t manifest_size,
    const void *root_public_key, size_t root_public_key_size,
    uint64_t minimum_generation,
    struct bbp_auth2_manifest_view *out);

bbp_auth2_status_t bbp_auth2_verify_envelope(
    const void *envelope, size_t envelope_size,
    const void *manifest, size_t manifest_size,
    const void *root_public_key, size_t root_public_key_size,
    uint64_t minimum_generation, uint32_t policy,
    struct bbp_auth2_verified_envelope *out);

const char *bbp_auth2_status_string(bbp_auth2_status_t status);

#endif
