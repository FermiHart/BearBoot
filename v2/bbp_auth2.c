/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_auth2.h>

#include "bbp_auth2_crypto.h"

static const uint8_t manifest_magic[8] = {
    'B', 'B', 'P', '2', 'K', 'E', 'Y', 0
};
static const uint8_t envelope_magic[8] = {
    'B', 'B', 'P', '2', 'S', 'I', 'G', 0
};
static const uint8_t spki_p256_prefix[26] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};
static const uint8_t p256_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const uint8_t p256_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
};
static const uint8_t zero_signature[BBP_AUTH2_SIGNATURE_SIZE] = {0};

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
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

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    uint8_t difference = 0;
    while (size--) difference |= *a++ ^ *b++;
    return difference == 0;
}

static int bytes_zero(const uint8_t *data, size_t size)
{
    uint8_t value = 0;
    while (size--) value |= *data++;
    return value == 0;
}

static int range_overlap(const void *a_pointer, size_t a_size,
                         const void *b_pointer, size_t b_size)
{
    uintptr_t a = (uintptr_t)a_pointer;
    uintptr_t b = (uintptr_t)b_pointer;
    if (a_size > (uintptr_t)-1 - a || b_size > (uintptr_t)-1 - b) return 1;
    return a < b + b_size && b < a + a_size;
}

static int compare_big_endian(const uint8_t *a, const uint8_t *b, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static int valid_signature_encoding(const uint8_t signature[64])
{
    const uint8_t *r = signature;
    const uint8_t *s = signature + 32;
    return !bytes_zero(r, 32) && !bytes_zero(s, 32) &&
           compare_big_endian(r, p256_order, 32) < 0 &&
           compare_big_endian(s, p256_order, 32) < 0 &&
           compare_big_endian(s, p256_half_order, 32) <= 0;
}

static void signed_extent_digest(const uint8_t *data, size_t size,
                                 uint8_t digest[32])
{
    struct bbp_auth2_hash_part parts[3];
    parts[0].data = data;
    parts[0].size = 72;
    parts[1].data = zero_signature;
    parts[1].size = sizeof(zero_signature);
    parts[2].data = data + 136;
    parts[2].size = size - 136;
    bbp_auth2_sha256_parts(parts, 3, digest);
}

static int make_key_id(const uint8_t point[65], uint8_t key_id[32])
{
    struct bbp_auth2_hash_part parts[2];
    uint8_t digest[32];
    if (!bbp_auth2_p256_point_valid(point)) return 0;
    parts[0].data = spki_p256_prefix;
    parts[0].size = sizeof(spki_p256_prefix);
    parts[1].data = point;
    parts[1].size = 65;
    bbp_auth2_sha256_parts(parts, 2, digest);
    key_id[0] = BBP_AUTH2_ALGORITHM_ECDSA_P256_SHA256;
    key_id[1] = 0;
    bbp_auth2_memcpy(key_id + 2, digest, 30);
    return 1;
}

static bbp_auth2_status_t validate_manifest_entries(const uint8_t *manifest,
                                                     uint32_t key_count)
{
    uint32_t i, j;
    for (i = 0; i < key_count; i++) {
        const uint8_t *entry = manifest + BBP_AUTH2_MANIFEST_HEADER_SIZE +
                               (size_t)i * BBP_AUTH2_MANIFEST_ENTRY_SIZE;
        uint8_t expected_id[BBP_AUTH2_KEY_ID_SIZE];
        uint16_t role = get16(entry + 34);
        uint32_t flags = get32(entry + 36);
        uint64_t activation = get64(entry + 40);
        uint64_t retirement = get64(entry + 48);
        if (get16(entry + 32) != BBP_AUTH2_ALGORITHM_ECDSA_P256_SHA256)
            return BBP_AUTH2_ERR_ALGORITHM;
        if ((role != BBP_AUTH2_ROLE_RELEASE &&
             role != BBP_AUTH2_ROLE_RECOVERY) ||
            (flags & ~1u) != 0 || activation == 0 || retirement == 0 ||
            activation > retirement || !bytes_zero(entry + 121, 7))
            return BBP_AUTH2_ERR_FORMAT;
        if (!make_key_id(entry + 56, expected_id) ||
            !bytes_equal(entry, expected_id, sizeof(expected_id)))
            return BBP_AUTH2_ERR_KEY;
        for (j = 0; j < i; j++) {
            const uint8_t *prior = manifest +
                BBP_AUTH2_MANIFEST_HEADER_SIZE +
                (size_t)j * BBP_AUTH2_MANIFEST_ENTRY_SIZE;
            if (bytes_equal(entry, prior, BBP_AUTH2_KEY_ID_SIZE))
                return BBP_AUTH2_ERR_KEY;
        }
    }
    return BBP_AUTH2_OK;
}

bbp_auth2_status_t bbp_auth2_verify_manifest(
    const void *manifest_pointer, size_t manifest_size,
    const void *root_public_key_pointer, size_t root_public_key_size,
    uint64_t minimum_generation,
    struct bbp_auth2_manifest_view *out)
{
    const uint8_t *manifest = (const uint8_t *)manifest_pointer;
    const uint8_t *root_public_key =
        (const uint8_t *)root_public_key_pointer;
    struct bbp_auth2_manifest_view candidate;
    uint8_t root_key_id[BBP_AUTH2_KEY_ID_SIZE], digest[32];
    uint32_t key_count;
    uint64_t generation;
    size_t expected_size;
    bbp_auth2_status_t status;

    if (!manifest || !root_public_key || !out) return BBP_AUTH2_ERR_NULL;
    if (range_overlap(out, sizeof(*out), manifest, manifest_size) ||
        range_overlap(out, sizeof(*out), root_public_key,
                      root_public_key_size))
        return BBP_AUTH2_ERR_ALIAS;
    if (manifest_size < BBP_AUTH2_MANIFEST_HEADER_SIZE)
        return BBP_AUTH2_ERR_EXTENT;
    if (!bytes_equal(manifest, manifest_magic, sizeof(manifest_magic)) ||
        get16(manifest + 8) != 1 ||
        get16(manifest + 10) != BBP_AUTH2_MANIFEST_HEADER_SIZE ||
        get16(manifest + 14) != BBP_AUTH2_MANIFEST_ENTRY_SIZE ||
        get32(manifest + 16) != 0)
        return BBP_AUTH2_ERR_FORMAT;
    if (get16(manifest + 12) != BBP_AUTH2_ALGORITHM_ECDSA_P256_SHA256)
        return BBP_AUTH2_ERR_ALGORITHM;
    key_count = get32(manifest + 20);
    if (key_count == 0 || key_count > BBP_AUTH2_MAX_KEYS)
        return BBP_AUTH2_ERR_EXTENT;
    expected_size = BBP_AUTH2_MANIFEST_HEADER_SIZE +
        (size_t)key_count * BBP_AUTH2_MANIFEST_ENTRY_SIZE;
    if (get64(manifest + 32) != expected_size || manifest_size != expected_size)
        return BBP_AUTH2_ERR_EXTENT;
    generation = get64(manifest + 24);
    if (generation == 0) return BBP_AUTH2_ERR_GENERATION;
    if (root_public_key_size != BBP_AUTH2_PUBLIC_KEY_SIZE ||
        !make_key_id(root_public_key, root_key_id) ||
        !bytes_equal(root_key_id, manifest + 40, sizeof(root_key_id)))
        return BBP_AUTH2_ERR_KEY;
    if (!valid_signature_encoding(manifest + 72))
        return BBP_AUTH2_ERR_SIGNATURE;
    signed_extent_digest(manifest, manifest_size, digest);
    if (!bbp_auth2_p256_verify(root_public_key, digest, manifest + 72))
        return BBP_AUTH2_ERR_SIGNATURE;
    if (generation < minimum_generation) return BBP_AUTH2_ERR_GENERATION;
    status = validate_manifest_entries(manifest, key_count);
    if (status != BBP_AUTH2_OK) return status;

    bbp_auth2_memset(&candidate, 0, sizeof(candidate));
    candidate.data = manifest;
    candidate.size = manifest_size;
    candidate.security_generation = generation;
    candidate.key_count = key_count;
    bbp_auth2_memcpy(out, &candidate, sizeof(candidate));
    return BBP_AUTH2_OK;
}

bbp_auth2_status_t bbp_auth2_verify_envelope(
    const void *envelope_pointer, size_t envelope_size,
    const void *manifest_pointer, size_t manifest_size,
    const void *root_public_key_pointer, size_t root_public_key_size,
    uint64_t minimum_generation, uint32_t policy,
    struct bbp_auth2_verified_envelope *out)
{
    const uint8_t *envelope = (const uint8_t *)envelope_pointer;
    const uint8_t *manifest = (const uint8_t *)manifest_pointer;
    const uint8_t *root_public_key =
        (const uint8_t *)root_public_key_pointer;
    struct bbp_auth2_manifest_view manifest_view;
    struct bbp_auth2_verified_envelope candidate;
    const uint8_t *signer = NULL;
    uint8_t digest[32];
    uint64_t generation, payload_size;
    uint16_t role;
    uint32_t i;
    bbp_auth2_status_t status;

    if (!envelope || !manifest || !root_public_key || !out)
        return BBP_AUTH2_ERR_NULL;
    if ((policy & ~BBP_AUTH2_ALLOW_RECOVERY) != 0)
        return BBP_AUTH2_ERR_POLICY;
    if (range_overlap(out, sizeof(*out), envelope, envelope_size) ||
        range_overlap(out, sizeof(*out), manifest, manifest_size) ||
        range_overlap(out, sizeof(*out), root_public_key,
                      root_public_key_size))
        return BBP_AUTH2_ERR_ALIAS;
    if (envelope_size < BBP_AUTH2_ENVELOPE_HEADER_SIZE)
        return BBP_AUTH2_ERR_EXTENT;
    if (!bytes_equal(envelope, envelope_magic, sizeof(envelope_magic)) ||
        get16(envelope + 8) != 1 ||
        get16(envelope + 10) != BBP_AUTH2_ENVELOPE_HEADER_SIZE ||
        get32(envelope + 16) != 0 || get32(envelope + 20) != 0)
        return BBP_AUTH2_ERR_FORMAT;
    if (get16(envelope + 12) != BBP_AUTH2_ALGORITHM_ECDSA_P256_SHA256)
        return BBP_AUTH2_ERR_ALGORITHM;
    role = get16(envelope + 14);
    if (role != BBP_AUTH2_ROLE_RELEASE && role != BBP_AUTH2_ROLE_RECOVERY)
        return BBP_AUTH2_ERR_POLICY;
    generation = get64(envelope + 24);
    if (generation == 0) return BBP_AUTH2_ERR_GENERATION;
    payload_size = get64(envelope + 32);
    if (payload_size > BBP_AUTH2_MAX_PAYLOAD_SIZE ||
        payload_size != envelope_size - BBP_AUTH2_ENVELOPE_HEADER_SIZE)
        return BBP_AUTH2_ERR_EXTENT;
    if (!valid_signature_encoding(envelope + 72))
        return BBP_AUTH2_ERR_SIGNATURE;

    status = bbp_auth2_verify_manifest(
        manifest, manifest_size, root_public_key, root_public_key_size,
        minimum_generation, &manifest_view);
    if (status != BBP_AUTH2_OK) return status;
    if (generation != manifest_view.security_generation)
        return BBP_AUTH2_ERR_GENERATION;
    for (i = 0; i < manifest_view.key_count; i++) {
        const uint8_t *entry = manifest + BBP_AUTH2_MANIFEST_HEADER_SIZE +
                               (size_t)i * BBP_AUTH2_MANIFEST_ENTRY_SIZE;
        if (bytes_equal(entry, envelope + 40, BBP_AUTH2_KEY_ID_SIZE)) {
            signer = entry;
            break;
        }
    }
    if (!signer) return BBP_AUTH2_ERR_KEY;
    if (get16(signer + 34) != role) return BBP_AUTH2_ERR_POLICY;
    if ((get32(signer + 36) & 1u) != 0) return BBP_AUTH2_ERR_POLICY;
    if (generation < get64(signer + 40) ||
        generation > get64(signer + 48))
        return BBP_AUTH2_ERR_GENERATION;
    if (role == BBP_AUTH2_ROLE_RECOVERY &&
        (policy & BBP_AUTH2_ALLOW_RECOVERY) == 0)
        return BBP_AUTH2_ERR_POLICY;
    signed_extent_digest(envelope, envelope_size, digest);
    if (!bbp_auth2_p256_verify(signer + 56, digest, envelope + 72))
        return BBP_AUTH2_ERR_SIGNATURE;

    bbp_auth2_memset(&candidate, 0, sizeof(candidate));
    candidate.payload = envelope + BBP_AUTH2_ENVELOPE_HEADER_SIZE;
    candidate.payload_size = (size_t)payload_size;
    candidate.security_generation = generation;
    bbp_auth2_memcpy(candidate.signer_key_id, envelope + 40,
                     BBP_AUTH2_KEY_ID_SIZE);
    candidate.role = role;
    bbp_auth2_memcpy(out, &candidate, sizeof(candidate));
    return BBP_AUTH2_OK;
}

const char *bbp_auth2_status_string(bbp_auth2_status_t status)
{
    switch (status) {
    case BBP_AUTH2_OK: return "ok";
    case BBP_AUTH2_ERR_NULL: return "null argument";
    case BBP_AUTH2_ERR_FORMAT: return "invalid format";
    case BBP_AUTH2_ERR_EXTENT: return "invalid extent";
    case BBP_AUTH2_ERR_ALGORITHM: return "unsupported algorithm";
    case BBP_AUTH2_ERR_POLICY: return "policy rejected";
    case BBP_AUTH2_ERR_GENERATION: return "generation rejected";
    case BBP_AUTH2_ERR_KEY: return "key rejected";
    case BBP_AUTH2_ERR_SIGNATURE: return "signature rejected";
    case BBP_AUTH2_ERR_ALIAS: return "aliased input and output";
    default: return "unknown status";
    }
}
