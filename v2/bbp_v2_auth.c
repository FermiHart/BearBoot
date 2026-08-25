/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_v2_auth.h>

static const uint8_t auth_magic[8] = BBP_V2_AUTH_MAGIC_BYTES;

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
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
    while (size--) {
        if (*a++ != *b++) return 0;
    }
    return 1;
}

static void bytes_copy(uint8_t *destination, const uint8_t *source,
                       size_t size)
{
    while (size--) *destination++ = *source++;
}

static void bytes_zero(uint8_t *destination, size_t size)
{
    while (size--) *destination++ = 0;
}

bbp_v2_auth_status_t bbp_v2_auth_parse(
    const void *envelope_pointer, size_t extent,
    bbp_v2_auth_mac_verify_fn verify_mac, void *mac_context,
    bbp_v2_auth_policy_fn policy, void *policy_context,
    struct bbp_v2_auth_view *out)
{
    const uint8_t *envelope = (const uint8_t *)envelope_pointer;
    const uint8_t *capsule;
    uint8_t authenticated_header[BBP_V2_AUTH_HEADER_SIZE];
    struct bbp_v2_auth_view candidate;
    uint64_t capsule_size, rollback_index;
    bbp_v2_status_t capsule_status;

    if (!envelope || !verify_mac || !policy || !out)
        return BBP_V2_AUTH_ERR_NULL;
    if (extent < BBP_V2_AUTH_HEADER_SIZE ||
        extent - BBP_V2_AUTH_HEADER_SIZE > BBP_V2_AUTH_MAX_CAPSULE_SIZE)
        return BBP_V2_AUTH_ERR_EXTENT;
    if (!bytes_equal(envelope, auth_magic, sizeof(auth_magic)))
        return BBP_V2_AUTH_ERR_MAGIC;
    if (get16(envelope + 8) != BBP_V2_AUTH_VERSION)
        return BBP_V2_AUTH_ERR_VERSION;
    if (get16(envelope + 10) != BBP_V2_AUTH_ALG_HMAC_SHA256)
        return BBP_V2_AUTH_ERR_ALGORITHM;
    if (get32(envelope + 12) != 0)
        return BBP_V2_AUTH_ERR_FLAGS;

    capsule_size = get64(envelope + 24);
    if (capsule_size > BBP_V2_AUTH_MAX_CAPSULE_SIZE ||
        capsule_size != (uint64_t)(extent - BBP_V2_AUTH_HEADER_SIZE))
        return BBP_V2_AUTH_ERR_EXTENT;
    capsule = envelope + BBP_V2_AUTH_HEADER_SIZE;
    rollback_index = get64(envelope + 16);

    bytes_copy(authenticated_header, envelope, sizeof(authenticated_header));
    bytes_zero(authenticated_header + BBP_V2_AUTH_TAG_OFFSET,
               BBP_V2_AUTH_TAG_SIZE);
    if (!verify_mac(mac_context, envelope + 32, authenticated_header, capsule,
                    (size_t)capsule_size,
                    envelope + BBP_V2_AUTH_TAG_OFFSET))
        return BBP_V2_AUTH_ERR_MAC;

    capsule_status = bbp_v2_parse(capsule, (size_t)capsule_size,
                                  &candidate.capsule);
    if (capsule_status != BBP_V2_OK) return BBP_V2_AUTH_ERR_CAPSULE;
    if (!policy(policy_context, rollback_index, envelope + 32,
                &candidate.capsule))
        return BBP_V2_AUTH_ERR_POLICY;

    candidate.envelope = envelope;
    candidate.envelope_size = extent;
    candidate.rollback_index = rollback_index;
    bytes_copy(candidate.key_identity, envelope + 32,
               BBP_V2_AUTH_KEY_ID_SIZE);
    *out = candidate;
    return BBP_V2_AUTH_OK;
}

const char *bbp_v2_auth_strstatus(bbp_v2_auth_status_t status)
{
    switch (status) {
    case BBP_V2_AUTH_OK: return "ok";
    case BBP_V2_AUTH_ERR_NULL: return "null argument or callback";
    case BBP_V2_AUTH_ERR_MAGIC: return "bad magic";
    case BBP_V2_AUTH_ERR_VERSION: return "unsupported envelope version";
    case BBP_V2_AUTH_ERR_ALGORITHM: return "unsupported MAC algorithm";
    case BBP_V2_AUTH_ERR_FLAGS: return "unsupported flags";
    case BBP_V2_AUTH_ERR_EXTENT: return "invalid exact extent";
    case BBP_V2_AUTH_ERR_MAC: return "authentication failed";
    case BBP_V2_AUTH_ERR_CAPSULE: return "invalid BBP v2 capsule";
    case BBP_V2_AUTH_ERR_POLICY: return "policy rejected capsule";
    default: return "unknown";
    }
}
