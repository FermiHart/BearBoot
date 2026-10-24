/* SPDX-License-Identifier: BSD-3-Clause */
#include "bbp_auth2_crypto.h"

#include <bearssl.h>

void *bbp_auth2_memcpy(void *destination, const void *source, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    const uint8_t *in = (const uint8_t *)source;
    size_t i;
    for (i = 0; i < size; i++) out[i] = in[i];
    return destination;
}

void *bbp_auth2_memmove(void *destination, const void *source, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    const uint8_t *in = (const uint8_t *)source;
    size_t i;
    if (out < in) {
        for (i = 0; i < size; i++) out[i] = in[i];
    } else if (out > in) {
        for (i = size; i != 0; i--) out[i - 1u] = in[i - 1u];
    }
    return destination;
}

void *bbp_auth2_memset(void *destination, int value, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    size_t i;
    for (i = 0; i < size; i++) out[i] = (uint8_t)value;
    return destination;
}

void bbp_auth2_sha256_parts(const struct bbp_auth2_hash_part *parts,
                            size_t part_count, uint8_t digest[32])
{
    br_sha256_context context;
    size_t i;
    br_sha256_init(&context);
    for (i = 0; i < part_count; i++) {
        br_sha256_update(&context, parts[i].data, parts[i].size);
    }
    br_sha256_out(&context, digest);
}

int bbp_auth2_p256_point_valid(const uint8_t point[65])
{
    static const uint8_t one[1] = {1};
    uint8_t candidate[65];
    bbp_auth2_memcpy(candidate, point, sizeof(candidate));
    if (candidate[0] != 4u) return 0;
    return br_ec_p256_m15.mul(candidate, sizeof(candidate), one, sizeof(one),
                              BR_EC_secp256r1) != 0;
}

int bbp_auth2_p256_verify(const uint8_t point[65],
                          const uint8_t digest[32],
                          const uint8_t signature[64])
{
    br_ec_public_key key;
    key.curve = BR_EC_secp256r1;
    key.q = (unsigned char *)(uintptr_t)point;
    key.qlen = 65;
    return br_ecdsa_i15_vrfy_raw(&br_ec_p256_m15, digest, 32, &key,
                                  signature, 64) != 0;
}
