/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef BBP_AUTH2_CRYPTO_H
#define BBP_AUTH2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

struct bbp_auth2_hash_part {
    const void *data;
    size_t size;
};

void bbp_auth2_sha256_parts(const struct bbp_auth2_hash_part *parts,
                            size_t part_count, uint8_t digest[32]);
int bbp_auth2_p256_point_valid(const uint8_t point[65]);
int bbp_auth2_p256_verify(const uint8_t point[65],
                          const uint8_t digest[32],
                          const uint8_t signature[64]);

/* Private freestanding memory symbols used by the pinned BearSSL objects. */
void *bbp_auth2_memcpy(void *destination, const void *source, size_t size);
void *bbp_auth2_memmove(void *destination, const void *source, size_t size);
void *bbp_auth2_memset(void *destination, int value, size_t size);

#endif
