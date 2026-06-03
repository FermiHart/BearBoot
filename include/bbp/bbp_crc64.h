/*
 * bbp_crc64.h — CRC-64/XZ (ECMA-182) for the Bear Boot Protocol.
 *
 * Freestanding, header-only, zero global state, no libc.
 * Same parameters as the checksum used by Limine / xz:
 *
 *     width   = 64
 *     poly    = 0x42F0E1EBA9EA3693   (reflected: 0xC96C5795D7870F42)
 *     init    = 0xFFFFFFFFFFFFFFFF
 *     refin   = true
 *     refout  = true
 *     xorout  = 0xFFFFFFFFFFFFFFFF
 *     check   = 0x995DC9BBDF1939FA   ("123456789")
 *
 * Incremental use:
 *     uint64_t c = bbp_crc64_init();
 *     c = bbp_crc64_update(c, a, alen);
 *     c = bbp_crc64_update(c, b, blen);
 *     uint64_t out = bbp_crc64_final(c);
 *
 * One-shot:
 *     uint64_t out = bbp_crc64(buf, len);
 *
 * Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_CRC64_H
#define BBP_CRC64_H

#include <stdint.h>
#include <stddef.h>

#define BBP_CRC64_POLY_REFLECTED 0xC96C5795D7870F42ULL
#define BBP_CRC64_INIT           0xFFFFFFFFFFFFFFFFULL

/* Begin an incremental computation. */
static inline uint64_t bbp_crc64_init(void)
{
    return BBP_CRC64_INIT;
}

/* Fold `len` bytes of `data` into the running CRC `crc`.
 * Bitwise (no 2KiB table) — fine for boot-time checksums of small structs;
 * a slice-by-8 table variant lives in tools/crc64.c for bulk hashing. */
static inline uint64_t bbp_crc64_update(uint64_t crc, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint64_t)p[i];
        for (int k = 0; k < 8; k++) {
            uint64_t mask = (uint64_t)-(int64_t)(crc & 1ULL);
            crc = (crc >> 1) ^ (BBP_CRC64_POLY_REFLECTED & mask);
        }
    }
    return crc;
}

/* Finalize an incremental computation (applies xorout). */
static inline uint64_t bbp_crc64_final(uint64_t crc)
{
    return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

/* One-shot convenience. */
static inline uint64_t bbp_crc64(const void *data, size_t len)
{
    return bbp_crc64_final(bbp_crc64_update(bbp_crc64_init(), data, len));
}

#endif /* BBP_CRC64_H */
