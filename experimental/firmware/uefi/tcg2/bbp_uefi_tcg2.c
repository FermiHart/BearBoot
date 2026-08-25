/* SPDX-License-Identifier: BSD-3-Clause */
#include "bbp_uefi_tcg2.h"

struct sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t used;
};

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void bytes_copy(void *destination, const void *source, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    const uint8_t *s = (const uint8_t *)source;
    while (bytes-- != 0u)
        *d++ = *s++;
}

static uint32_t rotate_right(uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void sha256_transform(struct sha256_context *context,
                             const uint8_t block[64])
{
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned i;

    for (i = 0u; i < 16u; i++)
        words[i] = read_be32(block + i * 4u);
    for (; i < 64u; i++) {
        uint32_t x = words[i - 15u];
        uint32_t y = words[i - 2u];
        uint32_t s0 = rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3);
        uint32_t s1 = rotate_right(y, 17u) ^ rotate_right(y, 19u) ^ (y >> 10);
        words[i] = words[i - 16u] + s0 + words[i - 7u] + s1;
    }

    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (i = 0u; i < 64u; i++) {
        uint32_t sum1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^
                        rotate_right(e, 25u);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choice + constants[i] + words[i];
        uint32_t sum0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^
                        rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(struct sha256_context *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    unsigned i;
    for (i = 0u; i < 8u; i++)
        context->state[i] = initial[i];
    context->bit_count = 0u;
    context->used = 0u;
}

static void sha256_update(struct sha256_context *context,
                          const uint8_t *data, size_t bytes)
{
    context->bit_count += (uint64_t)bytes * 8u;
    while (bytes != 0u) {
        size_t room = sizeof(context->block) - context->used;
        size_t take = bytes < room ? bytes : room;
        bytes_copy(context->block + context->used, data, take);
        context->used += take;
        data += take;
        bytes -= take;
        if (context->used == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->used = 0u;
        }
    }
}

static void sha256_final(struct sha256_context *context, uint8_t digest[32])
{
    uint64_t bits = context->bit_count;
    unsigned i;
    context->block[context->used++] = 0x80u;
    if (context->used > 56u) {
        while (context->used < 64u)
            context->block[context->used++] = 0u;
        sha256_transform(context, context->block);
        context->used = 0u;
    }
    while (context->used < 56u)
        context->block[context->used++] = 0u;
    for (i = 0u; i < 8u; i++)
        context->block[56u + i] = (uint8_t)(bits >> (56u - i * 8u));
    sha256_transform(context, context->block);
    for (i = 0u; i < 8u; i++)
        write_be32(digest + i * 4u, context->state[i]);
}

int bbp_tcg2_sha256(const void *data, size_t bytes, uint8_t digest[32])
{
    struct sha256_context context;
    if (digest == NULL || (bytes != 0u && data == NULL) ||
        bytes > (size_t)(UINT64_MAX >> 3))
        return -1;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)data, bytes);
    sha256_final(&context, digest);
    return 0;
}

void bbp_tcg2_sha256_extend(const uint8_t before[32],
                            const uint8_t digest[32], uint8_t after[32])
{
    uint8_t concatenated[64];
    bytes_copy(concatenated, before, 32u);
    bytes_copy(concatenated + 32u, digest, 32u);
    (void)bbp_tcg2_sha256(concatenated, sizeof(concatenated), after);
}

bbp_tcg2_wire_status bbp_tcg2_build_pcr_read(
    uint32_t pcr_index, uint8_t *output, size_t capacity, size_t *output_bytes)
{
    const size_t command_bytes = 20u;
    if (output == NULL || output_bytes == NULL)
        return BBP_TCG2_WIRE_ARGUMENT;
    if (pcr_index > BBP_TPM2_MAX_PCR)
        return BBP_TCG2_WIRE_PCR;
    if (capacity < command_bytes)
        return BBP_TCG2_WIRE_CAPACITY;
    for (size_t i = 0u; i < command_bytes; i++)
        output[i] = 0u;
    write_be16(output, BBP_TPM2_ST_NO_SESSIONS);
    write_be32(output + 2u, (uint32_t)command_bytes);
    write_be32(output + 6u, BBP_TPM2_PCR_READ_COMMAND);
    write_be32(output + 10u, 1u);
    write_be16(output + 14u, BBP_TPM2_ALG_SHA256);
    output[16] = 3u;
    output[17u + pcr_index / 8u] = (uint8_t)(1u << (pcr_index % 8u));
    *output_bytes = command_bytes;
    return BBP_TCG2_WIRE_OK;
}

bbp_tcg2_wire_status bbp_tcg2_parse_pcr_read_response(
    const uint8_t *response, size_t response_bytes, uint32_t expected_pcr,
    uint8_t digest[32], uint32_t *update_counter)
{
    size_t offset;
    uint8_t expected_select[3] = {0u, 0u, 0u};
    uint8_t candidate_digest[BBP_TPM2_SHA256_BYTES];
    uint32_t candidate_counter;
    uint32_t declared;

    if (response == NULL || digest == NULL || update_counter == NULL)
        return BBP_TCG2_WIRE_ARGUMENT;
    if (expected_pcr > BBP_TPM2_MAX_PCR)
        return BBP_TCG2_WIRE_PCR;
    if (response_bytes < 10u)
        return BBP_TCG2_WIRE_TRUNCATED;
    declared = read_be32(response + 2u);
    if (declared != response_bytes)
        return BBP_TCG2_WIRE_SIZE;
    if (read_be16(response) != BBP_TPM2_ST_NO_SESSIONS)
        return BBP_TCG2_WIRE_TAG;
    if (read_be32(response + 6u) != 0u)
        return BBP_TCG2_WIRE_RESPONSE_CODE;

    offset = 10u;
    if (response_bytes - offset < 8u)
        return BBP_TCG2_WIRE_TRUNCATED;
    candidate_counter = read_be32(response + offset);
    offset += 4u;
    if (read_be32(response + offset) != 1u)
        return BBP_TCG2_WIRE_COUNT;
    offset += 4u;
    if (response_bytes - offset < 3u)
        return BBP_TCG2_WIRE_TRUNCATED;
    if (read_be16(response + offset) != BBP_TPM2_ALG_SHA256)
        return BBP_TCG2_WIRE_ALGORITHM;
    offset += 2u;
    if (response[offset++] != 3u)
        return BBP_TCG2_WIRE_SELECTION;
    if (response_bytes - offset < 3u)
        return BBP_TCG2_WIRE_TRUNCATED;
    expected_select[expected_pcr / 8u] =
        (uint8_t)(1u << (expected_pcr % 8u));
    for (size_t i = 0u; i < 3u; i++) {
        if (response[offset + i] != expected_select[i])
            return BBP_TCG2_WIRE_SELECTION;
    }
    offset += 3u;
    if (response_bytes - offset < 6u)
        return BBP_TCG2_WIRE_TRUNCATED;
    if (read_be32(response + offset) != 1u)
        return BBP_TCG2_WIRE_COUNT;
    offset += 4u;
    if (read_be16(response + offset) != BBP_TPM2_SHA256_BYTES)
        return BBP_TCG2_WIRE_DIGEST_SIZE;
    offset += 2u;
    if (response_bytes - offset < BBP_TPM2_SHA256_BYTES)
        return BBP_TCG2_WIRE_TRUNCATED;
    bytes_copy(candidate_digest, response + offset, BBP_TPM2_SHA256_BYTES);
    offset += BBP_TPM2_SHA256_BYTES;
    if (offset != response_bytes)
        return BBP_TCG2_WIRE_TRAILING;
    bytes_copy(digest, candidate_digest, BBP_TPM2_SHA256_BYTES);
    *update_counter = candidate_counter;
    return BBP_TCG2_WIRE_OK;
}

const char *bbp_tcg2_wire_strstatus(bbp_tcg2_wire_status status)
{
    switch (status) {
    case BBP_TCG2_WIRE_OK:            return "ok";
    case BBP_TCG2_WIRE_ARGUMENT:      return "invalid argument";
    case BBP_TCG2_WIRE_CAPACITY:      return "insufficient capacity";
    case BBP_TCG2_WIRE_PCR:           return "invalid PCR";
    case BBP_TCG2_WIRE_TRUNCATED:     return "truncated response";
    case BBP_TCG2_WIRE_SIZE:          return "response size mismatch";
    case BBP_TCG2_WIRE_TAG:           return "unexpected response tag";
    case BBP_TCG2_WIRE_RESPONSE_CODE: return "TPM response error";
    case BBP_TCG2_WIRE_COUNT:         return "unexpected list count";
    case BBP_TCG2_WIRE_ALGORITHM:     return "unexpected algorithm";
    case BBP_TCG2_WIRE_SELECTION:     return "unexpected PCR selection";
    case BBP_TCG2_WIRE_DIGEST_SIZE:   return "unexpected digest size";
    case BBP_TCG2_WIRE_TRAILING:      return "trailing response bytes";
    default:                          return "unknown";
    }
}
