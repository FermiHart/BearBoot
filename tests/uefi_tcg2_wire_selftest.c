#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../experimental/firmware/uefi/tcg2/bbp_uefi_tcg2.h"

static int failures;

#define CHECK(condition, message) do { \
    if (condition) printf("ok:   %s\n", message); \
    else { printf("FAIL: %s\n", message); failures++; } \
} while (0)

static const uint8_t valid_response[62] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x0b, 0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x20,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static bbp_tcg2_wire_status parse(uint8_t *response, size_t bytes)
{
    uint8_t digest[32];
    uint32_t counter;
    return bbp_tcg2_parse_pcr_read_response(response, bytes, 16u,
                                             digest, &counter);
}

static void test_command_and_sha256(void)
{
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t command[20];
    uint8_t digest[32];
    size_t bytes = 0u;

    CHECK(bbp_tcg2_build_pcr_read(16u, command, sizeof(command), &bytes) ==
          BBP_TCG2_WIRE_OK && bytes == sizeof(command) &&
          command[17] == 0u && command[18] == 0u && command[19] == 1u,
          "PCR_Read command selects only SHA-256 PCR16");
    CHECK(bbp_tcg2_build_pcr_read(24u, command, sizeof(command), &bytes) ==
          BBP_TCG2_WIRE_PCR,
          "command builder rejects PCR indices outside 0..23");
    CHECK(bbp_tcg2_build_pcr_read(16u, command, sizeof(command) - 1u,
          &bytes) == BBP_TCG2_WIRE_CAPACITY,
          "command builder rejects short output buffers");
    CHECK(bbp_tcg2_sha256("abc", 3u, digest) == 0 &&
          memcmp(digest, abc_digest, sizeof(digest)) == 0,
          "dependency-free SHA-256 matches the abc KAT");
}

static void test_response_parser(void)
{
    uint8_t response[sizeof(valid_response) + 1u];
    uint8_t digest[32];
    uint32_t counter = 0u;

    memcpy(response, valid_response, sizeof(valid_response));
    CHECK(bbp_tcg2_parse_pcr_read_response(response, sizeof(valid_response),
          16u, digest, &counter) == BBP_TCG2_WIRE_OK && counter == 20u &&
          memcmp(digest, valid_response + 30u, sizeof(digest)) == 0,
          "bounded parser accepts an exact PCR16/SHA-256 response");
    for (size_t bytes = 0u; bytes < sizeof(valid_response); bytes++) {
        if (parse(response, bytes) == BBP_TCG2_WIRE_OK) {
            printf("FAIL: truncated response of %zu bytes was accepted\n", bytes);
            failures++;
            break;
        }
    }
    CHECK(failures == 0, "every proper prefix of a valid response is rejected");
    CHECK(parse(response, 9u) == BBP_TCG2_WIRE_TRUNCATED,
          "truncated TPM header is rejected");

    memcpy(response, valid_response, sizeof(valid_response));
    response[5] = 0x3du;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_SIZE,
          "declared response length mismatch is rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[1] = 0x02u;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_TAG,
          "session-tagged response is rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[9] = 0x84u;
    CHECK(parse(response, sizeof(valid_response)) ==
          BBP_TCG2_WIRE_RESPONSE_CODE,
          "non-success TPM response code is rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[17] = 0x02u;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_COUNT,
          "unexpected selection count is rejected before iteration");
    memcpy(response, valid_response, sizeof(valid_response));
    response[19] = 0x04u;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_ALGORITHM,
          "non-SHA-256 response selection is rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[20] = 0xffu;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_SELECTION,
          "oversized PCR select is rejected before reading it");
    memcpy(response, valid_response, sizeof(valid_response));
    response[23] = 0x02u;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_SELECTION,
          "wrong or additional selected PCR bits are rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[27] = 0x02u;
    CHECK(parse(response, sizeof(valid_response)) == BBP_TCG2_WIRE_COUNT,
          "unexpected digest count is rejected before iteration");
    memcpy(response, valid_response, sizeof(valid_response));
    response[29] = 0x1fu;
    CHECK(parse(response, sizeof(valid_response)) ==
          BBP_TCG2_WIRE_DIGEST_SIZE,
          "non-32-byte SHA-256 digest is rejected");
    memcpy(response, valid_response, sizeof(valid_response));
    response[5] = 0x3fu;
    response[sizeof(valid_response)] = 0u;
    CHECK(parse(response, sizeof(response)) == BBP_TCG2_WIRE_TRAILING,
          "trailing bytes outside the sole digest are rejected");
    CHECK(bbp_tcg2_parse_pcr_read_response(response, sizeof(response), 24u,
          digest, &counter) == BBP_TCG2_WIRE_PCR,
          "response parser rejects an out-of-range expected PCR");
}

int main(void)
{
    printf("== bounded UEFI TCG2/TPM2 wire self-test ==\n");
    test_command_and_sha256();
    test_response_parser();
    printf("%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
