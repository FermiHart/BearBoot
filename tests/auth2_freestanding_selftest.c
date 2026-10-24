/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_auth2.h>

#include "../v2/bbp_auth2_crypto.h"

#include <stdio.h>
#include <string.h>

#ifndef BBP_AUTH2_TEST_VECTOR_DIR
#define BBP_AUTH2_TEST_VECTOR_DIR "build/auth2-vectors"
#endif

static int failures;

#define CHECK(condition, message) do {                                      \
    if (!(condition)) {                                                     \
        fprintf(stderr, "FAIL: %s\n", (message));                           \
        failures++;                                                         \
    }                                                                       \
} while (0)

static const uint8_t root_public_key[BBP_AUTH2_PUBLIC_KEY_SIZE] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
    0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
    0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
    0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5
};

static const uint8_t p256_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static const uint8_t sha256_empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static const uint8_t sha256_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static void make_high_s(uint8_t signature[BBP_AUTH2_SIGNATURE_SIZE])
{
    unsigned borrow = 0, i;
    for (i = 32; i-- > 0;) {
        unsigned order_byte = p256_order[i];
        unsigned low_byte = signature[32u + i];
        unsigned subtrahend = low_byte + borrow;
        signature[32u + i] = (uint8_t)(order_byte - subtrahend);
        borrow = order_byte < subtrahend;
    }
}

static int load_file(const char *path, uint8_t *buffer, size_t capacity,
                     size_t *size)
{
    FILE *file = fopen(path, "rb");
    size_t got;
    if (!file) return 0;
    got = fread(buffer, 1, capacity, file);
    if (ferror(file) || !feof(file)) {
        fclose(file);
        return 0;
    }
    fclose(file);
    *size = got;
    return 1;
}

static void expect_manifest_status(const char *path,
                                   bbp_auth2_status_t expected,
                                   const char *message)
{
    uint8_t manifest[512];
    size_t manifest_size = 0;
    struct bbp_auth2_manifest_view view;
    CHECK(load_file(path, manifest, sizeof(manifest), &manifest_size) &&
          bbp_auth2_verify_manifest(
              manifest, manifest_size, root_public_key,
              sizeof(root_public_key), 0, &view) == expected,
          message);
}

static void test_crypto_provider(void)
{
    static const uint8_t abc[3] = {'a', 'b', 'c'};
    struct bbp_auth2_hash_part parts[3];
    uint8_t digest[32], invalid_point[65];

    bbp_auth2_sha256_parts(NULL, 0, digest);
    CHECK(memcmp(digest, sha256_empty, sizeof(digest)) == 0,
          "pinned provider matches the SHA-256 empty KAT");
    parts[0] = (struct bbp_auth2_hash_part){abc, 1};
    parts[1] = (struct bbp_auth2_hash_part){abc + 1, 1};
    parts[2] = (struct bbp_auth2_hash_part){abc + 2, 1};
    bbp_auth2_sha256_parts(parts, 3, digest);
    CHECK(memcmp(digest, sha256_abc, sizeof(digest)) == 0,
          "pinned provider matches split-update SHA-256 abc KAT");
    CHECK(bbp_auth2_p256_point_valid(root_public_key),
          "pinned provider accepts the P-256 generator point");
    memset(invalid_point, 0, sizeof(invalid_point));
    invalid_point[0] = 4;
    CHECK(!bbp_auth2_p256_point_valid(invalid_point),
          "pinned provider rejects an off-curve public point");
    memcpy(invalid_point, root_public_key, sizeof(invalid_point));
    invalid_point[0] = 3;
    CHECK(!bbp_auth2_p256_point_valid(invalid_point),
          "wrapper rejects compressed SEC1 public points");
}

static void test_checked_in_vectors(void)
{
    uint8_t manifest[512], envelope[512], recovery[512], payload[128];
    uint8_t mutated[513];
    uint8_t wrong_root[sizeof(root_public_key)] = {0};
    struct bbp_auth2_manifest_view manifest_view, manifest_before;
    struct bbp_auth2_verified_envelope verified, verified_before;
    union {
        max_align_t alignment;
        struct bbp_auth2_manifest_view manifest_view;
        struct bbp_auth2_verified_envelope verified;
        uint8_t bytes[512];
    } alias;
    size_t manifest_size = 0, envelope_size = 0, recovery_size = 0;
    size_t payload_size = 0, i;

    CHECK(load_file("tests/vectors/auth2/manifest.auth2", manifest,
                    sizeof(manifest), &manifest_size),
          "load checked-in manifest");
    CHECK(load_file("tests/vectors/auth2/release.auth2", envelope,
                    sizeof(envelope), &envelope_size),
          "load checked-in envelope");
    CHECK(load_file("tests/vectors/auth2/recovery.auth2", recovery,
                    sizeof(recovery), &recovery_size),
          "load checked-in recovery envelope");
    CHECK(load_file("tests/vectors/auth2/payload.dat", payload,
                    sizeof(payload), &payload_size),
          "load checked-in payload");

    memset(&manifest_view, 0xa5, sizeof(manifest_view));
    CHECK(bbp_auth2_verify_manifest(
              manifest, manifest_size, root_public_key,
              sizeof(root_public_key), 7, &manifest_view) == BBP_AUTH2_OK &&
          manifest_view.data == manifest &&
          manifest_view.size == manifest_size &&
          manifest_view.security_generation == 7 &&
          manifest_view.key_count == 2,
          "freestanding verifier authenticates the checked-in manifest");

    memset(&verified, 0xa5, sizeof(verified));
    CHECK(bbp_auth2_verify_envelope(
              envelope, envelope_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 7, 0,
              &verified) == BBP_AUTH2_OK &&
          verified.payload == envelope + BBP_AUTH2_ENVELOPE_HEADER_SIZE &&
          verified.payload_size == payload_size &&
          memcmp(verified.payload, payload, payload_size) == 0 &&
          verified.security_generation == 7 &&
          verified.role == BBP_AUTH2_ROLE_RELEASE &&
          memcmp(verified.signer_key_id, envelope + 40,
                 BBP_AUTH2_KEY_ID_SIZE) == 0,
          "freestanding verifier releases only the authentic exact payload");

    CHECK(bbp_auth2_verify_envelope(
              recovery, recovery_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 7, 0,
              &verified) == BBP_AUTH2_ERR_POLICY,
          "recovery is denied without explicit caller policy");
    CHECK(bbp_auth2_verify_envelope(
              recovery, recovery_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 7,
              BBP_AUTH2_ALLOW_RECOVERY, &verified) == BBP_AUTH2_OK &&
          verified.role == BBP_AUTH2_ROLE_RECOVERY &&
          verified.payload_size == payload_size &&
          memcmp(verified.payload, payload, payload_size) == 0,
          "explicit caller policy admits an authentic recovery envelope");

    memset(&manifest_view, 0xa5, sizeof(manifest_view));
    manifest_before = manifest_view;
    CHECK(bbp_auth2_verify_manifest(
              manifest, manifest_size, root_public_key,
              sizeof(root_public_key), 8, &manifest_view) ==
              BBP_AUTH2_ERR_GENERATION &&
          memcmp(&manifest_view, &manifest_before, sizeof(manifest_view)) == 0,
          "generation-floor failure does not publish a manifest view");

    wrong_root[0] = 4;
    memset(&manifest_view, 0xa5, sizeof(manifest_view));
    manifest_before = manifest_view;
    CHECK(bbp_auth2_verify_manifest(
              manifest, manifest_size, wrong_root, sizeof(wrong_root), 0,
              &manifest_view) == BBP_AUTH2_ERR_KEY &&
          memcmp(&manifest_view, &manifest_before, sizeof(manifest_view)) == 0,
          "invalid root point fails without output publication");

    memcpy(mutated, manifest, manifest_size);
    memset(mutated + 72, 0, 32);
    CHECK(bbp_auth2_verify_manifest(
              mutated, manifest_size, root_public_key,
              sizeof(root_public_key), 0, &manifest_view) ==
              BBP_AUTH2_ERR_SIGNATURE,
          "zero manifest scalar is rejected before provider verification");

    memcpy(mutated, manifest, manifest_size);
    memcpy(mutated + 72, p256_order, sizeof(p256_order));
    CHECK(bbp_auth2_verify_manifest(
              mutated, manifest_size, root_public_key,
              sizeof(root_public_key), 0, &manifest_view) ==
              BBP_AUTH2_ERR_SIGNATURE,
          "out-of-range manifest scalar is rejected");

    memcpy(mutated, manifest, manifest_size);
    make_high_s(mutated + 72);
    CHECK(bbp_auth2_verify_manifest(
              mutated, manifest_size, root_public_key,
              sizeof(root_public_key), 0, &manifest_view) ==
              BBP_AUTH2_ERR_SIGNATURE,
          "valid equivalent high-S manifest signature is rejected");

    memcpy(mutated, envelope, envelope_size);
    make_high_s(mutated + 72);
    CHECK(bbp_auth2_verify_envelope(
              mutated, envelope_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 0, 0,
              &verified) == BBP_AUTH2_ERR_SIGNATURE,
          "valid equivalent high-S envelope signature is rejected");

    memcpy(mutated, envelope, envelope_size);
    mutated[envelope_size - 1u] ^= 1u;
    memset(&verified, 0xa5, sizeof(verified));
    verified_before = verified;
    CHECK(bbp_auth2_verify_envelope(
              mutated, envelope_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 0, 0,
              &verified) == BBP_AUTH2_ERR_SIGNATURE &&
          memcmp(&verified, &verified_before, sizeof(verified)) == 0,
          "payload tamper fails without releasing a borrowed view");

    memcpy(mutated, envelope, envelope_size);
    mutated[envelope_size] = 0;
    CHECK(bbp_auth2_verify_envelope(
              mutated, envelope_size + 1u, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 0, 0,
              &verified) == BBP_AUTH2_ERR_EXTENT,
          "trailing envelope bytes are rejected");

    memcpy(mutated, manifest, manifest_size);
    mutated[manifest_size] = 0;
    CHECK(bbp_auth2_verify_manifest(
              mutated, manifest_size + 1u, root_public_key,
              sizeof(root_public_key), 0,
              &manifest_view) == BBP_AUTH2_ERR_EXTENT,
          "trailing manifest bytes are rejected");

    CHECK(bbp_auth2_verify_envelope(
              envelope, envelope_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 0, 2u,
              &verified) == BBP_AUTH2_ERR_POLICY,
          "unknown verifier policy bits fail closed");

    memcpy(alias.bytes, manifest, manifest_size);
    CHECK(bbp_auth2_verify_manifest(
              alias.bytes, manifest_size, root_public_key,
              sizeof(root_public_key), 0,
              &alias.manifest_view) == BBP_AUTH2_ERR_ALIAS,
          "manifest verifier rejects output aliasing authenticated input");
    memcpy(alias.bytes, envelope, envelope_size);
    CHECK(bbp_auth2_verify_envelope(
              alias.bytes, envelope_size, manifest, manifest_size,
              root_public_key, sizeof(root_public_key), 0, 0,
              &alias.verified) == BBP_AUTH2_ERR_ALIAS,
          "envelope verifier rejects output aliasing authenticated input");

    for (i = 0; i < manifest_size; i++) {
        memset(&manifest_view, 0xa5, sizeof(manifest_view));
        manifest_before = manifest_view;
        if (bbp_auth2_verify_manifest(
                manifest, i, root_public_key, sizeof(root_public_key), 0,
                &manifest_view) == BBP_AUTH2_OK ||
            memcmp(&manifest_view, &manifest_before,
                   sizeof(manifest_view)) != 0) {
            CHECK(0, "every manifest truncation fails atomically");
            break;
        }
    }
    for (i = 0; i < envelope_size; i++) {
        memset(&verified, 0xa5, sizeof(verified));
        verified_before = verified;
        if (bbp_auth2_verify_envelope(
                envelope, i, manifest, manifest_size, root_public_key,
                sizeof(root_public_key), 0, 0, &verified) == BBP_AUTH2_OK ||
            memcmp(&verified, &verified_before, sizeof(verified)) != 0) {
            CHECK(0, "every envelope truncation fails atomically");
            break;
        }
    }
}

static void test_authenticated_negative_manifests(void)
{
    static const struct {
        const char *name;
        bbp_auth2_status_t status;
    } cases[] = {
        {"entry-algorithm", BBP_AUTH2_ERR_ALGORITHM},
        {"entry-role", BBP_AUTH2_ERR_FORMAT},
        {"entry-flags", BBP_AUTH2_ERR_FORMAT},
        {"entry-window", BBP_AUTH2_ERR_FORMAT},
        {"entry-reserved", BBP_AUTH2_ERR_FORMAT},
        {"entry-key-id", BBP_AUTH2_ERR_KEY},
        {"entry-point", BBP_AUTH2_ERR_KEY},
        {"duplicate-entry", BBP_AUTH2_ERR_KEY},
    };
    char path[128];
    uint8_t manifest[512], envelope[512];
    size_t manifest_size, envelope_size, i;
    struct bbp_auth2_verified_envelope verified;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int length = snprintf(path, sizeof(path),
                              BBP_AUTH2_TEST_VECTOR_DIR
                              "/manifest-invalid-%s.auth2", cases[i].name);
        CHECK(length > 0 && (size_t)length < sizeof(path),
              "negative manifest path fits its fixed buffer");
        expect_manifest_status(path, cases[i].status,
                               "authenticated malformed manifest is rejected");
    }

    CHECK(load_file("tests/vectors/auth2/release.auth2", envelope,
                    sizeof(envelope), &envelope_size),
          "load release envelope for lifecycle tests");
    for (i = 0; i < 3; i++) {
        static const char *const names[] = {
            "revoked", "not-active", "retired"
        };
        static const bbp_auth2_status_t statuses[] = {
            BBP_AUTH2_ERR_POLICY,
            BBP_AUTH2_ERR_GENERATION,
            BBP_AUTH2_ERR_GENERATION,
        };
        int length = snprintf(path, sizeof(path),
                              BBP_AUTH2_TEST_VECTOR_DIR "/manifest-%s.auth2",
                              names[i]);
        CHECK(length > 0 && (size_t)length < sizeof(path),
              "lifecycle manifest path fits its fixed buffer");
        CHECK(load_file(path, manifest, sizeof(manifest), &manifest_size) &&
              bbp_auth2_verify_envelope(
                  envelope, envelope_size, manifest, manifest_size,
                  root_public_key, sizeof(root_public_key), 0, 0,
                  &verified) == statuses[i],
              "authenticated signer lifecycle policy is enforced");
    }
}

int main(void)
{
    test_crypto_provider();
    test_checked_in_vectors();
    test_authenticated_negative_manifests();
    printf("BBP auth2 freestanding selftest: %s (%d failures)\n",
           failures ? "FAILED" : "PASSED", failures);
    return failures != 0;
}
