/* Hosted collector proof; no UEFI headers, TCG2 protocol, or TPM is required. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"
#include "../experimental/firmware/uefi/bbp_security_collector.h"

#define ARENA_BYTES 4096u

static int failures;

#define CHECK(condition, message) do { \
    if (!(condition)) { printf("FAIL: %s\n", (message)); failures++; } \
    else printf("ok:   %s\n", (message)); \
} while (0)

struct fixture {
    union {
        max_align_t alignment;
        uint8_t bytes[sizeof(struct bbp_info) + ARENA_BYTES];
    } storage;
    struct bbp_builder builder;
};

struct mock_callbacks {
    unsigned tpm_calls;
    unsigned allocation_calls;
    unsigned abort_calls;
    int fail_tpm;
    unsigned fail_allocation;
    bbp_security_status abort_reason;
};

static const uint8_t expected_digest[BBP_SECURITY_SHA256_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static struct bbp_info *fixture_info(struct fixture *fixture)
{
    return (struct bbp_info *)fixture->storage.bytes;
}

static uint8_t *fixture_arena(struct fixture *fixture)
{
    return fixture->storage.bytes + sizeof(struct bbp_info);
}

static void fixture_init(struct fixture *fixture, size_t capacity)
{
    memset(fixture, 0, sizeof(*fixture));
    bbp_builder_init(&fixture->builder, fixture_arena(fixture),
        (bbp_phys_t)(uintptr_t)fixture_arena(fixture), capacity);
}

static int mock_hash_extend(void *context, uint32_t pcr_index,
                            uint32_t algorithm, const void *data,
                            size_t data_length, uint8_t digest[32])
{
    struct mock_callbacks *mock = context;
    size_t i;
    mock->tpm_calls++;
    if (pcr_index != 16u || algorithm != BBP_HASH_SHA256 || data == NULL ||
        data_length != 12u || memcmp(data, "kernel-image", 12u) != 0)
        return -1;
    if (mock->fail_tpm)
        return -1;
    for (i = 0; i < sizeof(expected_digest); i++)
        digest[i] = expected_digest[i];
    return 0;
}

static void *mock_allocate(void *context, struct bbp_builder *builder,
                           bbp_security_arena_object object,
                           const void *source, size_t bytes,
                           bbp_phys_t *out_phys)
{
    struct mock_callbacks *mock = context;
    mock->allocation_calls++;
    if (mock->fail_allocation == mock->allocation_calls)
        return NULL;
    return bbp_security_builder_allocate(NULL, builder, object, source, bytes,
                                         out_phys);
}

static void mock_abort(void *context, bbp_security_status reason)
{
    struct mock_callbacks *mock = context;
    mock->abort_calls++;
    mock->abort_reason = reason;
}

static struct bbp_security_callbacks callbacks_for(struct mock_callbacks *mock)
{
    struct bbp_security_callbacks callbacks;
    callbacks.context = mock;
    callbacks.hash_extend = mock_hash_extend;
    callbacks.arena_allocate = mock_allocate;
    callbacks.abort = mock_abort;
    return callbacks;
}

static struct bbp_security_source valid_source(void)
{
    static const uint8_t name[] = "kernel";
    struct bbp_security_source source;
    memset(&source, 0, sizeof(source));
    source.pcr_index = 16u;
    source.algorithm = BBP_HASH_SHA256;
    source.hash_length = BBP_SECURITY_SHA256_BYTES;
    source.data = "kernel-image";
    source.data_length = 12u;
    source.component_name = name;
    source.component_name_length = sizeof(name) - 1u;
    return source;
}

static struct bbp_security_platform valid_platform(void)
{
    struct bbp_security_platform platform;
    memset(&platform, 0, sizeof(platform));
    platform.tpm_version = 0x0200u;
    platform.tpm_interface = 2u;
    platform.tpm_flags = BBP_TPM_FLAG_ACTIVE;
    platform.secure_boot.mode = 2u;
    platform.secure_boot.signature_verified = 1u;
    platform.secure_boot.pk_present = 1u;
    platform.secure_boot.kek_present = 1u;
    platform.secure_boot.db_present = 1u;
    return platform;
}

static bbp_security_status collect_one(
    struct fixture *fixture, struct mock_callbacks *mock,
    struct bbp_tag_security **out_tag)
{
    struct bbp_security_source source = valid_source();
    struct bbp_security_platform platform = valid_platform();
    struct bbp_security_callbacks callbacks = callbacks_for(mock);
    return bbp_security_collect(&fixture->builder, &platform, &source, 1u,
                                &callbacks, out_tag);
}

static void test_success_roundtrip_and_tamper(void)
{
    struct fixture fixture;
    struct mock_callbacks mock;
    struct bbp_tag_security *published = NULL;
    struct bbp_info *info;
    struct bbp_kctx context;
    const struct bbp_tag_security *parsed;
    struct bbp_measurement *measurement;
    size_t log_bytes = sizeof(struct bbp_measurement);

    fixture_init(&fixture, ARENA_BYTES);
    memset(&mock, 0, sizeof(mock));
    CHECK(collect_one(&fixture, &mock, &published) == BBP_SECURITY_OK,
          "PCR16/SHA-256 measurement collection succeeds");
    CHECK(mock.tpm_calls == 1u && mock.allocation_calls == 2u &&
          mock.abort_calls == 0u,
          "one TPM operation precedes complete local publication");
    CHECK(published != NULL && published->header.tag_id == BBP_TAG_SECURITY &&
          published->header.tag_size == sizeof(*published) &&
          published->measurement_count == 1u &&
          published->measurements_crc != 0u,
          "collector emits the frozen v1.1 SECURITY layout");

    measurement = (struct bbp_measurement *)(uintptr_t)published->measurements;
    CHECK(measurement->pcr_index == 16u &&
          measurement->algorithm == BBP_HASH_SHA256 &&
          measurement->hash_length == 32u &&
          memcmp(measurement->hash, expected_digest, 32u) == 0 &&
          strcmp((const char *)measurement->component_name, "kernel") == 0,
          "measurement record contains PCR, algorithm, digest, and name");
    CHECK(published->measurements_crc == bbp_crc64(measurement, log_bytes),
          "measurements_crc seals the exact out-of-line record array");

    info = fixture_info(&fixture);
    CHECK(bbp_builder_finalize(&fixture.builder, info,
          (bbp_phys_t)(uintptr_t)info) != 0,
          "builder finalization seals SECURITY tag and INFO CRCs");
    CHECK(bbp_init_bounded(&context, info, 0, fixture.builder.arena_phys,
          fixture.builder.capacity) == BBP_OK,
          "bounded parser accepts finalized collector output");
    parsed = (const struct bbp_tag_security *)bbp_find_tag(
        &context, BBP_TAG_SECURITY);
    CHECK(parsed != NULL && bbp_verify_blob(&context, parsed->measurements,
          log_bytes, parsed->measurements_crc, 0) == BBP_OK,
          "bounded parser validates tag CRC and measurement-log CRC");

    measurement->hash[0] ^= 0x80u;
    CHECK(bbp_verify_blob(&context, parsed->measurements, log_bytes,
          parsed->measurements_crc, 0) == BBP_ERR_TAG_CHECKSUM,
          "tampered measurement log is rejected");
}

static void test_capacity_preflight_is_side_effect_free(void)
{
    struct fixture fixture;
    struct mock_callbacks mock;
    struct bbp_builder before;
    uint8_t arena_before[ARENA_BYTES];
    struct bbp_tag_security *published =
        (struct bbp_tag_security *)(uintptr_t)0x1234u;

    fixture_init(&fixture, sizeof(struct bbp_measurement) +
                            sizeof(struct bbp_tag_security) - 1u);
    memset(&mock, 0, sizeof(mock));
    before = fixture.builder;
    memcpy(arena_before, fixture_arena(&fixture), sizeof(arena_before));
    CHECK(collect_one(&fixture, &mock, &published) ==
          BBP_SECURITY_ERR_CAPACITY,
          "insufficient arena capacity fails exact preflight");
    CHECK(mock.tpm_calls == 0u && mock.allocation_calls == 0u,
          "capacity failure makes zero TPM and allocator calls");
    CHECK(memcmp(&fixture.builder, &before, sizeof(before)) == 0 &&
          memcmp(fixture_arena(&fixture), arena_before,
                 sizeof(arena_before)) == 0 &&
          published == (struct bbp_tag_security *)(uintptr_t)0x1234u,
          "capacity failure leaves builder, arena, and output unchanged");
}

static void test_tpm_failure_emits_nothing(void)
{
    struct fixture fixture;
    struct mock_callbacks mock;
    struct bbp_builder before;
    uint8_t arena_before[ARENA_BYTES];
    struct bbp_tag_security *published = NULL;

    fixture_init(&fixture, ARENA_BYTES);
    memset(&mock, 0, sizeof(mock));
    mock.fail_tpm = 1;
    before = fixture.builder;
    memcpy(arena_before, fixture_arena(&fixture), sizeof(arena_before));
    CHECK(collect_one(&fixture, &mock, &published) == BBP_SECURITY_ERR_TPM,
          "TPM callback failure is reported");
    CHECK(mock.tpm_calls == 1u && mock.allocation_calls == 0u &&
          mock.abort_calls == 0u,
          "first TPM failure performs no publication or abort");
    CHECK(memcmp(&fixture.builder, &before, sizeof(before)) == 0 &&
          memcmp(fixture_arena(&fixture), arena_before,
                 sizeof(arena_before)) == 0 && published == NULL,
          "TPM failure emits no tag or measurement bytes");
}

static void test_input_validation_precedes_callbacks(void)
{
    struct fixture fixture;
    struct mock_callbacks mock;
    struct bbp_security_source source;
    struct bbp_security_platform platform = valid_platform();
    struct bbp_security_callbacks callbacks;
    struct bbp_tag_security *published = NULL;
    uint8_t bad_name[64];
    static const uint8_t embedded_nul_name[] = {'k', 0, 'x'};

    fixture_init(&fixture, ARENA_BYTES);
    memset(&mock, 0, sizeof(mock));
    callbacks = callbacks_for(&mock);
    source = valid_source();
    source.pcr_index = BBP_SECURITY_MAX_PCR + 1u;
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_PCR,
          "out-of-range PCR is rejected");
    source = valid_source();
    source.algorithm = BBP_HASH_SHA384;
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_ALGORITHM,
          "non-SHA-256 algorithm is rejected");
    source = valid_source();
    source.hash_length = 31u;
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_HASH_LENGTH,
          "SHA-256 hash length must be exactly 32 bytes");
    memset(bad_name, 'x', sizeof(bad_name));
    source = valid_source();
    source.component_name = bad_name;
    source.component_name_length = sizeof(bad_name);
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_NAME,
          "component name must fit with a NUL in the 64-byte wire field");
    source = valid_source();
    source.component_name = embedded_nul_name;
    source.component_name_length = sizeof(embedded_nul_name);
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_NAME,
          "component name rejects embedded NUL bytes");
    source = valid_source();
    source.data_length = BBP_SECURITY_MAX_INPUT_BYTES + 1u;
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_RANGE,
          "component byte span is bounded");
    source = valid_source();
    source.data = (const void *)(uintptr_t)(UINTPTR_MAX - 3u);
    source.data_length = 8u;
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 1u,
          &callbacks, &published) == BBP_SECURITY_ERR_RANGE,
          "wrapping component byte span is rejected before dereference");
    CHECK(bbp_security_collect(&fixture.builder, &platform, &source, 0u,
          &callbacks, &published) == BBP_SECURITY_ERR_COUNT &&
          bbp_security_collect(&fixture.builder, &platform, &source,
          BBP_SECURITY_MAX_MEASUREMENTS + 1u, &callbacks, &published) ==
          BBP_SECURITY_ERR_COUNT,
          "zero and excessive measurement counts are rejected");
    CHECK(mock.tpm_calls == 0u && mock.allocation_calls == 0u,
          "all validation failures precede external callbacks");
}

static void test_late_publish_failure_aborts_and_rolls_back(void)
{
    struct fixture fixture;
    struct mock_callbacks mock;
    struct bbp_builder before;
    uint8_t arena_before[ARENA_BYTES];
    struct bbp_tag_security *published = NULL;

    fixture_init(&fixture, ARENA_BYTES);
    memset(&mock, 0, sizeof(mock));
    mock.fail_allocation = 2u;
    before = fixture.builder;
    memcpy(arena_before, fixture_arena(&fixture), sizeof(arena_before));
    CHECK(collect_one(&fixture, &mock, &published) ==
          BBP_SECURITY_ERR_ABORT_RETURNED,
          "a returning hosted abort hook produces a terminal status");
    CHECK(mock.tpm_calls == 1u && mock.abort_calls == 1u &&
          mock.abort_reason == BBP_SECURITY_ERR_PUBLISH_AFTER_TPM,
          "late allocation failure after TPM success invokes abort");
    CHECK(memcmp(&fixture.builder, &before, sizeof(before)) == 0 &&
          memcmp(fixture_arena(&fixture), arena_before,
                 sizeof(arena_before)) == 0 && published == NULL,
          "returning abort hook still leaves local output byte-atomic");
}

int main(void)
{
    printf("== firmware-independent SECURITY collector self-test ==\n");
    test_success_roundtrip_and_tamper();
    test_capacity_preflight_is_side_effect_free();
    test_tpm_failure_emits_nothing();
    test_input_validation_precedes_callbacks();
    test_late_publish_failure_aborts_and_rolls_back();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
