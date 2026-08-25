/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bbp/bbp_crc64.h>
#include <bbp/bbp_v2.h>
#include "../bootloader/bbp_build.h"
#include "../bridge/bbp_bridge.h"
#include "../kernel/bbp_kernel.h"

static int failures;

#define CHECK(c, msg) do { \
    if (!(c)) { printf("FAIL: %s\n", msg); failures++; } \
} while (0)

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static void store32(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8u * i));
}

static void store16(uint8_t *p, uint16_t v)
{
    unsigned i;
    for (i = 0; i < 2; i++) p[i] = (uint8_t)(v >> (8u * i));
}

static void store64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8u * i));
}

static uint64_t capsule_crc(const uint8_t *p, size_t n)
{
    static const uint8_t zero[8] = {0};
    uint64_t crc = bbp_crc64_init();
    crc = bbp_crc64_update(crc, p, 40);
    crc = bbp_crc64_update(crc, zero, sizeof(zero));
    crc = bbp_crc64_update(crc, p + 48, n - 48);
    return bbp_crc64_final(crc);
}

static uint64_t crc_skip_field(const uint8_t *p, size_t n, size_t offset)
{
    static const uint8_t zero[8] = {0};
    uint64_t crc = bbp_crc64_init();
    crc = bbp_crc64_update(crc, p, offset);
    crc = bbp_crc64_update(crc, zero, sizeof(zero));
    crc = bbp_crc64_update(crc, p + offset + 8, n - offset - 8);
    return bbp_crc64_final(crc);
}

static void reseal(uint8_t *p, size_t n)
{
    store64(p + 40, 0);
    store64(p + 40, capsule_crc(p, n));
}

static size_t make_capsule(uint8_t *out, size_t capacity, uint32_t alignment)
{
    static const uint8_t a[] = {1, 2, 3, 4, 5};
    static const uint8_t unknown[] = "unknown-entry";
    const struct bbp_v2_build_entry entries[] = {
        { UINT64_C(0x0001000000000003), 0, 1, alignment, a, sizeof(a) },
        { UINT64_C(0xfedcba9876543210), UINT32_C(0x80000000), 7,
          alignment, unknown, sizeof(unknown) }
    };
    size_t written = 0;
    CHECK(bbp_v2_build(out, capacity, entries, 2, &written) == BBP_V2_OK,
          "builder accepts known and unknown entries");
    return written;
}

static void test_layout_and_roundtrip(void)
{
    uint8_t a[1024], b[1024];
    struct bbp_v2_view view;
    struct bbp_v2_entry_view entry;
    size_t na = make_capsule(a, sizeof(a), 64);
    size_t nb = make_capsule(b, sizeof(b), 64);

    CHECK(sizeof(struct bbp_v2_header) == 64, "v2 header is exactly 64 bytes");
    CHECK(sizeof(struct bbp_v2_directory_entry) == 48,
          "v2 directory entry is exactly 48 bytes");
    CHECK(na != 0 && na == nb && memcmp(a, b, na) == 0,
          "builder output is deterministic");
    CHECK(bbp_v2_parse(a, na, &view) == BBP_V2_OK,
          "valid capsule parses");
    CHECK(view.entry_count == 2, "parser reports both entries");
    CHECK(bbp_v2_get_entry(&view, 1, &entry) == BBP_V2_OK &&
          entry.type == UINT64_C(0xfedcba9876543210),
          "unknown entry is accepted and exposed");
    CHECK(entry.size == sizeof("unknown-entry") &&
          memcmp(entry.data, "unknown-entry", entry.size) == 0,
          "unknown payload is preserved");
}

static void test_truncation_overflow_and_caps(void)
{
    uint8_t capsule[1024], forged[1024];
    struct bbp_v2_view view, before;
    struct bbp_v2_build_entry huge;
    size_t n = make_capsule(capsule, sizeof(capsule), 8);
    size_t empty_size = 0, rejected_size = 123;
    size_t i;

    CHECK(bbp_v2_build(forged, sizeof(forged), NULL, 0, &empty_size) ==
          BBP_V2_OK && empty_size == BBP_V2_HEADER_SIZE &&
          bbp_v2_parse(forged, empty_size, &view) == BBP_V2_OK,
          "empty capsules have a bounded canonical representation");

    memset(&view, 0xa5, sizeof(view));
    before = view;
    for (i = 0; i < n; i++) {
        bbp_v2_status_t st = bbp_v2_parse(capsule, i, &view);
        CHECK(st != BBP_V2_OK, "every truncated extent is rejected");
        CHECK(memcmp(&view, &before, sizeof(view)) == 0,
              "parse failure is output-atomic");
    }
    memcpy(forged, capsule, n);
    store64(forged + 64 + 16, UINT64_MAX - 7);
    store64(forged + 64 + 24, 32);
    reseal(forged, n);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_OVERFLOW,
          "wrapping payload span is rejected before CRC");

    memcpy(forged, capsule, n);
    store32(forged + 20, BBP_V2_MAX_ENTRIES + 1u);
    reseal(forged, n);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_COUNT,
          "entry count cap is enforced");

    memcpy(forged, capsule, n);
    store64(forged + 24, (uint64_t)BBP_V2_MAX_EXTENT + 1u);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_EXTENT,
          "total extent cap is enforced before checksum work");

    memset(forged, 0xa5, sizeof(forged));
    huge = (struct bbp_v2_build_entry){1, 0, 1, 8, capsule, SIZE_MAX};
    CHECK(bbp_v2_build(forged, sizeof(forged), &huge, 1, &rejected_size) ==
          BBP_V2_ERR_OVERFLOW && rejected_size == 123,
          "builder rejects a wrapping source without touching written");
    for (i = 0; i < sizeof(forged); i++) {
        if (forged[i] != 0xa5) {
            CHECK(0, "builder failure leaves destination unchanged");
            break;
        }
    }
    huge = (struct bbp_v2_build_entry){1, 0, 1, 8, capsule,
                                       49u * 1024u * 1024u};
    CHECK(bbp_v2_build(forged, sizeof(forged), &huge, 1, &rejected_size) ==
          BBP_V2_ERR_WORK,
          "builder enforces the cumulative CRC work cap before reading data");
}

static void test_overlap_alignment_crc_and_padding(void)
{
    uint8_t capsule[1024], forged[1024];
    struct bbp_v2_view view;
    size_t n = make_capsule(capsule, sizeof(capsule), 64);
    uint64_t first = load64(capsule + 64 + 16);
    uint64_t second = load64(capsule + 64 + 48 + 16);
    size_t i;

    memcpy(forged, capsule, n);
    store64(forged + 64 + 48 + 16, first + 1);
    reseal(forged, n);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_ALIGNMENT,
          "misaligned payload is rejected");

    memcpy(forged, capsule, n);
    store32(forged + 64 + 48 + 40, 1);
    store64(forged + 64 + 48 + 16, first + 1);
    reseal(forged, n);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_OVERLAP,
          "overlapping payloads are rejected");

    memcpy(forged, capsule, n);
    forged[first] ^= 1;
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_CRC,
          "capsule CRC detects payload tampering");

    memcpy(forged, capsule, n);
    forged[first] ^= 1;
    reseal(forged, n);
    CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_CRC,
          "entry CRC detects payload tampering after capsule reseal");

    for (i = 64 + 2 * 48; i < (size_t)first; i++) {
        if (capsule[i] == 0) {
            memcpy(forged, capsule, n);
            forged[i] = 1;
            reseal(forged, n);
            CHECK(bbp_v2_parse(forged, n, &view) == BBP_V2_ERR_PADDING,
                  "nonzero alignment padding is rejected");
            break;
        }
    }
    CHECK(second > first, "builder emits non-overlapping payload offsets");
}

static void test_builder_control_aliases(void)
{
    static const uint8_t payload[] = {1, 2, 3, 4};
    union {
        max_align_t alignment;
        struct bbp_v2_build_entry entry;
        uint8_t bytes[512];
    } storage;
    union {
        max_align_t alignment;
        uint8_t bytes[16];
    } source;
    struct bbp_v2_build_entry *entries;
    uint8_t before[sizeof(storage.bytes)];
    uint8_t source_before[sizeof(source.bytes)];
    size_t written = 123;

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    entries = &storage.entry;
    *entries = (struct bbp_v2_build_entry){
        UINT64_C(0x1234), 0, 1, 8, payload, sizeof(payload)
    };
    memcpy(before, storage.bytes, sizeof(before));
    CHECK(bbp_v2_build(storage.bytes, sizeof(storage.bytes), entries, 1,
                       &written) == BBP_V2_ERR_SOURCE,
          "builder rejects descriptor metadata inside its output extent");
    CHECK(written == 0 && memcmp(storage.bytes, before, sizeof(before)) == 0,
          "descriptor alias rejection leaves destination unchanged");

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    memcpy(before, storage.bytes, sizeof(before));
    {
        const struct bbp_v2_build_entry external = {
            UINT64_C(0x1234), 0, 1, 8, payload, sizeof(payload)
        };
        CHECK(bbp_v2_build(storage.bytes, sizeof(storage.bytes), &external, 1,
                           (size_t *)(void *)storage.bytes) ==
              BBP_V2_ERR_SOURCE,
              "builder rejects written metadata inside its output buffer");
    }
    CHECK(memcmp(storage.bytes, before, sizeof(before)) == 0,
          "written alias rejection leaves destination unchanged");

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    storage.entry = (struct bbp_v2_build_entry){
        UINT64_C(0x1234), 0, 1, 8, payload, sizeof(payload)
    };
    memcpy(before, storage.bytes, sizeof(before));
    CHECK(bbp_v2_build(before, sizeof(before), &storage.entry, 1,
                       (size_t *)(void *)&storage.entry) ==
          BBP_V2_ERR_SOURCE,
          "builder rejects written metadata inside its descriptor array");
    CHECK(memcmp(storage.bytes, before, sizeof(before)) == 0,
          "descriptor metadata remains unchanged on written alias rejection");

    memset(source.bytes, 0x5a, sizeof(source.bytes));
    memcpy(source_before, source.bytes, sizeof(source_before));
    entries = &(struct bbp_v2_build_entry){
        UINT64_C(0x1234), 0, 1, 8, source.bytes, sizeof(source.bytes)
    };
    CHECK(bbp_v2_build(storage.bytes, sizeof(storage.bytes), entries, 1,
                       (size_t *)(void *)source.bytes) ==
          BBP_V2_ERR_SOURCE,
          "builder rejects written metadata inside a payload source");
    CHECK(memcmp(source.bytes, source_before, sizeof(source_before)) == 0,
          "payload remains unchanged on written alias rejection");

    CHECK(bbp_v2_build(NULL, sizeof(storage.bytes), entries, 1,
                       (size_t *)(void *)source.bytes) ==
          BBP_V2_ERR_SOURCE,
          "NULL output does not hide a written-payload alias");
    CHECK(memcmp(source.bytes, source_before, sizeof(source_before)) == 0,
          "early output failure leaves aliased payload metadata unchanged");

    CHECK(bbp_v2_build(before, sizeof(before), &storage.entry,
                       BBP_V2_MAX_ENTRIES + 1u,
                       (size_t *)(void *)&storage.entry) ==
          BBP_V2_ERR_COUNT,
          "unbounded descriptor count is rejected without inspecting sources");
    CHECK(memcmp(storage.bytes, before, sizeof(before)) == 0,
          "count rejection leaves potentially aliased written unchanged");

    entries = &(struct bbp_v2_build_entry){
        UINT64_C(0x1234), 0, 1, 8, source.bytes, SIZE_MAX
    };
    CHECK(bbp_v2_build(storage.bytes, sizeof(storage.bytes), entries, 1,
                       (size_t *)(void *)source.bytes) ==
          BBP_V2_ERR_OVERFLOW,
          "wrapping payload source is rejected before clearing written");
    CHECK(memcmp(source.bytes, source_before, sizeof(source_before)) == 0,
          "wrapping payload rejection leaves source metadata unchanged");

    entries = &(struct bbp_v2_build_entry){
        UINT64_C(0x1234), 0, 1, 8, source.bytes, sizeof(source.bytes)
    };
    written = 123;
    CHECK(bbp_v2_build(NULL, sizeof(storage.bytes), entries, 1, &written) ==
          BBP_V2_ERR_NULL && written == 0,
          "ordinary early failure clears a non-aliased written result");
}

static void fnv_update(void *state, const void *data, size_t size)
{
    uint64_t *h = state;
    const uint8_t *p = data;
    while (size--) {
        *h ^= *p++;
        *h *= UINT64_C(0x100000001b3);
    }
}

static void test_relayout_digest(void)
{
    uint8_t compact[1024], padded[1024];
    struct bbp_v2_view a, b;
    uint64_t ha = UINT64_C(0xcbf29ce484222325);
    uint64_t hb = UINT64_C(0xcbf29ce484222325);
    size_t na = make_capsule(compact, sizeof(compact), 1);
    size_t nb = make_capsule(padded, sizeof(padded), 128);

    CHECK(na != nb, "test capsules use different physical layouts");
    CHECK(bbp_v2_parse(compact, na, &a) == BBP_V2_OK &&
          bbp_v2_parse(padded, nb, &b) == BBP_V2_OK,
          "both layouts parse");
    CHECK(bbp_v2_digest(&a, fnv_update, &ha) == BBP_V2_OK &&
          bbp_v2_digest(&b, fnv_update, &hb) == BBP_V2_OK && ha == hb,
          "canonical digest stream is layout-independent");
}

static const void *identity_map(void *user, bbp_phys_t address, size_t size)
{
    (void)user;
    (void)size;
    return (const void *)(uintptr_t)address;
}

static unsigned map_calls;

static const void *counting_map(void *user, bbp_phys_t address, size_t size)
{
    (void)user;
    (void)address;
    (void)size;
    map_calls++;
    return NULL;
}

struct bounded_map_context {
    const uint8_t *base;
    size_t size;
    unsigned unexpected;
};

static const void *bounded_map(void *user, bbp_phys_t address, size_t size)
{
    struct bounded_map_context *context =
        (struct bounded_map_context *)user;
    uintptr_t base = (uintptr_t)context->base;
    uintptr_t requested = (uintptr_t)address;

    if (requested < base || size > context->size ||
        requested - base > context->size - size) {
        context->unexpected++;
        return NULL;
    }
    return (const void *)requested;
}

static void test_bridge_roundtrip_and_policy(void)
{
    uint8_t v1[2048], v2[4096], back[2048], before[4096];
    struct bbp_info *info = (struct bbp_info *)v1;
    struct bbp_builder builder;
    struct bbp_v2_bridge_workspace workspace;
    struct bbp_v2_bridge_report report;
    struct bbp_v2_v1_source source;
    struct bbp_v2_view view;
    struct bbp_kctx kernel;
    size_t v2_size = 0, back_size = 0;

    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    {
        struct bbp_tag_hhdm *tag = bbp_alloc_tag(
            &builder, BBP_TAG_HHDM, 1, sizeof(*tag));
        tag->offset = 0;
    }
    info->architecture = BBP_ARCH_X86_64;
    info->cpu_count = 4;
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    source.info = info;
    source.map = identity_map;
    source.map_user = NULL;

    CHECK(bbp_v2_from_v1(&source, 0, &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_OK,
          "bounded v1 to v2 bridge succeeds");
    CHECK(report.tag_count == 1 && report.external_reference_entries == 0,
          "bridge report describes normalized input");
    CHECK(bbp_v2_parse(v2, v2_size, &view) == BBP_V2_OK,
          "bridged v2 capsule parses");
    CHECK(bbp_v2_to_v1(&view, 0, back, sizeof(back),
                       (bbp_phys_t)(uintptr_t)back, &back_size,
                       &report) == BBP_V2_OK,
          "bounded v2 to v1 bridge succeeds");
    CHECK(back_size >= sizeof(struct bbp_info) &&
          bbp_init(&kernel, (const struct bbp_info *)back) == BBP_OK,
          "round-tripped v1 handoff validates");
    CHECK(kernel.info->cpu_count == 4 &&
          bbp_find_tag(&kernel, BBP_TAG_HHDM) != NULL,
          "bridge roundtrip preserves info and tag semantics");

    /* CMDLINE's string is an out-of-line physical reference. Default policy
     * must reject it without touching the destination; explicit opt-in marks
     * the preserved reference in the v2 directory. */
    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    {
        struct bbp_tag_cmdline *tag = bbp_alloc_tag(
            &builder, BBP_TAG_CMDLINE, 1, sizeof(*tag));
        uint32_t length;
        tag->string = bbp_arena_strdup(&builder, "safe", &length);
        tag->length = length;
        tag->string_crc = bbp_crc64("safe", 4);
    }
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    memset(v2, 0xa5, sizeof(v2));
    memcpy(before, v2, sizeof(v2));
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_ERR_POLICY,
          "bridge rejects out-of-line physical references by default");
    CHECK(memcmp(v2, before, sizeof(v2)) == 0,
          "bridge failure leaves destination unchanged");
    CHECK(bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_OK &&
          report.external_reference_entries == 1,
          "explicit policy preserves and reports external physical refs");
    CHECK(bbp_v2_parse(v2, v2_size, &view) == BBP_V2_OK,
          "external-reference capsule remains structurally valid");
    {
        struct bbp_v2_entry_view entry;
        CHECK(bbp_v2_get_entry(&view, 1, &entry) == BBP_V2_OK &&
              (entry.flags & BBP_V2_EF_EXTERNAL_PHYS) != 0,
              "preserved physical reference is explicitly marked external");
    }
    memcpy(before, v2, v2_size);
    store32(before + BBP_V2_HEADER_SIZE + BBP_V2_DIRENT_SIZE + 8,
            BBP_V2_EF_V1_WIRE);
    reseal(before, v2_size);
    CHECK(bbp_v2_parse(before, v2_size, &view) == BBP_V2_OK &&
          bbp_v2_to_v1(&view, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                       back, sizeof(back), (bbp_phys_t)(uintptr_t)back,
                       &back_size, &report) == BBP_V2_ERR_SOURCE,
          "reverse bridge detects an unmarked physical reference itself");
    CHECK(bbp_v2_parse(v2, v2_size, &view) == BBP_V2_OK,
          "original external-reference capsule remains valid");
    memset(back, 0x5a, sizeof(back));
    memcpy(before, back, sizeof(back));
    CHECK(bbp_v2_to_v1(&view, 0, back, sizeof(back),
                       (bbp_phys_t)(uintptr_t)back, &back_size,
                       &report) == BBP_V2_ERR_POLICY,
          "reverse bridge also requires external-reference opt-in");
    CHECK(memcmp(back, before, sizeof(back)) == 0,
          "reverse bridge policy failure is destination-atomic");
    CHECK(bbp_v2_to_v1(&view, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                       back, sizeof(back), (bbp_phys_t)(uintptr_t)back,
                       &back_size, &report) == BBP_V2_OK &&
          report.external_reference_entries == 1,
          "reverse bridge preserves external refs only after explicit opt-in");

    store16(v1 + 18, BBP_VERSION_MINOR + 1u);
    store64(v1 + 136, 0);
    store64(v1 + 136, crc_skip_field(v1, sizeof(*info), 136));
    CHECK(bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_ERR_SOURCE,
          "v1.1 bridge does not silently downgrade a future v1 minor");

    store16(v1 + 18, BBP_VERSION_MINOR);
    store64(v1 + 120, UINT64_C(1) << 48);
    store64(v1 + 136, 0);
    store64(v1 + 136, crc_skip_field(v1, sizeof(*info), 136));
    source.map = counting_map;
    map_calls = 0;
    CHECK(bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_ERR_SOURCE && map_calls == 0,
          "forward bridge rejects physical addresses at the 2^48 ceiling");
}

static void test_bridge_ownership_controls(void)
{
    uint8_t v1[2048], v2[4096], forged[4096], before[4096];
    struct bbp_info *info = (struct bbp_info *)v1;
    struct bbp_builder builder;
    struct bbp_v2_bridge_workspace workspace;
    struct bbp_v2_bridge_report report;
    struct bbp_v2_v1_source source;
    struct bbp_v2_view view;
    struct bounded_map_context map_context;
    size_t v2_size = 0, written = 0, restored_size = 0;
    union {
        max_align_t alignment;
        struct bbp_v2_bridge_report report;
        size_t written;
        uint8_t bytes[4096];
    } control;
    union {
        max_align_t alignment;
        struct bbp_v2_bridge_workspace workspace;
        uint8_t bytes[sizeof(struct bbp_v2_bridge_workspace)];
    } shared;

    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    {
        struct bbp_tag_hhdm *tag = bbp_alloc_tag(
            &builder, BBP_TAG_HHDM, 1, sizeof(*tag));
        tag->offset = 0;
    }
    info->architecture = BBP_ARCH_X86_64;
    info->cpu_count = 1;
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    source = (struct bbp_v2_v1_source){info, identity_map, NULL};
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, v2, sizeof(v2), &v2_size,
                         &report) == BBP_V2_OK &&
          bbp_v2_parse(v2, v2_size, &view) == BBP_V2_OK,
          "ownership fixture bridges to v2");

    memset(before, 0xa5, sizeof(before));
    memcpy(forged, before, sizeof(forged));
    CHECK(bbp_v2_from_v1(&source, 2u, &workspace, forged, sizeof(forged),
                         &written, &report) == BBP_V2_ERR_POLICY &&
          memcmp(forged, before, sizeof(forged)) == 0,
          "forward bridge rejects unknown policy bits atomically");
    CHECK(bbp_v2_to_v1(&view, 2u, forged, sizeof(forged),
                       (bbp_phys_t)(uintptr_t)forged, &written,
                       &report) == BBP_V2_ERR_POLICY &&
          memcmp(forged, before, sizeof(forged)) == 0,
          "reverse bridge rejects unknown policy bits atomically");

    info->next_context = UINT64_C(0x2000);
    info->checksum = 0;
    info->checksum = crc_skip_field((const uint8_t *)info, sizeof(*info), 136);
    CHECK(bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, forged, sizeof(forged), &written,
                         &report) == BBP_V2_OK &&
          report.external_reference_entries == 1 &&
          bbp_v2_parse(forged, written, &view) == BBP_V2_OK &&
          bbp_v2_to_v1(&view, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                       before, sizeof(before),
                       (bbp_phys_t)(uintptr_t)before, &restored_size,
                       &report) == BBP_V2_OK &&
          report.external_reference_entries == 1 &&
          load64(before + 128) == UINT64_C(0x2000),
          "bridge reports and preserves an external INFO next context");
    info->next_context = 0;
    info->checksum = 0;
    info->checksum = crc_skip_field((const uint8_t *)info, sizeof(*info), 136);

    memcpy(forged, v2, v2_size);
    store32(forged + BBP_V2_HEADER_SIZE + BBP_V2_DIRENT_SIZE + 8,
            BBP_V2_EF_V1_WIRE | BBP_V2_EF_EXTERNAL_PHYS);
    reseal(forged, v2_size);
    CHECK(bbp_v2_parse(forged, v2_size, &view) == BBP_V2_OK &&
          bbp_v2_to_v1(&view, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                       before, sizeof(before),
                       (bbp_phys_t)(uintptr_t)before, &written,
                       &report) == BBP_V2_ERR_SOURCE,
          "reverse bridge rejects a false external marker");

    memcpy(forged, v2, v2_size);
    {
        size_t info_offset = (size_t)load64(
            forged + BBP_V2_HEADER_SIZE + 16);
        forged[info_offset + 92] = 1;
        store64(forged + BBP_V2_HEADER_SIZE + 32,
                bbp_crc64(forged + info_offset,
                          sizeof(struct bbp_v2_v1_info_payload)));
        reseal(forged, v2_size);
    }
    CHECK(bbp_v2_parse(forged, v2_size, &view) == BBP_V2_OK &&
          bbp_v2_to_v1(&view, 0, before, sizeof(before),
                       (bbp_phys_t)(uintptr_t)before, &written,
                       &report) == BBP_V2_ERR_SOURCE,
          "reverse bridge rejects nonzero normalized INFO reserved bytes");

    memset(control.bytes, 0xa5, sizeof(control.bytes));
    memcpy(before, control.bytes, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, control.bytes,
                         sizeof(control.bytes), &written,
                         &control.report) == BBP_V2_ERR_SOURCE &&
          memcmp(control.bytes, before, sizeof(before)) == 0,
          "forward bridge rejects report inside its output");

    memset(control.bytes, 0xa5, sizeof(control.bytes));
    memcpy(before, control.bytes, sizeof(before));
    CHECK(bbp_v2_parse(v2, v2_size, &view) == BBP_V2_OK &&
          bbp_v2_to_v1(&view, 0, control.bytes, sizeof(control.bytes),
                       (bbp_phys_t)(uintptr_t)control.bytes, &written,
                       &control.report) == BBP_V2_ERR_SOURCE &&
          memcmp(control.bytes, before, sizeof(before)) == 0,
          "reverse bridge rejects report inside its output");

    memset(control.bytes, 0xa5, sizeof(control.bytes));
    memcpy(before, control.bytes, sizeof(before));
    CHECK(bbp_v2_to_v1(&view, 0, control.bytes, sizeof(control.bytes),
                       (bbp_phys_t)(uintptr_t)control.bytes,
                       &control.written, &report) == BBP_V2_ERR_SOURCE &&
          memcmp(control.bytes, before, sizeof(before)) == 0,
          "reverse bridge rejects written inside its output");

    memset(control.bytes, 0xa5, sizeof(control.bytes));
    memset(before, 0xa5, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, before, sizeof(before),
                         &control.written,
                         &control.report) == BBP_V2_ERR_SOURCE &&
          memcmp(before, control.bytes, sizeof(before)) == 0,
          "bridge rejects overlapping written and report controls");

    memset(shared.bytes, 0xa5, sizeof(shared.bytes));
    memcpy(before, shared.bytes, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &shared.workspace, shared.bytes,
                         sizeof(before), &written,
                         &report) == BBP_V2_ERR_SOURCE &&
          memcmp(shared.bytes, before, sizeof(before)) == 0,
          "forward bridge rejects workspace inside its output atomically");

    memset(shared.bytes, 0xa5, sizeof(shared.bytes));
    memcpy(shared.bytes, info, sizeof(*info));
    memcpy(forged, shared.bytes, sizeof(*info));
    source.info = (const struct bbp_info *)shared.bytes;
    memset(before, 0xa5, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &shared.workspace, before,
                         sizeof(before), &written,
                         &report) == BBP_V2_ERR_SOURCE &&
          memcmp(shared.bytes, forged, sizeof(*info)) == 0,
          "forward bridge rejects workspace overlapping source INFO");
    source.info = info;

    memset(shared.bytes, 0, sizeof(shared.bytes));
    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, (uint8_t *)&shared.workspace.entries[1],
                     (bbp_phys_t)(uintptr_t)&shared.workspace.entries[1], 128);
    {
        struct bbp_tag_hhdm *tag = bbp_alloc_tag(
            &builder, BBP_TAG_HHDM, 1, sizeof(*tag));
        tag->offset = 0;
    }
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    source.info = info;
    memcpy(forged, &shared.workspace.entries[1],
           sizeof(struct bbp_tag_hhdm));
    memset(before, 0xa5, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &shared.workspace, before,
                         sizeof(before), &written,
                         &report) == BBP_V2_ERR_SOURCE &&
          memcmp(&shared.workspace.entries[1], forged,
                 sizeof(struct bbp_tag_hhdm)) == 0,
          "forward bridge rejects a mapped tag inside its workspace");

    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    {
        struct bbp_tag_hhdm *tag = bbp_alloc_tag(
            &builder, BBP_TAG_HHDM, 1, sizeof(*tag) + 8u);
        tag->offset = 0;
        store64((uint8_t *)tag + sizeof(*tag), UINT64_C(0x12345000));
    }
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    memset(forged, 0xa5, sizeof(forged));
    memcpy(before, forged, sizeof(before));
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, forged, sizeof(forged),
                         &written, &report) == BBP_V2_ERR_POLICY &&
          memcmp(forged, before, sizeof(forged)) == 0,
          "known opaque extensions are conservatively external");
    CHECK(bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, forged, sizeof(forged), &written,
                         &report) == BBP_V2_OK &&
          report.external_reference_entries == 1,
          "explicit policy preserves a marked opaque extension");

    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    {
        struct bbp_tag_pcie *tag = bbp_alloc_tag(
            &builder, BBP_TAG_PCIE, 1,
            sizeof(*tag) + sizeof(struct bbp_pcie_device));
        struct bbp_pcie_device *device =
            (struct bbp_pcie_device *)((uint8_t *)tag + sizeof(*tag));
        tag->device_count = 1;
        device->bar_count = 0;
    }
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, forged, sizeof(forged),
                         &written, &report) == BBP_V2_OK &&
          report.external_reference_entries == 0,
          "pointer-free PCIe topology remains self-contained");
    {
        struct bbp_tag_pcie *tag = (struct bbp_tag_pcie *)(v1 + sizeof(*info));
        struct bbp_pcie_device *device =
            (struct bbp_pcie_device *)((uint8_t *)tag + sizeof(*tag));
        device->bar_count = 1;
        device->bars[0].base = UINT64_C(0x1000);
        tag->header.checksum = 0;
        tag->header.checksum = crc_skip_field(
            (const uint8_t *)tag, tag->header.tag_size, 24);
    }
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, forged, sizeof(forged),
                         &written, &report) == BBP_V2_ERR_POLICY &&
          bbp_v2_from_v1(&source, BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS,
                         &workspace, forged, sizeof(forged), &written,
                         &report) == BBP_V2_OK &&
          report.external_reference_entries == 1,
          "PCIe BAR bases require and receive the external marker");

    memset(v1, 0, sizeof(v1));
    bbp_builder_init(&builder, v1 + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(v1 + sizeof(*info)),
                     sizeof(v1) - sizeof(*info));
    (void)bbp_alloc_tag(&builder, BBP_TAG_HHDM, 1,
                        sizeof(struct bbp_tag_hhdm));
    (void)bbp_alloc_tag(&builder, BBP_TAG_HHDM, 1,
                        sizeof(struct bbp_tag_hhdm));
    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    store64(v1 + sizeof(*info) + 16, UINT64_C(0x1000));
    map_context.base = v1 + sizeof(*info);
    map_context.size = sizeof(v1) - sizeof(*info);
    map_context.unexpected = 0;
    source.map = bounded_map;
    source.map_user = &map_context;
    CHECK(bbp_v2_from_v1(&source, 0, &workspace, forged, sizeof(forged),
                         &written, &report) == BBP_V2_ERR_SOURCE &&
          map_context.unexpected == 0,
          "forward bridge authenticates a tag before following its link");
}

int main(void)
{
    test_layout_and_roundtrip();
    test_truncation_overflow_and_caps();
    test_overlap_alignment_crc_and_padding();
    test_builder_control_aliases();
    test_relayout_digest();
    test_bridge_roundtrip_and_policy();
    test_bridge_ownership_controls();
    printf("BBP v2 selftest: %s (%d failures)\n",
           failures ? "FAILED" : "PASSED", failures);
    return failures != 0;
}
