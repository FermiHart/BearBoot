#include <stdio.h>
#include <string.h>
#include <bbp/bbp_crc64.h>
#include <bbp/bbp_v2_profile.h>

static int failures;
#define CHECK(condition, name) do { \
    if (!(condition)) { printf("FAIL: %s\n", name); failures++; } \
} while (0)

static void store64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8u * i));
}

static void reseal(uint8_t *capsule, size_t size)
{
    store64(capsule + 40, 0);
    store64(capsule + 40, bbp_crc64(capsule, size));
}

static bbp_v2_status_t run(struct bbp_v2_build_entry *entries, uint32_t count)
{
    uint8_t capsule[2048];
    size_t size;
    struct bbp_v2_view view;
    struct bbp_v2_p0_view profile;
    bbp_v2_status_t status = bbp_v2_build(capsule, sizeof(capsule), entries,
                                          count, &size);
    if (status != BBP_V2_OK) return status;
    status = bbp_v2_parse(capsule, size, &view);
    return status != BBP_V2_OK ? status : bbp_v2_p0_validate(&view, &profile);
}

static void test_stale_view_is_rejected(struct bbp_v2_build_entry *entries)
{
    uint8_t capsule[2048];
    struct bbp_v2_build_entry fixture[4];
    size_t size = 0;
    struct bbp_v2_view view;
    struct bbp_v2_entry_view devicetree;
    struct bbp_v2_p0_view profile;
    struct bbp_v2_p0_view before;

    if (bbp_v2_build(capsule, sizeof(capsule), entries, 4, &size) !=
        BBP_V2_OK) {
        CHECK(0, "stale-view fixture builds");
        return;
    }
    if (bbp_v2_parse(capsule, size, &view) != BBP_V2_OK) {
        CHECK(0, "stale-view fixture parses");
        return;
    }
    if (bbp_v2_get_entry(&view, 3, &devicetree) != BBP_V2_OK) {
        CHECK(0, "stale-view Device Tree entry is available");
        return;
    }
    ((uint8_t *)(uintptr_t)devicetree.data)[8] ^= 1u;
    memset(&profile, 0xa5, sizeof(profile));
    before = profile;
    CHECK(bbp_v2_p0_validate(&view, &profile) == BBP_V2_ERR_CRC,
          "Profile 0 reparses and rejects a capsule mutated after parse");
    CHECK(memcmp(&profile, &before, sizeof(profile)) == 0,
          "stale-view rejection leaves Profile 0 output unchanged");

    memcpy(fixture, entries, sizeof(fixture));
    if (bbp_v2_build(capsule, sizeof(capsule), fixture, 4, &size) !=
            BBP_V2_OK || bbp_v2_parse(capsule, size, &view) != BBP_V2_OK) {
        CHECK(0, "structural stale-view fixture is valid");
        return;
    }
    capsule[view.directory_offset + 14] = 1;
    reseal(capsule, size);
    memset(&profile, 0xa5, sizeof(profile));
    before = profile;
    CHECK(bbp_v2_p0_validate(&view, &profile) == BBP_V2_ERR_FORMAT,
          "Profile 0 reparses resealed generic framing");
    CHECK(memcmp(&profile, &before, sizeof(profile)) == 0,
          "generic framing rejection leaves Profile 0 output unchanged");

    fixture[3].alignment = 64;
    if (bbp_v2_build(capsule, sizeof(capsule), fixture, 4, &size) !=
            BBP_V2_OK || bbp_v2_parse(capsule, size, &view) != BBP_V2_OK ||
            bbp_v2_get_entry(&view, 3, &devicetree) != BBP_V2_OK ||
            devicetree.offset == 0 || capsule[devicetree.offset - 1] != 0) {
        CHECK(0, "padding stale-view fixture is valid");
        return;
    }
    capsule[devicetree.offset - 1] = 1;
    reseal(capsule, size);
    memset(&profile, 0xa5, sizeof(profile));
    before = profile;
    CHECK(bbp_v2_p0_validate(&view, &profile) == BBP_V2_ERR_PADDING,
          "Profile 0 reparses resealed generic padding");
    CHECK(memcmp(&profile, &before, sizeof(profile)) == 0,
          "generic padding rejection leaves Profile 0 output unchanged");
}

int main(void)
{
    uint8_t identity[16] = {2, 0, 0, 0, 1};
    uint8_t memory[40] = {
        1, 0, 0, 0, 32, 0, 0, 0,
        0, 0, 0x10, 0, 0, 0, 0, 0,
        0, 0, 0x20, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0,
    };
    uint8_t kernel[16] = {0, 0, 8, 64, 0, 0, 0, 0,
                           0, 0, 8, 64};
    uint8_t devicetree[12] = {0, 0, 0, 0, 4, 0, 0, 0,
                               0xd0, 0x0d, 0xfe, 0xed};
    uint8_t unknown[1] = {7};
    struct bbp_v2_build_entry entries[6] = {
        {BBP_V2_P0_BOOT_IDENTITY, 0, 1, 8, identity, sizeof(identity)},
        {BBP_V2_P0_MEMORY_MAP, 0, 1, 8, memory, sizeof(memory)},
        {BBP_V2_P0_KERNEL_ADDRESS, 0, 1, 8, kernel, sizeof(kernel)},
        {BBP_V2_P0_DEVICETREE, 0, 1, 8, devicetree, sizeof(devicetree)},
        {0xfeed, 0, 9, 1, unknown, sizeof(unknown)},
        {BBP_V2_P0_BOOT_IDENTITY, 0, 1, 8, identity, sizeof(identity)},
    };

    CHECK(run(entries, 4) == BBP_V2_OK, "canonical");
    CHECK(run(entries, 5) == BBP_V2_OK, "unknown");
    CHECK(run(entries, 3) == BBP_V2_ERR_FORMAT, "missing");
    CHECK(run(entries, 6) == BBP_V2_ERR_FORMAT, "duplicate");
    test_stale_view_is_rejected(entries);

    memory[4] = 31;
    CHECK(run(entries, 4) == BBP_V2_ERR_FORMAT, "stride");
    memory[4] = 32;
    memory[16] = memory[17] = memory[18] = 0;
    CHECK(run(entries, 4) == BBP_V2_ERR_FORMAT, "zero-length range");
    memory[17] = 0x20;
    memory[24] = 0;
    CHECK(run(entries, 4) == BBP_V2_ERR_FORMAT, "zero memory type");
    memory[24] = 1;
    memory[36] = 1;
    CHECK(run(entries, 4) == BBP_V2_ERR_FORMAT, "reserved memory field");

    printf("BBP v2 Profile 0: %s\n", failures ? "FAILED" : "PASSED");
    return failures ? 1 : 0;
}
