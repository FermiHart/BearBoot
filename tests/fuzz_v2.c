/* Bounded malformed-input fuzzer for the v2 capsule and Profile 0.
 * SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <bbp/bbp_v2_profile.h>

#define CAPACITY 4096u

static void drive(const uint8_t *data, size_t size)
{
    struct bbp_v2_view view;
    struct bbp_v2_p0_view profile;
    if (bbp_v2_parse(data, size, &view) == BBP_V2_OK) {
        uint32_t i;
        for (i = 0; i < view.entry_count; i++) {
            struct bbp_v2_entry_view entry;
            (void)bbp_v2_get_entry(&view, i, &entry);
        }
        (void)bbp_v2_p0_validate(&view, &profile);
    }
}

static void structured(const uint8_t *data, size_t size)
{
    static uint8_t capsule[CAPACITY];
    static const uint8_t identity_seed[16] = {2, 0, 0, 0, 1};
    static const uint8_t memory_seed[40] = {
        1, 0, 0, 0, 32, 0, 0, 0,
        0, 0, 0x10, 0, 0, 0, 0, 0,
        0, 0, 0x20, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t kernel_seed[16] = {0, 0, 8, 64, 0, 0, 0, 0,
                                             0, 0, 8, 64};
    static const uint8_t dtb_seed[12] = {0, 0, 0, 0, 4, 0, 0, 0,
                                          0xd0, 0x0d, 0xfe, 0xed};
    uint8_t identity[sizeof(identity_seed)], memory[sizeof(memory_seed)];
    uint8_t kernel[sizeof(kernel_seed)], dtb[sizeof(dtb_seed)];
    uint8_t *payloads[] = {identity, memory, kernel, dtb};
    const size_t lengths[] = {sizeof(identity), sizeof(memory),
                              sizeof(kernel), sizeof(dtb)};
    const struct bbp_v2_build_entry entries[] = {
        {BBP_V2_P0_BOOT_IDENTITY, 0, 1, 8, identity, sizeof(identity)},
        {BBP_V2_P0_MEMORY_MAP, 0, 1, 8, memory, sizeof(memory)},
        {BBP_V2_P0_KERNEL_ADDRESS, 0, 1, 8, kernel, sizeof(kernel)},
        {BBP_V2_P0_DEVICETREE, 0, 1, 8, dtb, sizeof(dtb)},
    };
    size_t written = 0;
    size_t i, cursor = 0;
    memcpy(identity, identity_seed, sizeof(identity));
    memcpy(memory, memory_seed, sizeof(memory));
    memcpy(kernel, kernel_seed, sizeof(kernel));
    memcpy(dtb, dtb_seed, sizeof(dtb));
    for (i = 0; i < 4; i++) {
        size_t j;
        for (j = 0; j < lengths[i] && cursor < size; j++, cursor++)
            payloads[i][j] ^= data[cursor];
    }
    if (bbp_v2_build(capsule, sizeof(capsule), entries, 4, &written) != BBP_V2_OK)
        return;
    drive(capsule, written);
}

#ifdef BBP_V2_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    drive(data, size);
    structured(data, size);
    return 0;
}
#else
#include <stdio.h>
int main(void)
{
    uint8_t data[512];
    uint32_t state = 0x42565032u;
    unsigned iteration;
    for (iteration = 0; iteration < 50000; iteration++) {
        size_t i;
        for (i = 0; i < sizeof(data); i++) {
            state = state * 1103515245u + 12345u;
            data[i] = (uint8_t)(state >> 16);
        }
        drive(data, sizeof(data));
        structured(data, sizeof(data));
    }
    puts("BBP v2 fuzz: PASS (50000 raw + structured inputs)");
    return 0;
}
#endif
