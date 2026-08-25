/* Bounded experimental BBP v2 Profile 0 producer/consumer roundtrip. */
#include <stdint.h>
#include <stdio.h>

#include <bbp/bbp_v2.h>
#include <bbp/bbp_v2_profile.h>

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8u * i));
}

static void put64(uint8_t *p, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8u * i));
}

int main(void)
{
    uint8_t identity[16] = {0};
    uint8_t memory[40] = {0};
    uint8_t kernel[16] = {0};
    uint8_t devicetree[12] = {0};
    uint8_t capsule[1024];
    struct bbp_v2_build_entry entries[4];
    struct bbp_v2_view view;
    struct bbp_v2_p0_view profile;
    size_t written = 0;

    put16(identity, 2); /* AArch64. */
    put32(identity + 4, 1);
    put32(memory, 1);
    put32(memory + 4, BBP_V2_P0_MEMORY_ENTRY_SIZE);
    put64(memory + 8, 0x100000);
    put64(memory + 16, 0x200000);
    put32(memory + 24, 1);
    put64(kernel, 0x40080000);
    put64(kernel + 8, 0xffffffff80000000ull);
    put32(devicetree + 4, 4);
    devicetree[8] = 0xd0;
    devicetree[9] = 0x0d;
    devicetree[10] = 0xfe;
    devicetree[11] = 0xed;

    entries[0] = (struct bbp_v2_build_entry){
        BBP_V2_P0_BOOT_IDENTITY, 0, BBP_V2_P0_VERSION, 8,
        identity, sizeof(identity)
    };
    entries[1] = (struct bbp_v2_build_entry){
        BBP_V2_P0_MEMORY_MAP, 0, BBP_V2_P0_VERSION, 8,
        memory, sizeof(memory)
    };
    entries[2] = (struct bbp_v2_build_entry){
        BBP_V2_P0_KERNEL_ADDRESS, 0, BBP_V2_P0_VERSION, 8,
        kernel, sizeof(kernel)
    };
    entries[3] = (struct bbp_v2_build_entry){
        BBP_V2_P0_DEVICETREE, 0, BBP_V2_P0_VERSION, 8,
        devicetree, sizeof(devicetree)
    };

    if (bbp_v2_build(capsule, sizeof(capsule), entries, 4, &written) !=
            BBP_V2_OK ||
        written > sizeof(capsule) ||
        bbp_v2_parse(capsule, written, &view) != BBP_V2_OK ||
        bbp_v2_p0_validate(&view, &profile) != BBP_V2_OK ||
        profile.architecture != 2 || profile.cpu_count != 1 ||
        profile.memory_entry_count != 1 || profile.dtb_size != 4 ||
        bbp_v2_parse(capsule, written - 1, &view) == BBP_V2_OK) {
        fputs("BBP v2 Profile 0 roundtrip: FAIL\n", stderr);
        return 1;
    }

    puts("BBP v2 Profile 0 roundtrip: PASS");
    return 0;
}
