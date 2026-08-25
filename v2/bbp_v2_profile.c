/* SPDX-License-Identifier: BSD-3-Clause */
#include <bbp/bbp_v2_profile.h>

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

bbp_v2_status_t bbp_v2_p0_validate(const struct bbp_v2_view *capsule,
                                    struct bbp_v2_p0_view *out)
{
    struct bbp_v2_view checked;
    struct bbp_v2_p0_view result = {0};
    uint32_t seen = 0;
    uint32_t i;
    bbp_v2_status_t status;

    if (!capsule || !out) return BBP_V2_ERR_NULL;
    status = bbp_v2_parse(capsule->data, capsule->total_size, &checked);
    if (status != BBP_V2_OK) return status;
    for (i = 0; i < checked.entry_count; i++) {
        struct bbp_v2_entry_view entry;
        uint32_t bit = 0;

        status = bbp_v2_get_entry(&checked, i, &entry);
        if (status != BBP_V2_OK) return status;
        if (entry.type == BBP_V2_P0_BOOT_IDENTITY) bit = 1u;
        else if (entry.type == BBP_V2_P0_MEMORY_MAP) bit = 2u;
        else if (entry.type == BBP_V2_P0_KERNEL_ADDRESS) bit = 4u;
        else if (entry.type == BBP_V2_P0_DEVICETREE) bit = 8u;
        else continue;

        if ((seen & bit) != 0 || entry.version != BBP_V2_P0_VERSION
            || entry.flags != 0)
            return BBP_V2_ERR_FORMAT;
        seen |= bit;

        if (bit == 1u) {
            if (entry.size != sizeof(struct bbp_v2_p0_identity)
                || get16(entry.data + 2) != 0 || get32(entry.data + 8) != 0
                || get32(entry.data + 12) != 0)
                return BBP_V2_ERR_FORMAT;
            result.architecture = get16(entry.data);
            result.cpu_count = get32(entry.data + 4);
            if (result.architecture == 0 || result.architecture > 4
                || result.cpu_count == 0)
                return BBP_V2_ERR_FORMAT;
        } else if (bit == 2u) {
            uint32_t count, j;
            if (entry.size < sizeof(struct bbp_v2_p0_memory_header))
                return BBP_V2_ERR_FORMAT;
            count = get32(entry.data);
            if (count == 0 || count > 4096
                || get32(entry.data + 4) != BBP_V2_P0_MEMORY_ENTRY_SIZE
                || (uint64_t)count * BBP_V2_P0_MEMORY_ENTRY_SIZE !=
                   entry.size - sizeof(struct bbp_v2_p0_memory_header))
                return BBP_V2_ERR_FORMAT;
            for (j = 0; j < count; j++) {
                const uint8_t *memory = entry.data +
                    sizeof(struct bbp_v2_p0_memory_header) +
                    (size_t)j * BBP_V2_P0_MEMORY_ENTRY_SIZE;
                uint64_t base = get64(memory);
                uint64_t length = get64(memory + 8);
                if (length == 0 || base > UINT64_MAX - length
                    || get32(memory + 16) == 0 || get32(memory + 28) != 0)
                    return BBP_V2_ERR_FORMAT;
            }
            result.memory_entry_count = count;
        } else if (bit == 4u) {
            if (entry.size != sizeof(struct bbp_v2_p0_kernel_address))
                return BBP_V2_ERR_FORMAT;
            result.kernel_physical_base = get64(entry.data);
            result.kernel_virtual_base = get64(entry.data + 8);
            if (result.kernel_physical_base == 0) return BBP_V2_ERR_FORMAT;
        } else {
            uint32_t size;
            if (entry.size <= sizeof(struct bbp_v2_p0_devicetree_header)
                || get32(entry.data) != 0)
                return BBP_V2_ERR_FORMAT;
            size = get32(entry.data + 4);
            if (size != entry.size - 8u) return BBP_V2_ERR_FORMAT;
            result.dtb = entry.data + 8;
            result.dtb_size = size;
        }
    }
    if (seen != 15u) return BBP_V2_ERR_FORMAT;
    *out = result;
    return BBP_V2_OK;
}
