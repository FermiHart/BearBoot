/*
 * uefi_exit.c - bounded ExitBootServices map-key state machine.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "uefi_exit.h"

static int map_capacity(size_t required, size_t descriptor_size,
                        size_t *capacity)
{
    const size_t size_max = (size_t)-1;
    size_t slack;

    if (descriptor_size == 0u ||
        descriptor_size > size_max / BBP_UEFI_EXIT_DESCRIPTOR_SLACK)
        return 0;
    slack = descriptor_size * BBP_UEFI_EXIT_DESCRIPTOR_SLACK;
    if (required > size_max - slack) return 0;
    *capacity = required + slack;
    return 1;
}

bbp_uefi_exit_status bbp_uefi_exit_boot_services(
    const struct bbp_uefi_exit_ops *ops, void *image_handle,
    struct bbp_uefi_exit_result *result)
{
    struct bbp_uefi_exit_result completed = {0};
    bbp_uefi_firmware_status firmware_status;
    size_t map_size = 0u;
    size_t descriptor_size = 0u;
    size_t capacity;
    uintptr_t map_key = 0u;
    uint32_t descriptor_version = 0u;
    void *memory_map;
    unsigned attempt;

    if (ops == NULL || result == NULL || ops->get_memory_map == NULL ||
        ops->exit_boot_services == NULL || ops->allocate == NULL ||
        ops->free == NULL)
        return BBP_UEFI_EXIT_ERR_ARGUMENT;

    firmware_status = ops->get_memory_map(
        ops->context, &map_size, NULL, &map_key, &descriptor_size,
        &descriptor_version);
    if (firmware_status != BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL)
        return BBP_UEFI_EXIT_ERR_PROBE;
    if (!map_capacity(map_size, descriptor_size, &capacity))
        return BBP_UEFI_EXIT_ERR_OVERFLOW;

    memory_map = ops->allocate(ops->context, capacity);
    if (memory_map == NULL) return BBP_UEFI_EXIT_ERR_ALLOCATION;

    for (attempt = 0u; attempt < BBP_UEFI_EXIT_MAX_ATTEMPTS; attempt++) {
        map_size = capacity;
        firmware_status = ops->get_memory_map(
            ops->context, &map_size, memory_map, &map_key,
            &descriptor_size, &descriptor_version);

        if (firmware_status == BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL) {
            size_t larger_capacity;
            if (!map_capacity(map_size, descriptor_size, &larger_capacity)) {
                ops->free(ops->context, memory_map);
                return BBP_UEFI_EXIT_ERR_OVERFLOW;
            }
            ops->free(ops->context, memory_map);
            capacity = larger_capacity;
            memory_map = ops->allocate(ops->context, capacity);
            if (memory_map == NULL) return BBP_UEFI_EXIT_ERR_ALLOCATION;
            continue;
        }
        if (firmware_status != BBP_UEFI_FIRMWARE_SUCCESS ||
            descriptor_size == 0u || map_size > capacity) {
            ops->free(ops->context, memory_map);
            return BBP_UEFI_EXIT_ERR_MEMORY_MAP;
        }

        firmware_status = ops->exit_boot_services(
            ops->context, image_handle, map_key);
        if (firmware_status == BBP_UEFI_FIRMWARE_SUCCESS) {
            completed.memory_map = memory_map;
            completed.memory_map_size = map_size;
            completed.memory_map_capacity = capacity;
            completed.map_key = map_key;
            completed.descriptor_size = descriptor_size;
            completed.descriptor_version = descriptor_version;
            completed.memory_map_final = 1u;
            *result = completed;
            return BBP_UEFI_EXIT_OK;
        }
        if (firmware_status != BBP_UEFI_FIRMWARE_INVALID_PARAMETER) {
            ops->free(ops->context, memory_map);
            return BBP_UEFI_EXIT_ERR_EXIT_BOOT_SERVICES;
        }
    }

    ops->free(ops->context, memory_map);
    return BBP_UEFI_EXIT_ERR_RETRY_LIMIT;
}
