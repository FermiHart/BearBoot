/*
 * uefi_exit.h - firmware-independent ExitBootServices state machine.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BBP_UEFI_EXIT_H
#define BBP_UEFI_EXIT_H

#include <stddef.h>
#include <stdint.h>

#define BBP_UEFI_EXIT_DESCRIPTOR_SLACK 8u
#define BBP_UEFI_EXIT_MAX_ATTEMPTS 8u

typedef enum bbp_uefi_firmware_status {
    BBP_UEFI_FIRMWARE_SUCCESS = 0,
    BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL,
    BBP_UEFI_FIRMWARE_INVALID_PARAMETER,
    BBP_UEFI_FIRMWARE_ERROR
} bbp_uefi_firmware_status;

typedef bbp_uefi_firmware_status (*bbp_uefi_get_memory_map_fn)(
    void *context, size_t *memory_map_size, void *memory_map,
    uintptr_t *map_key, size_t *descriptor_size,
    uint32_t *descriptor_version);

typedef bbp_uefi_firmware_status (*bbp_uefi_exit_boot_services_fn)(
    void *context, void *image_handle, uintptr_t map_key);

typedef void *(*bbp_uefi_allocate_fn)(void *context, size_t size);
typedef void (*bbp_uefi_free_fn)(void *context, void *allocation);

struct bbp_uefi_exit_ops {
    void *context;
    bbp_uefi_get_memory_map_fn get_memory_map;
    bbp_uefi_exit_boot_services_fn exit_boot_services;
    bbp_uefi_allocate_fn allocate;
    bbp_uefi_free_fn free;
};

typedef enum bbp_uefi_exit_status {
    BBP_UEFI_EXIT_OK = 0,
    BBP_UEFI_EXIT_ERR_ARGUMENT,
    BBP_UEFI_EXIT_ERR_PROBE,
    BBP_UEFI_EXIT_ERR_OVERFLOW,
    BBP_UEFI_EXIT_ERR_ALLOCATION,
    BBP_UEFI_EXIT_ERR_MEMORY_MAP,
    BBP_UEFI_EXIT_ERR_EXIT_BOOT_SERVICES,
    BBP_UEFI_EXIT_ERR_RETRY_LIMIT
} bbp_uefi_exit_status;

struct bbp_uefi_exit_result {
    void *memory_map;
    size_t memory_map_size;
    size_t memory_map_capacity;
    uintptr_t map_key;
    size_t descriptor_size;
    uint32_t descriptor_version;
    uint8_t memory_map_final;
};

/* On success the map allocation is retained for the post-EBS handoff. */
bbp_uefi_exit_status bbp_uefi_exit_boot_services(
    const struct bbp_uefi_exit_ops *ops, void *image_handle,
    struct bbp_uefi_exit_result *result);

#endif /* BBP_UEFI_EXIT_H */
