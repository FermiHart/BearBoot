/* Hosted state-machine tests; no UEFI headers or firmware are required. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../bootloader/uefi/uefi_exit.h"

static int failures;

#define CHECK(condition, message) do { \
    if (!(condition)) { printf("FAIL: %s\n", (message)); failures++; } \
    else printf("ok:   %s\n", (message)); \
} while (0)

enum mock_scenario {
    MOCK_SUCCESS,
    MOCK_GROW,
    MOCK_INVALID_ONCE,
    MOCK_ALWAYS_INVALID,
    MOCK_GET_ERROR,
    MOCK_EXIT_ERROR,
    MOCK_PROBE_SUCCESS,
    MOCK_ALLOCATE_ERROR,
    MOCK_OVERFLOW
};

union mock_block {
    max_align_t alignment;
    uint8_t bytes[2048];
};

struct mock_firmware {
    enum mock_scenario scenario;
    size_t probe_size;
    size_t probe_descriptor_size;
    unsigned probe_calls;
    unsigned map_calls;
    unsigned exit_calls;
    unsigned allocate_calls;
    unsigned free_calls;
    unsigned callbacks_after_success;
    int probe_contract_broken;
    int exited;
    size_t allocation_sizes[2];
    union mock_block blocks[2];
};

static void mock_init(struct mock_firmware *mock, enum mock_scenario scenario)
{
    memset(mock, 0, sizeof(*mock));
    mock->scenario = scenario;
    mock->probe_size = 96u;
    mock->probe_descriptor_size = 48u;
}

static void note_callback(struct mock_firmware *mock)
{
    if (mock->exited) mock->callbacks_after_success++;
}

static void *mock_allocate(void *context, size_t size)
{
    struct mock_firmware *mock = context;
    unsigned slot;
    note_callback(mock);
    slot = mock->allocate_calls++;
    if (slot < 2u) mock->allocation_sizes[slot] = size;
    if (mock->scenario == MOCK_ALLOCATE_ERROR || slot >= 2u ||
        size > sizeof(mock->blocks[slot].bytes)) return NULL;
    return mock->blocks[slot].bytes;
}

static void mock_free(void *context, void *allocation)
{
    struct mock_firmware *mock = context;
    note_callback(mock);
    if (allocation != NULL) mock->free_calls++;
}

static bbp_uefi_firmware_status mock_get_memory_map(
    void *context, size_t *memory_map_size, void *memory_map,
    uintptr_t *map_key, size_t *descriptor_size,
    uint32_t *descriptor_version)
{
    struct mock_firmware *mock = context;
    size_t exact_size;
    note_callback(mock);
    if (memory_map == NULL) {
        mock->probe_calls++;
        if (*memory_map_size != 0u) mock->probe_contract_broken = 1;
        *memory_map_size = mock->probe_size;
        *descriptor_size = mock->probe_descriptor_size;
        *descriptor_version = 1u;
        if (mock->scenario == MOCK_PROBE_SUCCESS)
            return BBP_UEFI_FIRMWARE_SUCCESS;
        return BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL;
    }

    mock->map_calls++;
    if (mock->scenario == MOCK_GROW && mock->map_calls == 1u) {
        *memory_map_size = 600u;
        *descriptor_size = 64u;
        return BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL;
    }
    if (mock->scenario == MOCK_GET_ERROR)
        return BBP_UEFI_FIRMWARE_ERROR;

    exact_size = (mock->scenario == MOCK_INVALID_ONCE &&
                  mock->map_calls == 2u) ? 144u : 96u;
    if (*memory_map_size < exact_size) {
        *memory_map_size = exact_size;
        *descriptor_size = 48u;
        return BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL;
    }
    memset(memory_map, (int)mock->map_calls, exact_size);
    *memory_map_size = exact_size;
    *map_key = (uintptr_t)(1000u + mock->map_calls);
    *descriptor_size = 48u;
    *descriptor_version = 7u;
    return BBP_UEFI_FIRMWARE_SUCCESS;
}

static bbp_uefi_firmware_status mock_exit_boot_services(
    void *context, void *image_handle, uintptr_t map_key)
{
    struct mock_firmware *mock = context;
    (void)image_handle;
    (void)map_key;
    note_callback(mock);
    mock->exit_calls++;
    if (mock->scenario == MOCK_ALWAYS_INVALID ||
        (mock->scenario == MOCK_INVALID_ONCE && mock->exit_calls == 1u))
        return BBP_UEFI_FIRMWARE_INVALID_PARAMETER;
    if (mock->scenario == MOCK_EXIT_ERROR)
        return BBP_UEFI_FIRMWARE_ERROR;
    mock->exited = 1;
    return BBP_UEFI_FIRMWARE_SUCCESS;
}

static struct bbp_uefi_exit_ops mock_ops(struct mock_firmware *mock)
{
    struct bbp_uefi_exit_ops ops;
    ops.context = mock;
    ops.get_memory_map = mock_get_memory_map;
    ops.exit_boot_services = mock_exit_boot_services;
    ops.allocate = mock_allocate;
    ops.free = mock_free;
    return ops;
}

static void test_success(void)
{
    struct mock_firmware mock;
    struct bbp_uefi_exit_ops ops;
    struct bbp_uefi_exit_result result;
    bbp_uefi_exit_status status;

    mock_init(&mock, MOCK_SUCCESS);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, (void *)(uintptr_t)1u, &result);
    CHECK(status == BBP_UEFI_EXIT_OK, "valid map exits boot services");
    CHECK(mock.probe_calls == 1u && !mock.probe_contract_broken,
          "first GetMemoryMap call is a zero-size NULL probe");
    CHECK(mock.allocation_sizes[0] == 96u + 8u * 48u,
          "probe allocation includes descriptor slack");
    CHECK(result.memory_map == mock.blocks[0].bytes &&
          result.memory_map_size == 96u && result.map_key == 1001u,
          "successful map pointer, exact size, and key are published");
    CHECK(result.memory_map_capacity == 480u &&
          result.descriptor_size == 48u && result.descriptor_version == 7u,
          "successful descriptor metadata and capacity are published");
    CHECK(result.memory_map_final == 1u,
          "final flag is set only by successful EBS completion");
    CHECK(mock.free_calls == 0u && mock.callbacks_after_success == 0u,
          "success performs no later allocation or firmware callback");
}

static void test_growth_and_stale_key(void)
{
    struct mock_firmware mock;
    struct bbp_uefi_exit_ops ops;
    struct bbp_uefi_exit_result result;
    bbp_uefi_exit_status status;

    mock_init(&mock, MOCK_GROW);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_OK && mock.allocate_calls == 2u &&
          mock.free_calls == 1u,
          "BUFFER_TOO_SMALL reacquires with a replacement map buffer");
    CHECK(mock.allocation_sizes[1] == 600u + 8u * 64u,
          "map growth uses updated descriptor slack");

    mock_init(&mock, MOCK_INVALID_ONCE);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_OK && mock.map_calls == 2u &&
          mock.exit_calls == 2u,
          "INVALID_PARAMETER reacquires the map and retries EBS");
    CHECK(result.memory_map_size == 144u && result.map_key == 1002u &&
          ((const uint8_t *)result.memory_map)[0] == 2u,
          "retry publishes only the exact successful reacquisition");
}

static void test_terminal_failures_are_atomic(void)
{
    struct mock_firmware mock;
    struct bbp_uefi_exit_ops ops;
    struct bbp_uefi_exit_result result;
    struct bbp_uefi_exit_result before;
    bbp_uefi_exit_status status;

    mock_init(&mock, MOCK_GET_ERROR);
    ops = mock_ops(&mock);
    memset(&result, 0xa5, sizeof(result));
    before = result;
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_MEMORY_MAP && mock.map_calls == 1u &&
          mock.exit_calls == 0u && mock.free_calls == 1u,
          "non-retryable GetMemoryMap error fails and releases scratch");
    CHECK(memcmp(&result, &before, sizeof(result)) == 0,
          "GetMemoryMap failure leaves every output byte unchanged");

    mock_init(&mock, MOCK_EXIT_ERROR);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_EXIT_BOOT_SERVICES &&
          mock.exit_calls == 1u && mock.map_calls == 1u &&
          mock.free_calls == 1u,
          "non-retryable EBS error is not retried");
    CHECK(result.memory_map_final == 0u,
          "failed EBS never marks the map final");

    mock_init(&mock, MOCK_PROBE_SUCCESS);
    ops = mock_ops(&mock);
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_PROBE && mock.allocate_calls == 0u,
          "size probe must report BUFFER_TOO_SMALL");
}

static void test_retry_cap_and_overflow(void)
{
    struct mock_firmware mock;
    struct bbp_uefi_exit_ops ops;
    struct bbp_uefi_exit_result result;
    bbp_uefi_exit_status status;

    mock_init(&mock, MOCK_ALWAYS_INVALID);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_RETRY_LIMIT &&
          mock.map_calls == BBP_UEFI_EXIT_MAX_ATTEMPTS &&
          mock.exit_calls == BBP_UEFI_EXIT_MAX_ATTEMPTS,
          "stale map keys stop at the bounded retry cap");
    CHECK(mock.free_calls == 1u && result.memory_map_final == 0u,
          "retry exhaustion releases scratch without publishing a final map");

    mock_init(&mock, MOCK_OVERFLOW);
    mock.probe_size = (size_t)-32;
    mock.probe_descriptor_size = 48u;
    ops = mock_ops(&mock);
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_OVERFLOW && mock.allocate_calls == 0u,
          "descriptor slack addition overflow is rejected before allocation");

    mock_init(&mock, MOCK_OVERFLOW);
    mock.probe_size = 1u;
    mock.probe_descriptor_size = (size_t)-1;
    ops = mock_ops(&mock);
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_OVERFLOW && mock.allocate_calls == 0u,
          "descriptor slack multiplication overflow is rejected");
}

static void test_argument_and_allocation_failures(void)
{
    struct mock_firmware mock;
    struct bbp_uefi_exit_ops ops;
    struct bbp_uefi_exit_result result;
    bbp_uefi_exit_status status;

    mock_init(&mock, MOCK_ALLOCATE_ERROR);
    ops = mock_ops(&mock);
    memset(&result, 0, sizeof(result));
    status = bbp_uefi_exit_boot_services(&ops, NULL, &result);
    CHECK(status == BBP_UEFI_EXIT_ERR_ALLOCATION && mock.map_calls == 0u,
          "allocation failure stops before map acquisition");
    CHECK(bbp_uefi_exit_boot_services(NULL, NULL, &result) ==
          BBP_UEFI_EXIT_ERR_ARGUMENT,
          "NULL callback table is rejected");
    ops.free = NULL;
    CHECK(bbp_uefi_exit_boot_services(&ops, NULL, &result) ==
          BBP_UEFI_EXIT_ERR_ARGUMENT,
          "incomplete callback table is rejected");
}

int main(void)
{
    printf("== UEFI ExitBootServices state-machine self-test ==\n");
    test_success();
    test_growth_and_stale_key();
    test_terminal_failures_are_atomic();
    test_retry_cap_and_overflow();
    test_argument_and_allocation_failures();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
