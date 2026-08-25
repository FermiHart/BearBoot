/* Dependency-free UEFI TCG2 declarations and bounded TPM2 wire helpers. */
#ifndef BBP_UEFI_TCG2_H
#define BBP_UEFI_TCG2_H

#include <stddef.h>
#include <stdint.h>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define BBP_EFIAPI __attribute__((ms_abi))
#else
#define BBP_EFIAPI
#endif

#define BBP_EFI_SUCCESS 0u

#define BBP_EFI_TCG2_BOOT_HASH_ALG_SHA256 0x00000002u
#define BBP_EFI_TCG2_EXTEND_ONLY          0x0000000000000001ULL
#define BBP_EFI_TCG2_EVENT_HEADER_VERSION 1u
#define BBP_EFI_TCG2_EV_EFI_ACTION        0x80000007u

#define BBP_TPM2_ALG_SHA256       0x000bu
#define BBP_TPM2_PCR_READ_COMMAND 0x0000017eu
#define BBP_TPM2_ST_NO_SESSIONS   0x8001u
#define BBP_TPM2_SHA256_BYTES     32u
#define BBP_TPM2_MAX_PCR          23u

struct bbp_efi_guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

struct bbp_efi_tcg2_version {
    uint8_t major;
    uint8_t minor;
};

struct bbp_efi_tcg2_capability {
    uint8_t size;
    struct bbp_efi_tcg2_version structure_version;
    struct bbp_efi_tcg2_version protocol_version;
    uint32_t hash_algorithm_bitmap;
    uint32_t supported_event_logs;
    uint8_t tpm_present;
    uint16_t max_command_size;
    uint16_t max_response_size;
    uint32_t manufacturer_id;
    uint32_t number_of_pcr_banks;
    uint32_t active_pcr_banks;
};

#pragma pack(push, 1)
struct bbp_efi_tcg2_event_header {
    uint32_t header_size;
    uint16_t header_version;
    uint32_t pcr_index;
    uint32_t event_type;
};

struct bbp_efi_tcg2_event {
    uint32_t size;
    struct bbp_efi_tcg2_event_header header;
    uint8_t event[1];
};
#pragma pack(pop)

struct bbp_efi_tcg2_protocol;

typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_get_capability_fn)(
    struct bbp_efi_tcg2_protocol *, struct bbp_efi_tcg2_capability *);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_get_event_log_fn)(
    struct bbp_efi_tcg2_protocol *, uint32_t, uint64_t *, uint64_t *, uint8_t *);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_hash_log_extend_event_fn)(
    struct bbp_efi_tcg2_protocol *, uint64_t, uint64_t, uint64_t,
    struct bbp_efi_tcg2_event *);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_submit_command_fn)(
    struct bbp_efi_tcg2_protocol *, uint32_t, uint8_t *, uint32_t, uint8_t *);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_get_active_pcr_banks_fn)(
    struct bbp_efi_tcg2_protocol *, uint32_t *);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_set_active_pcr_banks_fn)(
    struct bbp_efi_tcg2_protocol *, uint32_t);
typedef uint64_t (BBP_EFIAPI *bbp_efi_tcg2_get_result_fn)(
    struct bbp_efi_tcg2_protocol *, uint32_t *, uint32_t *);

struct bbp_efi_tcg2_protocol {
    bbp_efi_tcg2_get_capability_fn get_capability;
    bbp_efi_tcg2_get_event_log_fn get_event_log;
    bbp_efi_tcg2_hash_log_extend_event_fn hash_log_extend_event;
    bbp_efi_tcg2_submit_command_fn submit_command;
    bbp_efi_tcg2_get_active_pcr_banks_fn get_active_pcr_banks;
    bbp_efi_tcg2_set_active_pcr_banks_fn set_active_pcr_banks;
    bbp_efi_tcg2_get_result_fn get_result_of_set_active_pcr_banks;
};

typedef enum {
    BBP_TCG2_WIRE_OK = 0,
    BBP_TCG2_WIRE_ARGUMENT,
    BBP_TCG2_WIRE_CAPACITY,
    BBP_TCG2_WIRE_PCR,
    BBP_TCG2_WIRE_TRUNCATED,
    BBP_TCG2_WIRE_SIZE,
    BBP_TCG2_WIRE_TAG,
    BBP_TCG2_WIRE_RESPONSE_CODE,
    BBP_TCG2_WIRE_COUNT,
    BBP_TCG2_WIRE_ALGORITHM,
    BBP_TCG2_WIRE_SELECTION,
    BBP_TCG2_WIRE_DIGEST_SIZE,
    BBP_TCG2_WIRE_TRAILING
} bbp_tcg2_wire_status;

int bbp_tcg2_sha256(const void *data, size_t bytes,
                    uint8_t digest[BBP_TPM2_SHA256_BYTES]);
void bbp_tcg2_sha256_extend(
    const uint8_t before[BBP_TPM2_SHA256_BYTES],
    const uint8_t digest[BBP_TPM2_SHA256_BYTES],
    uint8_t after[BBP_TPM2_SHA256_BYTES]);

bbp_tcg2_wire_status bbp_tcg2_build_pcr_read(
    uint32_t pcr_index, uint8_t *output, size_t capacity, size_t *output_bytes);
bbp_tcg2_wire_status bbp_tcg2_parse_pcr_read_response(
    const uint8_t *response, size_t response_bytes, uint32_t expected_pcr,
    uint8_t digest[BBP_TPM2_SHA256_BYTES], uint32_t *update_counter);
const char *bbp_tcg2_wire_strstatus(bbp_tcg2_wire_status status);

#endif
