/* Real OVMF EFI_TCG2_PROTOCOL + swtpm + BBP SECURITY machine proof. */
#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"
#include "../experimental/firmware/uefi/bbp_security_collector.h"
#include "../experimental/firmware/uefi/tcg2/bbp_uefi_tcg2.h"

typedef void *efi_handle_t;
typedef uint64_t efi_status_t;

struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
};

typedef efi_status_t (*efi_locate_protocol_fn)(
    struct bbp_efi_guid *, void *, void **);

struct efi_boot_services {
    struct efi_table_header header;
    void *services_before_locate_protocol[37];
    efi_locate_protocol_fn locate_protocol;
};

struct efi_system_table {
    struct efi_table_header header;
    uint16_t *firmware_vendor;
    uint32_t firmware_revision;
    uint32_t padding;
    efi_handle_t console_in_handle;
    void *console_in;
    efi_handle_t console_out_handle;
    void *console_out;
    efi_handle_t standard_error_handle;
    void *standard_error;
    void *runtime_services;
    struct efi_boot_services *boot_services;
    size_t configuration_table_entries;
    void *configuration_table;
};

_Static_assert(offsetof(struct efi_boot_services, locate_protocol) == 320u,
               "UEFI LocateProtocol offset");
_Static_assert(offsetof(struct efi_system_table, boot_services) == 96u,
               "UEFI BootServices offset");
_Static_assert(sizeof(struct bbp_efi_tcg2_capability) == 36u,
               "UEFI TCG2 capability ABI");
_Static_assert(sizeof(struct bbp_efi_tcg2_event_header) == 14u,
               "UEFI TCG2 event header ABI");

#define PCR_INDEX 16u
#define TPM_TIS_BASE 0xfed40000ULL
#define ARENA_BYTES (64u * 1024u)

static const uint8_t evidence[] =
    "BearBoot Wave 18 real OVMF TCG2 PCR16 machine proof v1";
static const uint8_t component_name[] = "wave18-ovmf-tcg2";
static uint8_t arena[ARENA_BYTES] __attribute__((aligned(16)));
static uint8_t guest_exit = 0x11u;

struct tcg2_context {
    struct bbp_efi_tcg2_protocol *protocol;
};

#pragma pack(push, 1)
struct proof_event {
    uint32_t size;
    struct bbp_efi_tcg2_event_header header;
    uint8_t event[sizeof(evidence) - 1u];
};
#pragma pack(pop)

static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile("outb %0,%1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t value;
    __asm__ volatile("inb %1,%0" : "=a"(value) : "Nd"(port));
    return value;
}

static void serial_init(void)
{
    outb(0x3f9u, 0x00u);
    outb(0x3fbu, 0x80u);
    outb(0x3f8u, 0x01u);
    outb(0x3f9u, 0x00u);
    outb(0x3fbu, 0x03u);
    outb(0x3fau, 0xc7u);
    outb(0x3fcu, 0x0bu);
}

static void serial_puts(const char *text)
{
    while (*text != '\0') {
        if (*text == '\n') {
            while ((inb(0x3fdu) & 0x20u) == 0u) { }
            outb(0x3f8u, '\r');
        }
        while ((inb(0x3fdu) & 0x20u) == 0u) { }
        outb(0x3f8u, (uint8_t)*text++);
    }
}

static void serial_hex(const uint8_t *bytes, size_t count)
{
    static const char digits[] = "0123456789abcdef";
    char pair[3];
    pair[2] = '\0';
    while (count-- != 0u) {
        pair[0] = digits[*bytes >> 4];
        pair[1] = digits[*bytes & 0x0fu];
        serial_puts(pair);
        bytes++;
    }
}

static void memory_zero(void *destination, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    while (bytes-- != 0u)
        *d++ = 0u;
}

static void memory_copy(void *destination, const void *source, size_t bytes)
{
    uint8_t *d = (uint8_t *)destination;
    const uint8_t *s = (const uint8_t *)source;
    while (bytes-- != 0u)
        *d++ = *s++;
}

static int memory_equal(const void *left, const void *right, size_t bytes)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    while (bytes-- != 0u) {
        if (*a++ != *b++)
            return 0;
    }
    return 1;
}

__attribute__((noreturn)) static void machine_fail(const char *reason)
{
    guest_exit = 0x11u;
    serial_puts("BBP-UEFI-TCG2: FAIL: ");
    serial_puts(reason);
    serial_puts("\n");
    outb(0xf4u, guest_exit);
    for (;;)
        __asm__ volatile("hlt");
}

static uint32_t response_size(const uint8_t response[10])
{
    return ((uint32_t)response[2] << 24) |
           ((uint32_t)response[3] << 16) |
           ((uint32_t)response[4] << 8) | response[5];
}

static int read_sha256_pcr(struct bbp_efi_tcg2_protocol *protocol,
                           uint8_t digest[32])
{
    uint8_t command[20];
    uint8_t response[128];
    size_t command_bytes = 0u;
    uint32_t update_counter = 0u;
    uint32_t bytes;
    bbp_tcg2_wire_status wire_status;
    efi_status_t status;

    memory_zero(response, sizeof(response));
    wire_status = bbp_tcg2_build_pcr_read(
        PCR_INDEX, command, sizeof(command), &command_bytes);
    if (wire_status != BBP_TCG2_WIRE_OK)
        return -1;
    status = protocol->submit_command(protocol, (uint32_t)command_bytes,
        command, (uint32_t)sizeof(response), response);
    if (status != BBP_EFI_SUCCESS)
        return -1;
    bytes = response_size(response);
    if (bytes < 10u || bytes > sizeof(response))
        return -1;
    wire_status = bbp_tcg2_parse_pcr_read_response(
        response, bytes, PCR_INDEX, digest, &update_counter);
    return wire_status == BBP_TCG2_WIRE_OK ? 0 : -1;
}

static int tcg2_hash_extend(void *opaque, uint32_t pcr_index,
                            uint32_t algorithm, const void *data,
                            size_t data_length, uint8_t digest[32])
{
    struct tcg2_context *context = (struct tcg2_context *)opaque;
    struct proof_event event;
    efi_status_t status;

    if (context == NULL || context->protocol == NULL ||
        pcr_index != PCR_INDEX || algorithm != BBP_HASH_SHA256 ||
        data != evidence || data_length != sizeof(evidence) - 1u)
        return -1;
    if (bbp_tcg2_sha256(data, data_length, digest) != 0)
        return -1;
    memory_zero(&event, sizeof(event));
    event.size = sizeof(event);
    event.header.header_size = sizeof(event.header);
    event.header.header_version = BBP_EFI_TCG2_EVENT_HEADER_VERSION;
    event.header.pcr_index = pcr_index;
    event.header.event_type = BBP_EFI_TCG2_EV_EFI_ACTION;
    memory_copy(event.event, evidence, sizeof(event.event));
    status = context->protocol->hash_log_extend_event(
        context->protocol, BBP_EFI_TCG2_EXTEND_ONLY,
        (uint64_t)(uintptr_t)data, (uint64_t)data_length,
        (struct bbp_efi_tcg2_event *)&event);
    return status == BBP_EFI_SUCCESS ? 0 : -1;
}

__attribute__((noreturn)) static void collector_abort(
    void *opaque, bbp_security_status reason)
{
    (void)opaque;
    (void)reason;
    machine_fail("collector could not publish after irreversible TPM extend");
}

static void print_digest_line(const char *label, const uint8_t digest[32])
{
    serial_puts(label);
    serial_hex(digest, 32u);
    serial_puts("\n");
}

efi_status_t efi_main(efi_handle_t image, struct efi_system_table *system_table)
{
    static struct bbp_efi_guid tcg2_guid = {
        0x607f766cu, 0x7455u, 0x42beu,
        {0x93u, 0x0bu, 0xe4u, 0xd7u, 0x6du, 0xb2u, 0x72u, 0x0fu}
    };
    struct bbp_efi_tcg2_protocol *protocol = NULL;
    struct bbp_efi_tcg2_capability capability;
    struct bbp_security_platform platform;
    struct bbp_security_source source;
    struct bbp_security_callbacks callbacks;
    struct bbp_tag_security *published = NULL;
    struct bbp_builder builder;
    struct bbp_info *info;
    struct bbp_kctx parser;
    const struct bbp_tag_security *parsed;
    const struct bbp_measurement *measurement;
    struct tcg2_context tcg2;
    uint8_t before[32], evidence_digest[32], expected_after[32], after[32];
    efi_status_t status;

    (void)image;
    serial_init();
    serial_puts("BBP-UEFI-TCG2: OVMF entry\n");
    if (system_table == NULL || system_table->boot_services == NULL ||
        system_table->boot_services->locate_protocol == NULL)
        machine_fail("invalid UEFI system table");
    status = system_table->boot_services->locate_protocol(
        &tcg2_guid, NULL, (void **)&protocol);
    if (status != BBP_EFI_SUCCESS || protocol == NULL)
        machine_fail("EFI_TCG2_PROTOCOL not found");
    serial_puts("BBP-UEFI-TCG2: EFI_TCG2_PROTOCOL located\n");

    memory_zero(&capability, sizeof(capability));
    capability.size = sizeof(capability);
    status = protocol->get_capability(protocol, &capability);
    if (status != BBP_EFI_SUCCESS)
        machine_fail("TCG2 GetCapability failed");
    if (capability.size < sizeof(capability) || capability.tpm_present == 0u)
        machine_fail("TCG2 reports no usable TPM2");
    if ((capability.hash_algorithm_bitmap &
         BBP_EFI_TCG2_BOOT_HASH_ALG_SHA256) == 0u ||
        (capability.active_pcr_banks &
         BBP_EFI_TCG2_BOOT_HASH_ALG_SHA256) == 0u)
        machine_fail("SHA-256 PCR bank is not supported and active");
    if (capability.max_command_size < 20u ||
        capability.max_response_size < 62u)
        machine_fail("TCG2 TPM command limits are too small");
    serial_puts("BBP-UEFI-TCG2: TPM2 present, SHA-256 PCR bank active\n");

    if (read_sha256_pcr(protocol, before) != 0)
        machine_fail("bounded pre-extend PCR_Read failed");
    if (bbp_tcg2_sha256(evidence, sizeof(evidence) - 1u,
                        evidence_digest) != 0)
        machine_fail("local SHA-256 failed");
    print_digest_line("BBP-UEFI-TCG2: PCR16_BEFORE ", before);
    print_digest_line("BBP-UEFI-TCG2: EVIDENCE_SHA256 ", evidence_digest);

    memory_zero(arena, sizeof(arena));
    info = (struct bbp_info *)arena;
    bbp_builder_init(&builder, arena + sizeof(*info),
        (bbp_phys_t)(uintptr_t)(arena + sizeof(*info)),
        sizeof(arena) - sizeof(*info));
    memory_zero(&platform, sizeof(platform));
    platform.tpm_base_address = TPM_TIS_BASE;
    platform.tpm_version = 0x0200u;
    platform.tpm_interface = 1u;
    platform.tpm_flags = BBP_TPM_FLAG_ACTIVE;
    memory_zero(&source, sizeof(source));
    source.pcr_index = PCR_INDEX;
    source.algorithm = BBP_HASH_SHA256;
    source.hash_length = BBP_SECURITY_SHA256_BYTES;
    source.data = evidence;
    source.data_length = sizeof(evidence) - 1u;
    source.component_name = component_name;
    source.component_name_length = sizeof(component_name) - 1u;
    tcg2.protocol = protocol;
    callbacks.context = &tcg2;
    callbacks.hash_extend = tcg2_hash_extend;
    callbacks.arena_allocate = bbp_security_builder_allocate;
    callbacks.abort = collector_abort;

    if (bbp_security_collect(&builder, &platform, &source, 1u,
          &callbacks, &published) != BBP_SECURITY_OK)
        machine_fail("TCG2 extend or SECURITY collection failed");
    if (read_sha256_pcr(protocol, after) != 0)
        machine_fail("bounded post-extend PCR_Read failed");
    bbp_tcg2_sha256_extend(before, evidence_digest, expected_after);
    if (!memory_equal(after, expected_after, sizeof(after)))
        machine_fail("PCR16 does not equal SHA256(before || evidence digest)");
    print_digest_line("BBP-UEFI-TCG2: PCR16_AFTER ", after);

    if (bbp_builder_finalize(&builder, info,
          (bbp_phys_t)(uintptr_t)info) == 0u || builder.overflow != 0)
        machine_fail("BBP builder finalization failed");
    if (bbp_init_bounded(&parser, info, 0u, builder.arena_phys,
          builder.capacity) != BBP_OK)
        machine_fail("bounded BBP parser rejected finalized output");
    parsed = (const struct bbp_tag_security *)bbp_find_tag(
        &parser, BBP_TAG_SECURITY);
    if (parsed == NULL || parsed != published ||
        parsed->measurement_count != 1u ||
        parsed->secure_boot.mode != 0u ||
        parsed->secure_boot.signature_verified != 0u ||
        bbp_verify_blob(&parser, parsed->measurements,
            sizeof(struct bbp_measurement), parsed->measurements_crc, 0) !=
            BBP_OK)
        machine_fail("SECURITY tag/log validation failed");
    measurement = (const struct bbp_measurement *)(uintptr_t)
        parsed->measurements;
    if (measurement->pcr_index != PCR_INDEX ||
        measurement->algorithm != BBP_HASH_SHA256 ||
        measurement->hash_length != sizeof(evidence_digest) ||
        !memory_equal(measurement->hash, evidence_digest,
                      sizeof(evidence_digest)) ||
        !memory_equal(measurement->component_name, component_name,
                      sizeof(component_name)))
        machine_fail("SECURITY measurement record mismatch");

    serial_puts("BBP-UEFI-TCG2: BBP v1.1 SECURITY tag/log bounded PASS\n");
    serial_puts("BBP-UEFI-TCG2: Secure Boot/identity claims: none\n");
    guest_exit = 0x10u;
    serial_puts("BBP-UEFI-TCG2: PASS\n");
    outb(0xf4u, guest_exit);
    for (;;)
        __asm__ volatile("hlt");
    return BBP_EFI_SUCCESS;
}
