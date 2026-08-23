/* Hosted translation tests; these prove import logic, not firmware collection. */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../bootloader/bbp_import.h"
#include "../kernel/bbp_kernel.h"

#define ARENA_BYTES 16384u

static int failures;

#define CHECK(condition, message) do { \
    if (!(condition)) { printf("FAIL: %s\n", (message)); failures++; } \
    else printf("ok:   %s\n", (message)); \
} while (0)

struct fixture {
    union {
        max_align_t alignment;
        uint8_t bytes[sizeof(struct bbp_info) + ARENA_BYTES];
    } storage;
    struct bbp_builder builder;
};

static struct bbp_info *fixture_info(struct fixture *fixture)
{
    return (struct bbp_info *)fixture->storage.bytes;
}

static uint8_t *fixture_arena(struct fixture *fixture)
{
    return fixture->storage.bytes + sizeof(struct bbp_info);
}

static void fixture_init(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    bbp_builder_init(&fixture->builder, fixture_arena(fixture),
        (bbp_phys_t)(uintptr_t)fixture_arena(fixture), ARENA_BYTES);
}

static int builder_unchanged(const struct fixture *fixture,
                             const struct bbp_builder *before,
                             const uint8_t *arena_before)
{
    return memcmp(&fixture->builder, before, sizeof(*before)) == 0
        && memcmp(fixture->storage.bytes + sizeof(struct bbp_info),
                  arena_before, ARENA_BYTES) == 0;
}

static int finalize_and_init(struct fixture *fixture, struct bbp_kctx *context)
{
    struct bbp_info *info = fixture_info(fixture);
    bbp_builder_finalize(&fixture->builder, info,
                         (bbp_phys_t)(uintptr_t)info);
    return bbp_init_bounded(context, info, 0,
        fixture->builder.arena_phys, fixture->builder.capacity) == BBP_OK;
}

static void test_planner_limits(void)
{
    struct fixture fixture;
    struct bbp_import_plan plan;

    fixture_init(&fixture);
    fixture.builder.capacity = BBP_IMPORT_MAX_ARENA + 8u;
    CHECK(bbp_import_plan_begin(&fixture.builder, &plan) == BBP_IMPORT_OK,
          "import planner accepts a valid large-capacity builder");
    plan.used = BBP_IMPORT_MAX_ARENA;
    CHECK(bbp_import_plan_blob(&fixture.builder, &plan, 1)
          == BBP_IMPORT_ERR_CAPACITY,
          "import planner cannot exceed the finalizable INFO ceiling");

    plan.used = 0;
    plan.tag_count = BBP_IMPORT_MAX_TAGS;
    CHECK(bbp_import_plan_tag(&fixture.builder, &plan,
                              sizeof(struct bbp_tag_acpi))
          == BBP_IMPORT_ERR_COUNT,
          "import planner cannot exceed the consumer walk ceiling");
}

static void test_limine(void)
{
    static const uint8_t cmdline[] = "console=ttyS0";
    const struct bbp_limine_mmap_entry mmap[] = {
        {0x1000, 0x9000, 0},
        {0x10000, 0x1000, 99}
    };
    const struct bbp_limine_cpu cpus[] = {{0, 2}, {1, 7}};
    struct bbp_limine_snapshot snapshot;
    struct fixture fixture;
    struct bbp_kctx context;
    const struct bbp_tag_memory_map *map_tag;
    const struct bbp_tag_smp *smp;
    const struct bbp_tag_cmdline *cmd;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.present = BBP_IMPORT_HAS_HHDM | BBP_IMPORT_HAS_MEMORY_MAP
        | BBP_IMPORT_HAS_KERNEL_ADDRESS | BBP_IMPORT_HAS_SMP
        | BBP_IMPORT_HAS_CMDLINE | BBP_IMPORT_HAS_FRAMEBUFFER
        | BBP_IMPORT_HAS_ACPI;
    snapshot.memory_map = mmap;
    snapshot.memory_map_count = 2;
    snapshot.kernel_physical_base = 0x200000;
    snapshot.kernel_virtual_base = 0xffffffff80000000ULL;
    snapshot.cpus = cpus;
    snapshot.cpu_count = 2;
    snapshot.bsp_apic_id = 2;
    snapshot.x2apic = 1;
    snapshot.command_line.data = cmdline;
    snapshot.command_line.bytes = sizeof(cmdline);
    snapshot.framebuffer = (struct bbp_import_framebuffer){
        .address = 0x80000000, .total_size = 800u * 600u * 4u,
        .width = 800, .height = 600, .pitch = 3200,
        .pixel_format = BBP_FB_BGRA8888, .color_depth = 8
    };
    snapshot.acpi = (struct bbp_import_acpi){
        .rsdp_address = 0xe0000, .xsdt_address = 0x120000,
        .acpi_version = 0x0604, .flags = BBP_ACPI_FLAG_XSDT_AVAILABLE
    };

    fixture_init(&fixture);
    CHECK(bbp_import_limine(&fixture.builder, &snapshot) == BBP_IMPORT_OK,
          "Limine valid snapshot imports");
    CHECK(fixture.builder.tag_count == 7,
          "Limine emits seven deterministic tags");
    CHECK(finalize_and_init(&fixture, &context),
          "Limine output roundtrips through bounded parser");
    map_tag = (const struct bbp_tag_memory_map *)bbp_find_tag(
        &context, BBP_TAG_MEMORY_MAP);
    CHECK(map_tag != NULL && map_tag->entry_count == 2,
          "Limine memory map tag and CRC validate");
    if (map_tag != NULL) {
        const struct bbp_memory_entry *entries =
            (const struct bbp_memory_entry *)((const uint8_t *)map_tag
                + sizeof(*map_tag));
        CHECK(entries[1].type == BBP_MEM_RESERVED
              && entries[1].attributes == 0,
              "unknown Limine mmap type maps to RESERVED without permissions");
    }
    smp = (const struct bbp_tag_smp *)bbp_find_tag(&context, BBP_TAG_SMP);
    CHECK(smp != NULL && smp->cpu_count == 2 && smp->bsp_id == 2
          && (smp->flags & BBP_SMP_FLAG_X2APIC) != 0,
          "Limine SMP/BSP/x2APIC fields survive translation");
    cmd = (const struct bbp_tag_cmdline *)bbp_find_tag(&context,
                                                       BBP_TAG_CMDLINE);
    CHECK(cmd != NULL && bbp_verify_blob(&context, cmd->string, cmd->length,
          cmd->string_crc, 0) == BBP_OK,
          "Limine command-line copy has a valid out-of-line CRC");

    {
        struct bbp_limine_cpu duplicate[] = {{0, 3}, {1, 3}};
        struct bbp_builder before;
        uint8_t arena_before[ARENA_BYTES];
        fixture_init(&fixture);
        snapshot.present = BBP_IMPORT_HAS_SMP;
        snapshot.cpus = duplicate;
        snapshot.cpu_count = 2;
        snapshot.bsp_apic_id = 3;
        before = fixture.builder;
        memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES);
        CHECK(bbp_import_limine(&fixture.builder, &snapshot)
              == BBP_IMPORT_ERR_DUPLICATE,
              "Limine duplicate APIC IDs are rejected");
        CHECK(builder_unchanged(&fixture, &before, arena_before),
              "Limine failure leaves builder and arena byte-identical");

        fixture_init(&fixture);
        snapshot.present = BBP_IMPORT_HAS_HHDM;
        fixture.builder.capacity = 32;
        before = fixture.builder;
        memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES);
        CHECK(bbp_import_limine(&fixture.builder, &snapshot)
              == BBP_IMPORT_ERR_CAPACITY,
              "exact preflight rejects insufficient arena capacity");
        CHECK(builder_unchanged(&fixture, &before, arena_before),
              "capacity failure leaves builder and arena byte-identical");

        fixture_init(&fixture);
        snapshot.present = BBP_IMPORT_HAS_CMDLINE;
        snapshot.command_line.data = fixture_arena(&fixture) + 256;
        snapshot.command_line.bytes = 2;
        fixture_arena(&fixture)[256] = 'x';
        fixture_arena(&fixture)[257] = 0;
        before = fixture.builder;
        memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES);
        CHECK(bbp_import_limine(&fixture.builder, &snapshot)
              == BBP_IMPORT_ERR_RANGE,
              "Limine source overlapping the destination arena is rejected");
        CHECK(builder_unchanged(&fixture, &before, arena_before),
              "Limine overlap failure leaves builder and arena byte-identical");

        fixture_init(&fixture);
        snapshot.command_line.data = (const uint8_t *)(UINTPTR_MAX - 3u);
        snapshot.command_line.bytes = 8;
        before = fixture.builder;
        memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES);
        CHECK(bbp_import_limine(&fixture.builder, &snapshot)
              == BBP_IMPORT_ERR_RANGE,
              "Limine wrapping source span is rejected before dereference");
        CHECK(builder_unchanged(&fixture, &before, arena_before),
              "Limine wrapping-span failure is failure-atomic");
    }
}

struct mbi_image {
    uint8_t bytes[2048];
    size_t used;
    size_t cmdline;
    size_t module;
    size_t mmap;
    size_t framebuffer;
    size_t acpi_new;
    size_t end;
};

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16); p[3] = (uint8_t)(value >> 24);
}

static void put64(uint8_t *p, uint64_t value)
{
    put32(p, (uint32_t)value); put32(p + 4, (uint32_t)(value >> 32));
}

static uint8_t *mbi_tag(struct mbi_image *image, uint32_t type, uint32_t size)
{
    size_t offset = image->used;
    size_t padded = ((size_t)size + 7u) & ~(size_t)7u;
    uint8_t *tag = image->bytes + offset;
    memset(tag, 0, padded);
    put32(tag, type); put32(tag + 4, size);
    image->used += padded;
    return tag;
}

static void rsdp_checksums(uint8_t *rsdp, size_t bytes)
{
    unsigned sum = 0;
    rsdp[8] = 0;
    for (size_t i = 0; i < 20; i++) sum += rsdp[i];
    rsdp[8] = (uint8_t)(0u - sum);
    if (bytes > 20) {
        sum = 0; rsdp[32] = 0;
        for (size_t i = 0; i < bytes; i++) sum += rsdp[i];
        rsdp[32] = (uint8_t)(0u - sum);
    }
}

static void build_mbi(struct mbi_image *image)
{
    uint8_t *tag;
    memset(image, 0, sizeof(*image));
    image->used = 8;

    image->cmdline = image->used;
    tag = mbi_tag(image, 1, 15);
    memcpy(tag + 8, "root=x", 7);

    image->module = image->used;
    tag = mbi_tag(image, 3, 97);
    put32(tag + 8, 0x300000); put32(tag + 12, 0x304000);
    memset(tag + 16, 'm', 80); tag[96] = 0;

    image->mmap = image->used;
    tag = mbi_tag(image, 6, 64);
    put32(tag + 8, 24); put32(tag + 12, 0);
    put64(tag + 16, 0x1000); put64(tag + 24, 0x9f000); put32(tag + 32, 1);
    put64(tag + 40, 0x100000); put64(tag + 48, 0x1000); put32(tag + 56, 3);

    image->framebuffer = image->used;
    tag = mbi_tag(image, 8, 38);
    put64(tag + 8, 0x90000000); put32(tag + 16, 4096);
    put32(tag + 20, 1024); put32(tag + 24, 768);
    tag[28] = 32; tag[29] = 1;
    tag[32] = 16; tag[33] = 8; tag[34] = 8;
    tag[35] = 8; tag[36] = 0; tag[37] = 8;

    image->acpi_new = image->used;
    tag = mbi_tag(image, 15, 44);
    memcpy(tag + 8, "RSD PTR ", 8); memcpy(tag + 17, "NEWOEM", 6);
    tag[23] = 2; put32(tag + 24, 0x20000); put32(tag + 28, 36);
    put64(tag + 32, 0x12345000); rsdp_checksums(tag + 8, 36);

    tag = mbi_tag(image, 14, 28);
    memcpy(tag + 8, "RSD PTR ", 8); memcpy(tag + 17, "OLDOEM", 6);
    tag[23] = 0; put32(tag + 24, 0x10000); rsdp_checksums(tag + 8, 20);

    image->end = image->used;
    (void)mbi_tag(image, 0, 8);
    put32(image->bytes, (uint32_t)image->used);
}

static void test_multiboot2(void)
{
    struct mbi_image image;
    struct bbp_multiboot2_snapshot snapshot;
    struct fixture fixture;
    struct bbp_kctx context;
    const struct bbp_tag_modules *modules;
    const struct bbp_tag_memory_map *memory_map_tag;
    const struct bbp_tag_acpi *acpi;
    const struct bbp_tag_cmdline *cmd;

    build_mbi(&image);
    snapshot = (struct bbp_multiboot2_snapshot){
        .mbi = image.bytes, .mapped_bytes = image.used,
        .present = BBP_IMPORT_HAS_HHDM | BBP_IMPORT_HAS_KERNEL_ADDRESS,
        .kernel_physical_base = 0x200000,
        .kernel_virtual_base = 0xffffffff80000000ULL
    };
    fixture_init(&fixture);
    CHECK(bbp_import_multiboot2(&fixture.builder, &snapshot) == BBP_IMPORT_OK,
          "Multiboot2 valid MBI imports");
    CHECK(finalize_and_init(&fixture, &context),
          "Multiboot2 output roundtrips through bounded parser");
    modules = (const struct bbp_tag_modules *)bbp_find_tag(&context,
                                                           BBP_TAG_MODULES);
    CHECK(modules != NULL && modules->module_count == 1,
          "Multiboot2 module becomes a fixed BBP descriptor");
    if (modules != NULL) {
        const struct bbp_module_entry *entry =
            (const struct bbp_module_entry *)((const uint8_t *)modules
                                               + sizeof(*modules));
        CHECK(entry->name[63] == 0 && strlen((const char *)entry->name) == 63,
              "long Multiboot2 module name truncates deterministically");
    }
    memory_map_tag = (const struct bbp_tag_memory_map *)bbp_find_tag(
        &context, BBP_TAG_MEMORY_MAP);
    if (memory_map_tag != NULL) {
        const struct bbp_memory_entry *entries =
            (const struct bbp_memory_entry *)((const uint8_t *)memory_map_tag
                                               + sizeof(*memory_map_tag));
        CHECK(entries[0].attributes
              == (BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE)
              && entries[1].attributes == BBP_MEM_ATTR_READABLE,
              "Multiboot2 memory permissions follow conservative type mapping");
    }
    acpi = (const struct bbp_tag_acpi *)bbp_find_tag(&context, BBP_TAG_ACPI);
    CHECK(acpi != NULL && acpi->acpi_version == 0x0200
          && acpi->xsdt_address == 0x12345000,
          "Multiboot2 ACPI new tag wins over old tag");
    cmd = (const struct bbp_tag_cmdline *)bbp_find_tag(&context,
                                                       BBP_TAG_CMDLINE);
    CHECK(cmd != NULL && bbp_verify_blob(&context, cmd->string, cmd->length,
          cmd->string_crc, 0) == BBP_OK,
          "Multiboot2 command line and CRC validate");

    {
        struct bbp_builder before;
        uint8_t arena_before[ARENA_BYTES];
#define MB2_FAILURE(expected, label) do { \
    fixture_init(&fixture); before = fixture.builder; \
    memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES); \
    CHECK(bbp_import_multiboot2(&fixture.builder, &snapshot) == (expected), label); \
    CHECK(builder_unchanged(&fixture, &before, arena_before), \
          label " is failure-atomic"); \
} while (0)
        snapshot.mapped_bytes = image.used - 1;
        MB2_FAILURE(BBP_IMPORT_ERR_FRAMING, "Multiboot2 mapped truncation rejected");
        snapshot.mapped_bytes = image.used;

        put32(image.bytes + image.end, 42);
        MB2_FAILURE(BBP_IMPORT_ERR_FRAMING, "Multiboot2 missing end tag rejected");
        put32(image.bytes + image.end, 0);

        put32(image.bytes, (uint32_t)image.used + 8);
        snapshot.mapped_bytes = image.used + 8;
        MB2_FAILURE(BBP_IMPORT_ERR_FRAMING,
                    "Multiboot2 bytes after end tag rejected");
        put32(image.bytes, (uint32_t)image.used);
        snapshot.mapped_bytes = image.used;

        image.bytes[image.cmdline + 14] = 'x';
        MB2_FAILURE(BBP_IMPORT_ERR_STRING, "Multiboot2 unterminated string rejected");
        image.bytes[image.cmdline + 14] = 0;

        put32(image.bytes + image.mmap + 8, 23);
        MB2_FAILURE(BBP_IMPORT_ERR_FRAMING, "Multiboot2 malformed mmap rejected");
        put32(image.bytes + image.mmap + 8, 24);

        {
            struct mbi_image bad_stride;
            uint8_t *tag;
            memset(&bad_stride, 0, sizeof(bad_stride)); bad_stride.used = 8;
            tag = mbi_tag(&bad_stride, 6, 41);
            put32(tag + 8, 25); put32(tag + 12, 0);
            put64(tag + 16, 0x1000); put64(tag + 24, 0x1000);
            put32(tag + 32, 1);
            (void)mbi_tag(&bad_stride, 0, 8);
            put32(bad_stride.bytes, (uint32_t)bad_stride.used);
            snapshot.mbi = bad_stride.bytes;
            snapshot.mapped_bytes = bad_stride.used;
            MB2_FAILURE(BBP_IMPORT_ERR_FRAMING,
                        "Multiboot2 non-aligned mmap stride rejected");
            snapshot.mbi = image.bytes;
            snapshot.mapped_bytes = image.used;
        }

        put32(image.bytes + image.module + 12, 0x300000);
        MB2_FAILURE(BBP_IMPORT_ERR_RANGE, "Multiboot2 malformed module range rejected");
        put32(image.bytes + image.module + 12, 0x304000);

        image.bytes[image.framebuffer + 29] = 2;
        MB2_FAILURE(BBP_IMPORT_ERR_UNSUPPORTED,
                    "Multiboot2 non-RGB framebuffer rejected");
        image.bytes[image.framebuffer + 29] = 1;

        image.bytes[image.framebuffer + 28] = 24;
        MB2_FAILURE(BBP_IMPORT_ERR_UNSUPPORTED,
                    "Multiboot2 unrepresentable BGR24 layout rejected");
        image.bytes[image.framebuffer + 28] = 32;

        image.bytes[image.acpi_new + 16] ^= 1;
        MB2_FAILURE(BBP_IMPORT_ERR_FRAMING, "Multiboot2 bad ACPI checksum rejected");
        image.bytes[image.acpi_new + 16] ^= 1;

        {
            struct mbi_image duplicate;
            uint8_t *tag;
            memset(&duplicate, 0, sizeof(duplicate)); duplicate.used = 8;
            tag = mbi_tag(&duplicate, 1, 10); tag[8] = 'a'; tag[9] = 0;
            tag = mbi_tag(&duplicate, 1, 10); tag[8] = 'b'; tag[9] = 0;
            (void)mbi_tag(&duplicate, 0, 8);
            put32(duplicate.bytes, (uint32_t)duplicate.used);
            snapshot.mbi = duplicate.bytes; snapshot.mapped_bytes = duplicate.used;
            MB2_FAILURE(BBP_IMPORT_ERR_DUPLICATE,
                        "Multiboot2 duplicate singleton rejected");
        }
#undef MB2_FAILURE
    }
}

static void uefi_descriptor(uint8_t *entry, uint32_t type, uint64_t base,
                            uint64_t pages, uint64_t attributes)
{
    memset(entry, 0, 48);
    put32(entry, type); put64(entry + 8, base);
    put64(entry + 24, pages); put64(entry + 32, attributes);
}

static void test_uefi(void)
{
    static const uint8_t cmdline[] = "quiet utf8=ok";
    uint8_t memory_map[96];
    struct bbp_uefi_snapshot snapshot;
    struct fixture fixture;
    struct bbp_kctx context;
    const struct bbp_tag_memory_map *map;
    const struct bbp_tag_efi *efi;

    uefi_descriptor(memory_map, 7, 0x100000, 16, 1u << 3);
    uefi_descriptor(memory_map + 48, 10, 0x200000, 2,
                    (1u << 0) | (1u << 12) | (1u << 13));
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.present = BBP_IMPORT_HAS_HHDM | BBP_IMPORT_HAS_MEMORY_MAP
        | BBP_IMPORT_HAS_KERNEL_ADDRESS | BBP_IMPORT_HAS_CMDLINE
        | BBP_IMPORT_HAS_FRAMEBUFFER | BBP_IMPORT_HAS_ACPI
        | BBP_IMPORT_HAS_EFI | BBP_IMPORT_HAS_SMBIOS;
    snapshot.memory_map = memory_map;
    snapshot.memory_map_bytes = sizeof(memory_map);
    snapshot.descriptor_stride = 48;
    snapshot.descriptor_version = 1;
    snapshot.memory_map_final = 1;
    snapshot.system_table = 0x70000;
    snapshot.kernel_physical_base = 0x200000;
    snapshot.kernel_virtual_base = 0xffffffff80000000ULL;
    snapshot.command_line = (struct bbp_import_string){cmdline, sizeof(cmdline)};
    snapshot.framebuffer = (struct bbp_import_framebuffer){
        .address = 0xa0000000, .total_size = 640u * 480u * 4u,
        .width = 640, .height = 480, .pitch = 2560,
        .pixel_format = BBP_FB_RGBA8888, .color_depth = 8
    };
    snapshot.acpi = (struct bbp_import_acpi){
        .rsdp_address = 0xe0000, .xsdt_address = 0x180000,
        .acpi_version = 0x0604, .flags = BBP_ACPI_FLAG_XSDT_AVAILABLE
    };
    snapshot.smbios_32 = 0xf0000;
    snapshot.smbios_64 = 0xf1000;

    fixture_init(&fixture);
    CHECK(bbp_import_uefi_hobs(&fixture.builder, &snapshot) == BBP_IMPORT_OK,
          "normalized final UEFI snapshot imports");
    CHECK(fixture.builder.tag_count == 8,
          "UEFI emits eight deterministic tags");
    CHECK(finalize_and_init(&fixture, &context),
          "UEFI output roundtrips through bounded parser");
    map = (const struct bbp_tag_memory_map *)bbp_find_tag(&context,
                                                          BBP_TAG_MEMORY_MAP);
    CHECK(map != NULL && map->entry_count == 2,
          "UEFI descriptor prefixes become BBP memory entries");
    if (map != NULL) {
        const struct bbp_memory_entry *entry =
            (const struct bbp_memory_entry *)((const uint8_t *)map + sizeof(*map));
        CHECK(entry[0].type == BBP_MEM_USABLE
              && entry[1].type == BBP_MEM_ACPI_NVS,
              "UEFI standard memory types map conservatively");
        CHECK((entry[1].attributes & BBP_MEM_ATTR_READABLE) == 0
              && (entry[1].attributes & BBP_MEM_ATTR_WRITABLE) != 0
              && (entry[1].attributes & BBP_MEM_ATTR_UNCACHED) != 0,
              "UEFI read protection and cacheability map without inventing RO");
    }
    efi = (const struct bbp_tag_efi *)bbp_find_tag(&context, BBP_TAG_EFI);
    CHECK(efi != NULL && efi->memory_map_size == sizeof(memory_map)
          && memcmp((const void *)(uintptr_t)efi->memory_map,
                    memory_map, sizeof(memory_map)) == 0,
          "UEFI raw memory map is copied into the builder arena");

    {
        struct bbp_builder before;
        uint8_t arena_before[ARENA_BYTES];
#define UEFI_FAILURE(expected, label) do { \
    fixture_init(&fixture); before = fixture.builder; \
    memcpy(arena_before, fixture_arena(&fixture), ARENA_BYTES); \
    CHECK(bbp_import_uefi_hobs(&fixture.builder, &snapshot) == (expected), label); \
    CHECK(builder_unchanged(&fixture, &before, arena_before), \
          label " is failure-atomic"); \
} while (0)
        snapshot.memory_map_final = 0;
        UEFI_FAILURE(BBP_IMPORT_ERR_NON_FINAL, "UEFI non-final map rejected");
        snapshot.memory_map_final = 1;

        snapshot.descriptor_stride = 32;
        UEFI_FAILURE(BBP_IMPORT_ERR_UNSUPPORTED, "UEFI short descriptor stride rejected");
        snapshot.descriptor_stride = 48;

        put64(memory_map + 24, UINT64_MAX);
        UEFI_FAILURE(BBP_IMPORT_ERR_OVERFLOW, "UEFI page-count overflow rejected");
        put64(memory_map + 24, 16);
#undef UEFI_FAILURE
    }
}

int main(void)
{
    printf("== BBP boot-source importer self-test ==\n");
    test_planner_limits();
    test_limine();
    test_multiboot2();
    test_uefi();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
