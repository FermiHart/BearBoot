/* Minimal hosted producer -> bounded consumer conformance example. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include <bbp/bbp_sdk.h>

#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

#define CHECK_COUNT 10

struct check_result {
    const char *name;
    int passed;
};

union handoff_storage {
    uint64_t align;
    uint8_t bytes[4096];
};

static union handoff_storage storage;

static int build_and_check(struct check_result checks[CHECK_COUNT])
{
    struct bbp_info *info = (struct bbp_info *)storage.bytes;
    uint8_t *arena = storage.bytes + sizeof(*info);
    size_t arena_bytes = sizeof(storage.bytes) - sizeof(*info);
    struct bbp_builder builder;
    struct bbp_kctx context;
    int all_passed = 1;

    memset(&storage, 0, sizeof(storage));
    bbp_builder_init(&builder, arena, (bbp_phys_t)(uintptr_t)arena, arena_bytes);

    struct bbp_tag_hhdm *hhdm = bbp_alloc_tag(
        &builder, BBP_TAG_HHDM, 1, sizeof(*hhdm));
    if (hhdm) hhdm->offset = 0;

    size_t map_size = sizeof(struct bbp_tag_memory_map)
        + 2 * sizeof(struct bbp_memory_entry);
    struct bbp_tag_memory_map *map = bbp_alloc_tag(
        &builder, BBP_TAG_MEMORY_MAP, 1, map_size);
    if (map) {
        map->entry_count = 2;
        map->entry_size = sizeof(struct bbp_memory_entry);
        struct bbp_memory_entry *entries = (struct bbp_memory_entry *)(map + 1);
        entries[0] = (struct bbp_memory_entry){
            .base = 0x1000, .length = 0x9f000, .type = BBP_MEM_USABLE
        };
        entries[1] = (struct bbp_memory_entry){
            .base = 0x100000, .length = 0x3f00000, .type = BBP_MEM_USABLE
        };
    }

    static const char command_line[] = "console=ttyS0 bbp.strict=1";
    uint32_t command_length = 0;
    bbp_phys_t command_phys = bbp_arena_strdup(
        &builder, command_line, &command_length);
    struct bbp_tag_cmdline *command = bbp_alloc_tag(
        &builder, BBP_TAG_CMDLINE, 1, sizeof(*command));
    if (command) {
        command->string = command_phys;
        command->length = command_length;
        command->string_crc = bbp_crc64(command_line, command_length);
    }

    info->architecture = BBP_ARCH_X86_64;
    info->cpu_count = 1;
    bbp_phys_t finalized = bbp_builder_finalize(
        &builder, info, (bbp_phys_t)(uintptr_t)info);

    checks[0] = (struct check_result){
        "crc64-xz-vector",
        bbp_crc64("123456789", 9) == 0x995dc9bbdf1939faULL
    };
    checks[1] = (struct check_result){
        "wire-layout",
        sizeof(struct bbp_header) == 160 && sizeof(struct bbp_info) == 144
            && sizeof(struct bbp_tag_header) == 32
    };
    const uint16_t endian_probe = 1;
    checks[2] = (struct check_result){
        "c-wire-little-endian", *(const uint8_t *)&endian_probe == 1
    };
    checks[3] = (struct check_result){
        "builder-finalize",
        finalized == (bbp_phys_t)(uintptr_t)info && !builder.overflow
            && info->tag_count == 3
    };

    bbp_status_t init_status = bbp_init_bounded(
        &context, info, 0, (bbp_phys_t)(uintptr_t)arena, arena_bytes);
    checks[4] = (struct check_result){
        "bounded-parser", init_status == BBP_OK
            && bbp_find_tag(&context, BBP_TAG_HHDM) != NULL
            && bbp_find_tag(&context, BBP_TAG_MEMORY_MAP) != NULL
            && bbp_find_tag(&context, BBP_TAG_CMDLINE) != NULL
    };

    uint32_t safe_count = 0;
    if (map) {
        (void)bbp_tag_array(&map->header, sizeof(*map),
                            sizeof(struct bbp_memory_entry), UINT32_MAX,
                            &safe_count);
    }
    checks[5] = (struct check_result){"trailing-array-clamp", safe_count == 2};

    int blob_ok = init_status == BBP_OK
        && bbp_verify_blob(&context, command_phys, command_length,
                           command ? command->string_crc : 0, 0) == BBP_OK
        && bbp_verify_blob(&context, command_phys, command_length, 0, 0)
            == BBP_ERR_TAG_CHECKSUM
        && bbp_verify_blob(&context, command_phys, command_length, 0, 1)
            == BBP_OK;
    checks[6] = (struct check_result){"blob-crc-policy", blob_ok};

    uint16_t saved_architecture = info->architecture;
    info->architecture ^= 1u;
    struct bbp_kctx rejected_context;
    bbp_status_t info_tamper = bbp_init_bounded(
        &rejected_context, info, 0, (bbp_phys_t)(uintptr_t)arena, arena_bytes);
    info->architecture = saved_architecture;
    checks[7] = (struct check_result){
        "info-tamper-detection", info_tamper == BBP_ERR_CHECKSUM
    };

    uint32_t saved_flags = command ? command->flags : 0;
    if (command) command->flags ^= 1u;
    checks[8] = (struct check_result){
        "tag-tamper-detection", init_status == BBP_OK && command
            && bbp_find_tag(&context, BBP_TAG_CMDLINE) == NULL
    };
    if (command) command->flags = saved_flags;

    uint8_t tiny_arena[31];
    struct bbp_builder tiny;
    struct bbp_info tiny_info = {0};
    bbp_builder_init(&tiny, tiny_arena,
                     (bbp_phys_t)(uintptr_t)tiny_arena, sizeof(tiny_arena));
    void *too_large = bbp_alloc_tag(
        &tiny, BBP_TAG_HHDM, 1, sizeof(struct bbp_tag_hhdm));
    checks[9] = (struct check_result){
        "builder-fail-closed", too_large == NULL && tiny.overflow
            && bbp_builder_finalize(&tiny, &tiny_info,
                                    (bbp_phys_t)(uintptr_t)&tiny_info) == 0
    };

    for (size_t i = 0; i < CHECK_COUNT; i++) {
        if (!checks[i].passed) all_passed = 0;
    }
    return all_passed;
}

static void print_json(const struct check_result checks[CHECK_COUNT], int passed)
{
    printf("{\"schema\":\"bbp-conformance-report-v1\","
           "\"sdk_version\":\"%s\",\"wire_version\":\"%s\","
           "\"profile\":\"bbp-c-sdk-host-roundtrip-v1\","
           "\"conformant\":%s,\"checks\":[",
           BBP_SDK_VERSION, BBP_SDK_WIRE_VERSION, passed ? "true" : "false");
    for (size_t i = 0; i < CHECK_COUNT; i++) {
        printf("%s{\"name\":\"%s\",\"status\":\"%s\"}",
               i ? "," : "", checks[i].name,
               checks[i].passed ? "pass" : "fail");
    }
    puts("]}");
}

static void print_human(const struct check_result checks[CHECK_COUNT])
{
    for (size_t i = 0; i < CHECK_COUNT; i++)
        printf("[%s] %s\n", checks[i].passed ? "pass" : "FAIL", checks[i].name);
}

int main(int argc, char **argv)
{
    struct check_result checks[CHECK_COUNT];
    int passed = build_and_check(checks);

    if (argc == 2 && strcmp(argv[1], "--json") == 0)
        print_json(checks, passed);
    else if ((argc == 1) || (argc == 2 && strcmp(argv[1], "--human") == 0))
        print_human(checks);
    else {
        fprintf(stderr, "usage: %s [--human|--json]\n", argv[0]);
        return 2;
    }
    return passed ? 0 : 1;
}
