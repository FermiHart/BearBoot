/* Hosted tests for the pure ELF64 planner; no firmware headers are required. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../bootloader/uefi/elf64_loader.h"

#define IMAGE_CAPACITY 12288u
#define ELF_HEADER_SIZE 64u
#define PROGRAM_HEADER_SIZE 56u
#define PT_LOAD 1u

static int failures;

#define CHECK(condition, message) do { \
    if (!(condition)) { printf("FAIL: %s\n", (message)); failures++; } \
    else printf("ok:   %s\n", (message)); \
} while (0)

struct fixture {
    uint8_t image[IMAGE_CAPACITY];
    size_t size;
};

static void put16(uint8_t *bytes, size_t offset, uint16_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *bytes, size_t offset, uint32_t value)
{
    unsigned i;
    for (i = 0u; i < 4u; i++)
        bytes[offset + i] = (uint8_t)(value >> (i * 8u));
}

static void put64(uint8_t *bytes, size_t offset, uint64_t value)
{
    unsigned i;
    for (i = 0u; i < 8u; i++)
        bytes[offset + i] = (uint8_t)(value >> (i * 8u));
}

static void set_phdr(struct fixture *fixture, unsigned index, uint32_t type,
                     uint32_t flags, uint64_t offset, uint64_t virtual_address,
                     uint64_t physical_address, uint64_t file_size,
                     uint64_t memory_size, uint64_t alignment)
{
    size_t ph = ELF_HEADER_SIZE + (size_t)index * PROGRAM_HEADER_SIZE;
    put32(fixture->image, ph, type);
    put32(fixture->image, ph + 4u, flags);
    put64(fixture->image, ph + 8u, offset);
    put64(fixture->image, ph + 16u, virtual_address);
    put64(fixture->image, ph + 24u, physical_address);
    put64(fixture->image, ph + 32u, file_size);
    put64(fixture->image, ph + 40u, memory_size);
    put64(fixture->image, ph + 48u, alignment);
}

static void fixture_init(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->size = 0x2020u;
    fixture->image[0] = 0x7fu;
    fixture->image[1] = 'E';
    fixture->image[2] = 'L';
    fixture->image[3] = 'F';
    fixture->image[4] = 2u;
    fixture->image[5] = 1u;
    fixture->image[6] = 1u;
    put16(fixture->image, 16u, 2u);
    put16(fixture->image, 18u, 62u);
    put32(fixture->image, 20u, 1u);
    put64(fixture->image, 24u, UINT64_C(0xffffffff80000010));
    put64(fixture->image, 32u, ELF_HEADER_SIZE);
    put16(fixture->image, 52u, ELF_HEADER_SIZE);
    put16(fixture->image, 54u, PROGRAM_HEADER_SIZE);
    put16(fixture->image, 56u, 2u);

    set_phdr(fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x80), UINT64_C(0x80),
             UINT64_C(0x1000));
    set_phdr(fixture, 1u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_W,
             UINT64_C(0x2000), UINT64_C(0xffffffff80002000),
             UINT64_C(0x202000), UINT64_C(0x20), UINT64_C(0x1000),
             UINT64_C(0x1000));
}

static bbp_elf64_status plan_fixture(const struct fixture *fixture,
                                     struct bbp_elf64_plan *plan)
{
    return bbp_elf64_plan(fixture->image, fixture->size, plan);
}

static void expect_rejected(const struct fixture *fixture,
                            bbp_elf64_status expected, const char *message)
{
    struct bbp_elf64_plan plan;
    struct bbp_elf64_plan before;
    bbp_elf64_status status;

    memset(&plan, 0xa5, sizeof(plan));
    before = plan;
    status = plan_fixture(fixture, &plan);
    CHECK(status == expected, message);
    CHECK(memcmp(&plan, &before, sizeof(plan)) == 0,
          "rejected image leaves the plan unchanged");
}

static void test_valid_multisegment_bss(void)
{
    struct fixture fixture;
    struct bbp_elf64_plan plan;
    bbp_elf64_status status;

    fixture_init(&fixture);
    memset(&plan, 0, sizeof(plan));
    status = plan_fixture(&fixture, &plan);
    CHECK(status == BBP_ELF64_OK, "valid ELF64 executable is planned");
    CHECK(plan.segment_count == 2u &&
          plan.entry == UINT64_C(0xffffffff80000010),
          "entry and both PT_LOAD segments are published");
    CHECK(plan.segments[0].file_offset == UINT64_C(0x1000) &&
          plan.segments[0].page_base == UINT64_C(0x200000) &&
          plan.segments[0].page_count == 1u,
          "executable segment file and page geometry are retained");
    CHECK(plan.segments[1].file_size == UINT64_C(0x20) &&
          plan.segments[1].memory_size == UINT64_C(0x1000),
          "BSS tail is represented by filesz smaller than memsz");
    CHECK(plan.physical_base == UINT64_C(0x200000) &&
          plan.physical_end == UINT64_C(0x203000),
          "exclusive physical envelope spans every planned page");
}

static void test_required_elf_identity(void)
{
    struct fixture fixture;

    fixture_init(&fixture);
    fixture.image[0] = 0u;
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "bad ELF magic is rejected");
    fixture_init(&fixture);
    fixture.image[4] = 1u;
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "non-ELF64 class is rejected");
    fixture_init(&fixture);
    fixture.image[5] = 2u;
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "non-little-endian encoding is rejected");
    fixture_init(&fixture);
    put16(fixture.image, 16u, 3u);
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "non-ET_EXEC image is rejected");
    fixture_init(&fixture);
    put16(fixture.image, 18u, 183u);
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "non-x86_64 machine is rejected");
    fixture_init(&fixture);
    put32(fixture.image, 20u, 0u);
    expect_rejected(&fixture, BBP_ELF64_ERR_FORMAT,
                    "invalid ELF version is rejected");
}

static void test_header_bounds_and_capacity(void)
{
    struct fixture fixture;
    unsigned i;

    fixture_init(&fixture);
    fixture.size = ELF_HEADER_SIZE - 1u;
    expect_rejected(&fixture, BBP_ELF64_ERR_TRUNCATED,
                    "truncated ELF header is rejected");
    fixture_init(&fixture);
    put16(fixture.image, 54u, PROGRAM_HEADER_SIZE - 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_PROGRAM_HEADERS,
                    "wrong ELF64 program-header size is rejected");
    fixture_init(&fixture);
    put16(fixture.image, 56u, BBP_ELF64_MAX_PROGRAM_HEADERS + 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_PROGRAM_HEADERS,
                    "program-header count is bounded");
    fixture_init(&fixture);
    put64(fixture.image, 32u, UINT64_MAX - 8u);
    expect_rejected(&fixture, BBP_ELF64_ERR_OVERFLOW,
                    "program-header table addition overflow is rejected");
    fixture_init(&fixture);
    fixture.size = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
    expect_rejected(&fixture, BBP_ELF64_ERR_TRUNCATED,
                    "program-header table outside the image is rejected");

    fixture_init(&fixture);
    put16(fixture.image, 56u, BBP_ELF64_MAX_LOAD_SEGMENTS + 1u);
    for (i = 0u; i < BBP_ELF64_MAX_LOAD_SEGMENTS + 1u; i++)
        set_phdr(&fixture, i, PT_LOAD, BBP_ELF64_PF_R, 0u,
                 UINT64_C(0x1000) * i, UINT64_C(0x100000) +
                 UINT64_C(0x2000) * i, 0u, 0u, 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_SEGMENT_LIMIT,
                    "PT_LOAD plan capacity is enforced");
}

static void test_segment_sizes_and_overflow(void)
{
    struct fixture fixture;

    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x81), UINT64_C(0x80),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_MEMORY_SIZE,
                    "PT_LOAD filesz larger than memsz is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_MAX - 7u, UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), 16u, 16u, 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_OVERFLOW,
                    "segment file-range overflow is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_MAX - 7u, UINT64_C(0x200000),
             16u, 16u, 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_OVERFLOW,
                    "segment virtual-range overflow is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_MAX - 7u, 16u, 16u, 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_OVERFLOW,
                    "segment physical-range overflow is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x3000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x1000), UINT64_C(0x1000),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_FILE_RANGE,
                    "segment bytes outside the image are rejected");
}

static void test_alignment_boundaries(void)
{
    struct fixture fixture;

    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x80), UINT64_C(0x80), 3u);
    expect_rejected(&fixture, BBP_ELF64_ERR_ALIGNMENT,
                    "non-power-of-two p_align is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1001), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x80), UINT64_C(0x80),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_ALIGNMENT,
                    "VMA and file offset incongruence is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200001), UINT64_C(0x80), UINT64_C(0x80),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_ALIGNMENT,
                     "physical address and file offset incongruence is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200001), UINT64_C(0x80), UINT64_C(0x80), 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_ALIGNMENT,
                     "VMA and physical page offsets must always match");
}

static void test_address_boundaries(void)
{
    struct fixture fixture;

    fixture_init(&fixture);
    put64(fixture.image, 24u, UINT64_C(0x0000800000000000));
    expect_rejected(&fixture, BBP_ELF64_ERR_ADDRESS,
                    "non-canonical entry is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0x0000800000000000),
             UINT64_C(0x200000), UINT64_C(0x80), UINT64_C(0x80),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_ADDRESS,
                    "non-canonical segment VMA is rejected");
    fixture_init(&fixture);
    put64(fixture.image, 24u, UINT64_C(0x00007ffffffffff0));
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1ff0), UINT64_C(0x00007ffffffffff0),
             UINT64_C(0x200ff0), UINT64_C(0x20), UINT64_C(0x20), 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_ADDRESS,
                    "segment crossing the canonical-address hole is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x0001000000000000), UINT64_C(0x80),
             UINT64_C(0x80), UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_PHYSICAL_LIMIT,
                    "physical start at the 48-bit limit is rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x0000fffffffff000), UINT64_C(0x80),
             UINT64_C(0x1001), UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_PHYSICAL_LIMIT,
                    "physical end beyond 48 bits is rejected");
}

static void test_security_and_entry_contract(void)
{
    struct fixture fixture;

    fixture_init(&fixture);
    set_phdr(&fixture, 1u, PT_LOAD, BBP_ELF64_PF_R | BBP_ELF64_PF_W,
             UINT64_C(0x2000), UINT64_C(0xffffffff80002080),
             UINT64_C(0x200080), UINT64_C(0x20), UINT64_C(0x100), 1u);
    expect_rejected(&fixture, BBP_ELF64_ERR_PAGE_OVERLAP,
                    "distinct byte ranges sharing a physical page are rejected");
    fixture_init(&fixture);
    set_phdr(&fixture, 0u, PT_LOAD,
             BBP_ELF64_PF_R | BBP_ELF64_PF_W | BBP_ELF64_PF_X,
             UINT64_C(0x1000), UINT64_C(0xffffffff80000000),
             UINT64_C(0x200000), UINT64_C(0x80), UINT64_C(0x80),
             UINT64_C(0x1000));
    expect_rejected(&fixture, BBP_ELF64_ERR_WX,
                    "writable executable PT_LOAD is rejected");
    fixture_init(&fixture);
    put64(fixture.image, 24u, UINT64_C(0xffffffff80001000));
    expect_rejected(&fixture, BBP_ELF64_ERR_ENTRY,
                    "entry outside every executable segment is rejected");
    fixture_init(&fixture);
    put64(fixture.image, 24u, UINT64_C(0xffffffff80002010));
    expect_rejected(&fixture, BBP_ELF64_ERR_ENTRY,
                    "entry inside a non-executable segment is rejected");
}

static void test_arguments_are_atomic(void)
{
    struct fixture fixture;
    struct bbp_elf64_plan plan;
    struct bbp_elf64_plan before;

    fixture_init(&fixture);
    memset(&plan, 0x5a, sizeof(plan));
    before = plan;
    CHECK(bbp_elf64_plan(NULL, fixture.size, &plan) ==
          BBP_ELF64_ERR_ARGUMENT, "NULL image is rejected");
    CHECK(memcmp(&plan, &before, sizeof(plan)) == 0,
          "argument failure leaves the plan unchanged");
    CHECK(bbp_elf64_plan(fixture.image, fixture.size, NULL) ==
          BBP_ELF64_ERR_ARGUMENT, "NULL plan is rejected");
}

int main(void)
{
    printf("== UEFI bounded ELF64 planner self-test ==\n");
    test_valid_multisegment_bss();
    test_required_elf_identity();
    test_header_bounds_and_capacity();
    test_segment_sizes_and_overflow();
    test_alignment_boundaries();
    test_address_boundaries();
    test_security_and_entry_contract();
    test_arguments_are_atomic();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
