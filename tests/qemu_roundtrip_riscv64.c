/* OpenSBI/QEMU RV64 proof: platform DTB in A1, BearBoot INFO in A0.
 * SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

#define UART_BASE        0x10000000u
#define TEST_BASE        0x00100000u
#define FDT_MAGIC        0xd00dfeedu
#define FDT_HEADER_SIZE  40u
#define FDT_MAX_SIZE     (2u * 1024u * 1024u)
#define RAM_BASE         0x80000000ull
#define RAM_END          0x88000000ull
#define IMAGE_BASE       0x80200000ull
#define PAGE_SIZE        4096ull
#define HANDOFF_SIZE     (FDT_MAX_SIZE + 64u * 1024u)

static uint8_t handoff[HANDOFF_SIZE] __attribute__((aligned(16)));
extern uint8_t _start[];
extern uint8_t __image_end[];
void bbp_riscv64_handoff(const struct bbp_info *) __attribute__((noreturn));

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | p[3];
}

static void putc(char c)
{
    volatile uint8_t *uart = (volatile uint8_t *)(uintptr_t)UART_BASE;
    while ((uart[5] & 0x20u) == 0) { }
    uart[0] = (uint8_t)c;
}

static void puts(const char *s)
{
    while (*s) {
        if (*s == '\n') putc('\r');
        putc(*s++);
    }
}

static void finish(uint32_t value) __attribute__((noreturn));
static void finish(uint32_t value)
{
    __asm__ volatile("fence iorw, iorw" : : : "memory");
    *(volatile uint32_t *)(uintptr_t)TEST_BASE = value;
    for (;;) __asm__ volatile("wfi");
}

static void fail(const char *why) __attribute__((noreturn));
static void fail(const char *why)
{
    puts("BBP-RISCV64: FAIL: ");
    puts(why);
    puts("\n");
    finish((35u << 16) | 0x3333u);
}

static uint64_t down(uint64_t value) { return value & ~(PAGE_SIZE - 1u); }
static uint64_t up(uint64_t value)
{
    return (value + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
}

static uint32_t validate_fdt(const uint8_t *fdt)
{
    uintptr_t address = (uintptr_t)fdt;
    uint32_t total;
    uint32_t structure;
    uint32_t strings;
    uint32_t structure_size;
    uint32_t strings_size;
    if (!fdt || (address & 7u) != 0) fail("invalid FDT pointer");
    if (address < RAM_BASE || address > RAM_END - FDT_HEADER_SIZE)
        fail("FDT outside RAM");
    if (be32(fdt) != FDT_MAGIC) fail("FDT magic");
    total = be32(fdt + 4);
    if (total <= FDT_HEADER_SIZE || total > FDT_MAX_SIZE
        || (uint64_t)address + total > RAM_END)
        fail("FDT extent");
    structure = be32(fdt + 8);
    strings = be32(fdt + 12);
    strings_size = be32(fdt + 32);
    structure_size = be32(fdt + 36);
    if (be32(fdt + 16) >= total || structure > total
        || structure_size > total - structure || strings > total
        || strings_size > total - strings)
        fail("FDT sections");
    return total;
}

static void set_entry(struct bbp_memory_entry *e, uint64_t base, uint64_t end,
                      uint32_t type, uint32_t attributes)
{
    e->base = base;
    e->length = end - base;
    e->type = type;
    e->attributes = attributes;
}

void riscv64_producer(const void *fdt_pointer)
{
    const uint8_t *fdt = fdt_pointer;
    uint32_t fdt_size = validate_fdt(fdt);
    uint64_t image_end = up((uint64_t)(uintptr_t)__image_end);
    uint64_t fdt_base = down((uint64_t)(uintptr_t)fdt);
    uint64_t fdt_end = up((uint64_t)(uintptr_t)fdt + fdt_size);
    struct bbp_info *info = (struct bbp_info *)handoff;
    struct bbp_builder builder;
    struct bbp_tag_memory_map *memory;
    struct bbp_memory_entry *entries;
    struct bbp_tag_kernel_address *kernel;
    struct bbp_tag_devicetree *dt;
    bbp_phys_t copied;
    uint64_t source_crc;
    size_t mm_size = sizeof(*memory) + 5u * sizeof(*entries);

    puts("BBP-RISCV64: OpenSBI DTB in A1, building handoff\n");
    if (bbp_crc64("123456789", 9) != 0x995dc9bbdf1939faull)
        fail("CRC vector");
    if ((uintptr_t)_start != IMAGE_BASE || image_end >= fdt_base
        || fdt_end > RAM_END)
        fail("unexpected QEMU memory layout");

    bbp_builder_init(&builder, handoff + sizeof(*info),
        (bbp_phys_t)(uintptr_t)(handoff + sizeof(*info)),
        sizeof(handoff) - sizeof(*info));
    memory = bbp_alloc_tag(&builder, BBP_TAG_MEMORY_MAP, 1, mm_size);
    if (!memory) fail("memory-map allocation");
    memory->entry_count = 5;
    memory->entry_size = sizeof(*entries);
    entries = (void *)((uint8_t *)memory + sizeof(*memory));
    set_entry(&entries[0], RAM_BASE, IMAGE_BASE, BBP_MEM_RESERVED,
              BBP_MEM_ATTR_READABLE);
    set_entry(&entries[1], IMAGE_BASE, image_end, BBP_MEM_KERNEL_AND_MODULES,
              BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE
              | BBP_MEM_ATTR_EXECUTABLE | BBP_MEM_ATTR_CACHED);
    set_entry(&entries[2], image_end, fdt_base, BBP_MEM_USABLE,
              BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_CACHED);
    set_entry(&entries[3], fdt_base, fdt_end, BBP_MEM_BOOTLOADER_RECLAIM,
              BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE
              | BBP_MEM_ATTR_CACHED);
    set_entry(&entries[4], fdt_end, RAM_END, BBP_MEM_USABLE,
              BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE | BBP_MEM_ATTR_CACHED);

    kernel = bbp_alloc_tag(&builder, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*kernel));
    if (!kernel) fail("kernel-address allocation");
    kernel->physical_base = IMAGE_BASE;
    kernel->virtual_base = IMAGE_BASE;
    dt = bbp_alloc_tag(&builder, BBP_TAG_DEVICETREE, 1, sizeof(*dt));
    if (!dt) fail("devicetree allocation");
    source_crc = bbp_crc64(fdt, fdt_size);
    copied = bbp_arena_blob(&builder, fdt, fdt_size);
    if (!copied) fail("FDT copy");
    dt->dtb_address = copied;
    dt->dtb_size = fdt_size;
    dt->dtb_crc = source_crc;
    info->architecture = BBP_ARCH_RISCV64;
    info->cpu_count = 1;
    if (bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info)
            != (bbp_phys_t)(uintptr_t)info || builder.overflow)
        fail("builder finalize");
    puts("BBP-RISCV64: transferring INFO in A0\n");
    bbp_riscv64_handoff(info);
}

void riscv64_consumer(const struct bbp_info *info)
{
    struct bbp_kctx context;
    const struct bbp_tag_header *tag;
    const struct bbp_tag_memory_map *memory;
    const struct bbp_memory_entry *entries;
    const struct bbp_tag_kernel_address *kernel;
    struct bbp_tag_devicetree *dt;
    uint8_t *fdt;
    uint32_t count;
    if ((uintptr_t)info != (uintptr_t)handoff) fail("A0 handoff pointer");
    if (info->architecture != BBP_ARCH_RISCV64 || info->cpu_count != 1)
        fail("RV64 INFO identity");
    if (bbp_init_bounded(&context, info, 0,
            (bbp_phys_t)(uintptr_t)(handoff + sizeof(*info)),
            sizeof(handoff) - sizeof(*info)) != BBP_OK)
        fail("bounded parser");
    if (context.hhdm_offset != 0 || bbp_find_tag(&context, BBP_TAG_HHDM))
        fail("invented HHDM");
    tag = bbp_find_tag(&context, BBP_TAG_MEMORY_MAP);
    if (!tag || tag->tag_size < sizeof(*memory)) fail("memory-map tag");
    memory = (const void *)tag;
    entries = bbp_tag_array(tag, sizeof(*memory), sizeof(*entries),
                            memory->entry_count, &count);
    if (memory->entry_size != sizeof(*entries) || count != 5
        || entries[0].base != RAM_BASE || entries[0].type != BBP_MEM_RESERVED
        || entries[1].base != IMAGE_BASE
        || entries[1].type != BBP_MEM_KERNEL_AND_MODULES
        || entries[3].type != BBP_MEM_BOOTLOADER_RECLAIM
        || entries[4].base + entries[4].length != RAM_END)
        fail("memory-map semantics");
    tag = bbp_find_tag(&context, BBP_TAG_KERNEL_ADDRESS);
    if (!tag || tag->tag_size < sizeof(*kernel)) fail("kernel-address tag");
    kernel = (const void *)tag;
    if (kernel->physical_base != IMAGE_BASE || kernel->virtual_base != IMAGE_BASE)
        fail("kernel-address semantics");
    tag = bbp_find_tag(&context, BBP_TAG_DEVICETREE);
    if (!tag || tag->tag_size < sizeof(*dt)) fail("devicetree tag");
    dt = (void *)(uintptr_t)tag;
    if (bbp_verify_blob(&context, dt->dtb_address, dt->dtb_size,
                        dt->dtb_crc, 0) != BBP_OK)
        fail("DTB verification");
    fdt = (void *)(uintptr_t)dt->dtb_address;
    fdt[FDT_HEADER_SIZE] ^= 1u;
    if (bbp_verify_blob(&context, dt->dtb_address, dt->dtb_size,
                        dt->dtb_crc, 0) != BBP_ERR_TAG_CHECKSUM)
        fail("DTB tamper accepted");
    fdt[FDT_HEADER_SIZE] ^= 1u;
    dt->flags ^= 1u;
    if (bbp_find_tag(&context, BBP_TAG_DEVICETREE)) fail("tag tamper accepted");
    dt->flags ^= 1u;
    if (!bbp_find_tag(&context, BBP_TAG_DEVICETREE)) fail("tag restore rejected");
    puts("BBP-RISCV64: A0 + bounded parser + DTB CRC verified\n");
    puts("BBP-RISCV64: PASS\n");
    finish(0x5555u);
}
