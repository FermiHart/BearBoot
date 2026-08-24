/*
 * Bare-metal AArch64 BBP round-trip under QEMU virt.
 *
 * QEMU enters with its FDT pointer in X0. The producer copies that exact DTB
 * into a BBP arena, seals a v1.1 handoff, then the assembly trampoline enters
 * the consumer with the physical INFO pointer in X0 as required by the ABI.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

#define PL011_BASE       0x09000000u
#define PL011_FR_TXFF    (1u << 5)
#define FDT_MAGIC        0xd00dfeedu
#define FDT_HEADER_SIZE  40u
#define FDT_MAX_SIZE     (2u * 1024u * 1024u)
#define RAM_BASE         0x40000000ull
#define RAM_END          0x48000000ull
#define IMAGE_BASE       0x40080000ull
#define PAGE_SIZE        4096ull
#define HANDOFF_SIZE     (FDT_MAX_SIZE + 64u * 1024u)

static uint8_t handoff[HANDOFF_SIZE] __attribute__((aligned(16)));

extern uint8_t _start[];
extern uint8_t __image_end[];

void bbp_aarch64_handoff(const struct bbp_info *info)
    __attribute__((noreturn));

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void serial_putc(char c)
{
    volatile uint32_t *dr = (volatile uint32_t *)(uintptr_t)PL011_BASE;
    volatile uint32_t *fr = (volatile uint32_t *)(uintptr_t)(PL011_BASE + 0x18u);
    while ((*fr & PL011_FR_TXFF) != 0) { }
    *dr = (uint32_t)(uint8_t)c;
}

static void serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') serial_putc('\r');
        serial_putc(*s++);
    }
}

static void serial_hex(uint64_t value)
{
    int shift;
    serial_puts("0x");
    for (shift = 60; shift >= 0; shift -= 4)
        serial_putc("0123456789abcdef"[(value >> shift) & 0xfu]);
}

static void qemu_exit(uint64_t status) __attribute__((noreturn));
static void qemu_exit(uint64_t status)
{
    uint64_t block[2] __attribute__((aligned(16))) = { 0x20026u, status };
    register uint64_t operation __asm__("x0") = 0x20u;
    register const void *argument __asm__("x1") = block;
    __asm__ volatile("hlt #0xf000" : : "r"(operation), "r"(argument) : "memory");
    for (;;) __asm__ volatile("wfe");
}

static void fail(const char *why) __attribute__((noreturn));
static void fail(const char *why)
{
    serial_puts("BBP-AARCH64: FAIL: ");
    serial_puts(why);
    serial_puts("\n");
    qemu_exit(35u);
}

static uint64_t align_down(uint64_t value)
{
    return value & ~(PAGE_SIZE - 1u);
}

static uint64_t align_up(uint64_t value)
{
    return (value + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
}

static void memory_entry(struct bbp_memory_entry *entry, uint64_t base,
                         uint64_t end, uint32_t type, uint32_t attributes)
{
    entry->base = base;
    entry->length = end - base;
    entry->type = type;
    entry->attributes = attributes;
}

static uint32_t validate_fdt(const uint8_t *fdt)
{
    uintptr_t address = (uintptr_t)fdt;
    uint32_t total;
    uint32_t struct_offset;
    uint32_t strings_offset;
    uint32_t reserve_offset;
    uint32_t struct_size;
    uint32_t strings_size;

    if (!fdt || (address & 7u) != 0) fail("invalid FDT pointer");
    if (address < RAM_BASE || address > RAM_END - FDT_HEADER_SIZE)
        fail("FDT outside RAM");
    if (read_be32(fdt) != FDT_MAGIC) fail("FDT magic");

    total = read_be32(fdt + 4);
    if (total <= FDT_HEADER_SIZE || total > FDT_MAX_SIZE
        || (uint64_t)address + total > RAM_END)
        fail("FDT extent");

    struct_offset = read_be32(fdt + 8);
    strings_offset = read_be32(fdt + 12);
    reserve_offset = read_be32(fdt + 16);
    strings_size = read_be32(fdt + 32);
    struct_size = read_be32(fdt + 36);
    if (reserve_offset >= total || struct_offset > total
        || struct_size > total - struct_offset || strings_offset > total
        || strings_size > total - strings_offset)
        fail("FDT sections");
    return total;
}

void aarch64_producer(const void *fdt_pointer)
{
    const uint8_t *fdt = (const uint8_t *)fdt_pointer;
    uint32_t fdt_size;
    uint64_t image_end;
    uint64_t fdt_page;
    uint64_t fdt_end;
    uint32_t entry_count = 0;
    size_t memory_tag_size;
    struct bbp_info *info = (struct bbp_info *)handoff;
    struct bbp_builder builder;
    struct bbp_tag_memory_map *memory;
    struct bbp_memory_entry *entries;
    struct bbp_tag_kernel_address *kernel;
    struct bbp_tag_devicetree *devicetree;
    bbp_phys_t copied_fdt;

    serial_puts("BBP-AARCH64: QEMU FDT in X0, building handoff\n");
    if (bbp_crc64("123456789", 9) != 0x995dc9bbdf1939faull)
        fail("CRC vector");
    fdt_size = validate_fdt(fdt);

    image_end = align_up((uint64_t)(uintptr_t)__image_end);
    fdt_page = align_down((uint64_t)(uintptr_t)fdt);
    fdt_end = align_up((uint64_t)(uintptr_t)fdt + fdt_size);
    if ((uint64_t)(uintptr_t)_start != IMAGE_BASE || image_end >= fdt_page
        || fdt_page < IMAGE_BASE || fdt_end > RAM_END)
        fail("unexpected QEMU memory layout");

    entry_count = 5;
    memory_tag_size = sizeof(*memory)
                    + entry_count * sizeof(struct bbp_memory_entry);
    bbp_builder_init(&builder, handoff + sizeof(*info),
                     (bbp_phys_t)(uintptr_t)(handoff + sizeof(*info)),
                     sizeof(handoff) - sizeof(*info));

    memory = bbp_alloc_tag(&builder, BBP_TAG_MEMORY_MAP, 1, memory_tag_size);
    if (!memory) fail("memory-map allocation");
    memory->entry_count = entry_count;
    memory->entry_size = sizeof(struct bbp_memory_entry);
    entries = (struct bbp_memory_entry *)((uint8_t *)memory + sizeof(*memory));
    memory_entry(&entries[0], RAM_BASE, IMAGE_BASE, BBP_MEM_RESERVED,
                 BBP_MEM_ATTR_READABLE);
    memory_entry(&entries[1], IMAGE_BASE, image_end, BBP_MEM_KERNEL_AND_MODULES,
                 BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE
                 | BBP_MEM_ATTR_EXECUTABLE | BBP_MEM_ATTR_CACHED);
    memory_entry(&entries[2], image_end, fdt_page, BBP_MEM_USABLE,
                 BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE
                 | BBP_MEM_ATTR_CACHED);
    memory_entry(&entries[3], fdt_page, fdt_end, BBP_MEM_BOOTLOADER_RECLAIM,
                 BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_CACHED);
    memory_entry(&entries[4], fdt_end, RAM_END, BBP_MEM_USABLE,
                 BBP_MEM_ATTR_READABLE | BBP_MEM_ATTR_WRITABLE
                 | BBP_MEM_ATTR_CACHED);

    kernel = bbp_alloc_tag(&builder, BBP_TAG_KERNEL_ADDRESS, 1, sizeof(*kernel));
    if (!kernel) fail("kernel-address allocation");
    kernel->physical_base = IMAGE_BASE;
    kernel->virtual_base = IMAGE_BASE;

    devicetree = bbp_alloc_tag(&builder, BBP_TAG_DEVICETREE, 1,
                               sizeof(*devicetree));
    if (!devicetree) fail("devicetree allocation");
    copied_fdt = bbp_arena_blob(&builder, fdt, fdt_size);
    if (!copied_fdt) fail("FDT copy");
    devicetree->dtb_address = copied_fdt;
    devicetree->dtb_size = fdt_size;
    devicetree->dtb_crc = bbp_crc64((const void *)(uintptr_t)copied_fdt,
                                    fdt_size);

    info->architecture = BBP_ARCH_AARCH64;
    info->cpu_count = 1;
    if (bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info)
            != (bbp_phys_t)(uintptr_t)info || builder.overflow)
        fail("builder finalize");

    serial_puts("BBP-AARCH64: sealed DTB bytes=");
    serial_hex(fdt_size);
    serial_puts(", transferring INFO in X0\n");
    bbp_aarch64_handoff(info);
}

void aarch64_consumer(const struct bbp_info *info)
{
    struct bbp_kctx context;
    const struct bbp_tag_header *tag;
    const struct bbp_tag_memory_map *memory;
    const struct bbp_tag_kernel_address *kernel;
    struct bbp_tag_devicetree *devicetree;
    const struct bbp_memory_entry *entries;
    uint8_t *fdt;
    uint32_t count = 0;

    if ((uintptr_t)info != (uintptr_t)handoff)
        fail("X0 handoff pointer");
    if (info->architecture != BBP_ARCH_AARCH64 || info->cpu_count != 1)
        fail("AArch64 INFO identity");
    if (info->tag_count != 3) fail("tag count");
    if (bbp_init_bounded(&context, info, 0,
            (bbp_phys_t)(uintptr_t)(handoff + sizeof(*info)),
            sizeof(handoff) - sizeof(*info)) != BBP_OK)
        fail("bounded parser");
    if (context.hhdm_offset != 0
        || bbp_find_tag(&context, BBP_TAG_HHDM) != NULL)
        fail("invented HHDM");

    tag = bbp_find_tag(&context, BBP_TAG_MEMORY_MAP);
    if (!tag || tag->tag_size < sizeof(*memory)) fail("memory-map tag");
    memory = (const struct bbp_tag_memory_map *)tag;
    entries = bbp_tag_array(tag, sizeof(*memory),
                            sizeof(struct bbp_memory_entry),
                            memory->entry_count, &count);
    if (count != 5 || entries[1].base != IMAGE_BASE
        || entries[1].type != BBP_MEM_KERNEL_AND_MODULES)
        fail("memory-map semantics");

    tag = bbp_find_tag(&context, BBP_TAG_KERNEL_ADDRESS);
    if (!tag || tag->tag_size < sizeof(*kernel)) fail("kernel-address tag");
    kernel = (const struct bbp_tag_kernel_address *)tag;
    if (kernel->physical_base != IMAGE_BASE || kernel->virtual_base != IMAGE_BASE)
        fail("kernel-address semantics");

    tag = bbp_find_tag(&context, BBP_TAG_DEVICETREE);
    if (!tag || tag->tag_size < sizeof(*devicetree)) fail("devicetree tag");
    devicetree = (struct bbp_tag_devicetree *)(uintptr_t)tag;
    if (devicetree->dtb_size < FDT_HEADER_SIZE
        || bbp_verify_blob(&context, devicetree->dtb_address,
                           devicetree->dtb_size, devicetree->dtb_crc, 0) != BBP_OK)
        fail("DTB verification");
    fdt = (uint8_t *)(uintptr_t)devicetree->dtb_address;
    if (read_be32(fdt) != FDT_MAGIC) fail("copied FDT magic");

    fdt[FDT_HEADER_SIZE] ^= 1u;
    if (bbp_verify_blob(&context, devicetree->dtb_address,
                        devicetree->dtb_size, devicetree->dtb_crc, 0)
            != BBP_ERR_TAG_CHECKSUM)
        fail("DTB tamper accepted");
    fdt[FDT_HEADER_SIZE] ^= 1u;

    devicetree->flags ^= 1u;
    if (bbp_find_tag(&context, BBP_TAG_DEVICETREE) != NULL)
        fail("tag tamper accepted");
    devicetree->flags ^= 1u;
    if (bbp_find_tag(&context, BBP_TAG_DEVICETREE) == NULL)
        fail("tag restore rejected");

    serial_puts("BBP-AARCH64: X0 + bounded parser + DTB CRC verified\n");
    serial_puts("BBP-AARCH64: PASS\n");
    qemu_exit(33u);
}
