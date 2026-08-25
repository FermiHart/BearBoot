/* Higher-half proof kernel entered by bootloader/efi_main.c with physical INFO in RDI. */
#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp.h>
#include "../kernel/bbp_kernel.h"

#define PROOF_HHDM UINT64_C(0xffff800000000000)
#define PROOF_PHYSICAL_BASE UINT64_C(0x00400000)
#define PROOF_VIRTUAL_BASE UINT64_C(0xffffffff80000000)

__attribute__((used))
const struct bbp_tag_request bbp_requests[] = {
    {BBP_TAG_HHDM, 0u, 0u},
    {BBP_TAG_MEMORY_MAP, 0u, 0u},
    {BBP_TAG_KERNEL_ADDRESS, 0u, 0u}
};

__attribute__((section(".bbp_hdr"), used, aligned(8)))
const struct bbp_header bbp_kernel_header = {
    .magic = BBP_HEADER_MAGIC,
    .version_major = BBP_VERSION_MAJOR,
    .version_minor = BBP_VERSION_MINOR,
    .header_size = sizeof(struct bbp_header),
    .flags = BBP_HF_UNMAP_NULL_PAGE,
    .entry_point = 0u,
    .paging_mode = BBP_PAGING_4LEVEL,
    .kernel_virtual_base = PROOF_VIRTUAL_BASE,
    .request_count = sizeof(bbp_requests) / sizeof(bbp_requests[0]),
    .reserved0 = 0u,
    .requests = 0u,
    .kernel_uuid = {UINT64_C(0x5741564531370001), UINT64_C(0x4f564d46454c4636)},
    .kernel_name = "bearboot-wave17-ovmf-proof",
    .checksum = 0u
};

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

static void serial_puts(const char *text)
{
    while (*text != 0) {
        if (*text == '\n') {
            while ((inb(0x3fd) & 0x20u) == 0u) { }
            outb(0x3f8, '\r');
        }
        while ((inb(0x3fd) & 0x20u) == 0u) { }
        outb(0x3f8, (uint8_t)*text++);
    }
}

__attribute__((noreturn)) static void finish(uint8_t status, const char *text)
{
    serial_puts(text);
    outb(0xf4, status);
    for (;;) __asm__ volatile("hlt");
}

static int memory_map_valid(const struct bbp_tag_memory_map *map)
{
    const struct bbp_memory_entry *entries;
    uint32_t count = 0u;
    uint32_t index;
    int have_usable = 0;
    entries = (const struct bbp_memory_entry *)bbp_tag_array(
        &map->header, sizeof(*map), sizeof(*entries), map->entry_count, &count);
    if (map->entry_size != sizeof(*entries) || count == 0u ||
        count != map->entry_count)
        return 0;
    for (index = 0u; index < count; index++) {
        if (entries[index].length == 0u) return 0;
        if (entries[index].type == BBP_MEM_USABLE) have_usable = 1;
    }
    return have_usable;
}

__attribute__((noreturn)) void proof_main(const struct bbp_info *physical_info)
{
    struct bbp_kctx context;
    const struct bbp_tag_hhdm *hhdm;
    const struct bbp_tag_memory_map *map;
    const struct bbp_tag_kernel_address *kernel;
    const struct bbp_info *hhdm_info;
    uintptr_t info_address = (uintptr_t)physical_info;

    serial_puts("BBP-UEFI-LOADER: higher-half kernel entry\n");
    if (info_address == 0u || info_address >= UINT64_C(0x100000000) ||
        physical_info->info_size < sizeof(*physical_info))
        finish(0x11, "BBP-UEFI-LOADER: FAIL: physical RDI\n");
    if (bbp_init_bounded(&context, physical_info, 0u,
            (bbp_phys_t)(info_address + sizeof(*physical_info)),
            physical_info->info_size - sizeof(*physical_info)) != BBP_OK)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: INFO parser\n");
    if (context.hhdm_offset != PROOF_HHDM)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: HHDM adoption\n");

    hhdm_info = (const struct bbp_info *)(uintptr_t)(info_address + PROOF_HHDM);
    if (hhdm_info->checksum != physical_info->checksum)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: HHDM mapping\n");
    hhdm = (const struct bbp_tag_hhdm *)bbp_find_tag(&context, BBP_TAG_HHDM);
    map = (const struct bbp_tag_memory_map *)bbp_find_tag(
        &context, BBP_TAG_MEMORY_MAP);
    kernel = (const struct bbp_tag_kernel_address *)bbp_find_tag(
        &context, BBP_TAG_KERNEL_ADDRESS);
    if (hhdm == NULL || hhdm->header.tag_size != sizeof(*hhdm) ||
        hhdm->offset != PROOF_HHDM)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: HHDM tag\n");
    if (map == NULL || !memory_map_valid(map))
        finish(0x11, "BBP-UEFI-LOADER: FAIL: MEMORY_MAP tag\n");
    if (kernel == NULL || kernel->header.tag_size != sizeof(*kernel) ||
        kernel->physical_base != PROOF_PHYSICAL_BASE ||
        kernel->virtual_base != PROOF_VIRTUAL_BASE)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: KERNEL_ADDRESS tag\n");
    if (physical_info->tag_count != 3u ||
        physical_info->architecture != BBP_ARCH_X86_64)
        finish(0x11, "BBP-UEFI-LOADER: FAIL: INFO metadata\n");
    finish(0x10, "BBP-UEFI-LOADER: PASS ELF64 HEADER EBS PAGING HHDM TAGS RDI\n");
}

__attribute__((naked, used, noreturn)) void _start(void)
{
    __asm__ volatile(
        "xorq %rbp, %rbp\n\t"
        "callq proof_main\n\t"
        "1: hlt\n\t"
        "jmp 1b\n\t");
}
