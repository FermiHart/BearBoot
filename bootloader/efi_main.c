/*
 * Dependency-free x86_64 UEFI ELF64 loader proof for Bear Boot Protocol v1.1.
 * It deliberately supports only the three required proof tags and 4-level
 * paging; unsupported required kernel requests fail closed.
 */
#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp.h>

#include "bbp_build.h"
#include "../kernel/bbp_kernel.h"
#include "uefi/elf64_loader.h"
#include "uefi/uefi_exit.h"
#include "uefi/uefi_min.h"

#define BBP_ARENA_PAGES 256u
#define BBP_STACK_PAGES 16u
#define BBP_PAGE_TABLE_PAGES 32u
#define BBP_IDENTITY_LIMIT UINT64_C(0x100000000)
#define BBP_HHDM_OFFSET UINT64_C(0xffff800000000000)
#define BBP_MAX_KERNEL_FILE (16u * 1024u * 1024u)
#define BBP_MAX_REQUESTS 64u
#define BBP_SUPPORTED_HEADER_FLAGS ((uint64_t)BBP_HF_UNMAP_NULL_PAGE)

#define X86_PTE_PRESENT UINT64_C(1)
#define X86_PTE_WRITABLE UINT64_C(2)
#define X86_PTE_LARGE UINT64_C(0x80)
#define X86_PTE_NX (UINT64_C(1) << 63)

struct page_pool {
    uint64_t base;
    size_t used;
    size_t count;
};

struct firmware_context {
    EFI_BOOT_SERVICES *boot;
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

static void serial_init(void)
{
    outb(0x3f9, 0x00);
    outb(0x3fb, 0x80);
    outb(0x3f8, 0x01);
    outb(0x3f9, 0x00);
    outb(0x3fb, 0x03);
    outb(0x3fa, 0xc7);
    outb(0x3fc, 0x0b);
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

static EFI_STATUS fail(const char *reason)
{
    serial_puts("BBP-UEFI-LOADER: FAIL: ");
    serial_puts(reason);
    serial_puts("\n");
    outb(0xf4, 0x11);
    return EFI_LOAD_ERROR;
}

__attribute__((noreturn)) static void fail_after_exit(const char *reason)
{
    (void)fail(reason);
    for (;;) __asm__ volatile("hlt");
}

static void bytes_zero(void *destination, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    while (size-- != 0u) *out++ = 0u;
}

static void bytes_copy(void *destination, const void *source, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    const uint8_t *in = (const uint8_t *)source;
    while (size-- != 0u) *out++ = *in++;
}

static int bytes_equal(const void *left, const void *right, size_t size)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    while (size-- != 0u) {
        if (*a++ != *b++) return 0;
    }
    return 1;
}

/* Clang may still lower fixed-size freestanding copies/clears to these names. */
void *memcpy(void *destination, const void *source, size_t size)
{
    bytes_copy(destination, source, size);
    return destination;
}

void *memset(void *destination, int value, size_t size)
{
    uint8_t *out = (uint8_t *)destination;
    while (size-- != 0u) *out++ = (uint8_t)value;
    return destination;
}

static EFI_STATUS allocate_low_pages(EFI_BOOT_SERVICES *boot, size_t pages,
                                     uint64_t *address)
{
    EFI_PHYSICAL_ADDRESS physical = BBP_IDENTITY_LIMIT - 1u;
    EFI_STATUS status = boot->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                            pages, &physical);
    if (status == EFI_SUCCESS) {
        bytes_zero((void *)(uintptr_t)physical, pages * EFI_PAGE_SIZE);
        *address = physical;
    }
    return status;
}

static EFI_STATUS read_kernel(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table,
                              void **file_bytes, size_t *file_size,
                              EFI_LOADED_IMAGE_PROTOCOL **loaded_image)
{
    EFI_BOOT_SERVICES *boot = system_table->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *filesystem = NULL;
    EFI_FILE_PROTOCOL *root = NULL;
    EFI_FILE_PROTOCOL *file = NULL;
    EFI_FILE_INFO_PREFIX *info = NULL;
    EFI_UINTN info_size = 0u;
    EFI_UINTN done = 0u;
    void *buffer = NULL;
    EFI_STATUS status;
    static CHAR16 path[] = {'\\', 'k', 'e', 'r', 'n', 'e', 'l', '.',
                            'e', 'l', 'f', 0};

    status = boot->HandleProtocol(image, (EFI_GUID *)&BBP_EFI_LOADED_IMAGE_GUID,
                                  (void **)&loaded);
    if (status != EFI_SUCCESS) return status;
    status = boot->HandleProtocol(loaded->DeviceHandle,
                                  (EFI_GUID *)&BBP_EFI_SIMPLE_FILE_SYSTEM_GUID,
                                  (void **)&filesystem);
    if (status != EFI_SUCCESS) return status;
    status = filesystem->OpenVolume(filesystem, &root);
    if (status != EFI_SUCCESS) return status;
    status = root->Open(root, &file, path, EFI_FILE_MODE_READ, 0u);
    if (status != EFI_SUCCESS) goto out;

    status = file->GetInfo(file, (EFI_GUID *)&BBP_EFI_FILE_INFO_GUID,
                           &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || info_size < sizeof(*info)) {
        status = EFI_LOAD_ERROR;
        goto out;
    }
    status = boot->AllocatePool(EfiLoaderData, info_size, (void **)&info);
    if (status != EFI_SUCCESS) goto out;
    status = file->GetInfo(file, (EFI_GUID *)&BBP_EFI_FILE_INFO_GUID,
                           &info_size, info);
    if (status != EFI_SUCCESS || info->FileSize < 64u ||
        info->FileSize > BBP_MAX_KERNEL_FILE ||
        info->FileSize > (uint64_t)(size_t)-1) {
        status = EFI_LOAD_ERROR;
        goto out;
    }
    status = boot->AllocatePool(EfiLoaderData, (size_t)info->FileSize, &buffer);
    if (status != EFI_SUCCESS) goto out;
    while (done < (EFI_UINTN)info->FileSize) {
        EFI_UINTN amount = (EFI_UINTN)info->FileSize - done;
        status = file->Read(file, &amount, (uint8_t *)buffer + done);
        if (status != EFI_SUCCESS || amount == 0u) {
            status = EFI_LOAD_ERROR;
            goto out;
        }
        done += amount;
    }

    *file_bytes = buffer;
    *file_size = (size_t)info->FileSize;
    *loaded_image = loaded;
    buffer = NULL;
out:
    if (info != NULL) boot->FreePool(info);
    if (file != NULL) file->Close(file);
    if (root != NULL) root->Close(root);
    if (buffer != NULL) boot->FreePool(buffer);
    return status;
}

static EFI_STATUS load_segments(EFI_BOOT_SERVICES *boot, const void *image,
                                 const struct bbp_elf64_plan *plan)
{
    size_t index;
    EFI_STATUS status = EFI_SUCCESS;
    for (index = 0u; index < plan->segment_count; index++) {
        const struct bbp_elf64_segment_plan *segment = &plan->segments[index];
        EFI_PHYSICAL_ADDRESS physical = segment->page_base;
        if (segment->page_count == 0u) continue;
        if (segment->page_base == 0u ||
            segment->page_base + segment->page_count * EFI_PAGE_SIZE >
                BBP_IDENTITY_LIMIT) {
            status = EFI_LOAD_ERROR;
            goto fail;
        }
        status = boot->AllocatePages(AllocateAddress, EfiLoaderData,
                                     (EFI_UINTN)segment->page_count, &physical);
        if (status != EFI_SUCCESS) goto fail;
        if (physical != segment->page_base) {
            (void)boot->FreePages(physical, (EFI_UINTN)segment->page_count);
            status = EFI_LOAD_ERROR;
            goto fail;
        }
        bytes_zero((void *)(uintptr_t)segment->page_base,
                   (size_t)segment->page_count * EFI_PAGE_SIZE);
        bytes_copy((void *)(uintptr_t)segment->physical_address,
                   (const uint8_t *)image + (size_t)segment->file_offset,
                   (size_t)segment->file_size);
    }
    return EFI_SUCCESS;

fail:
    while (index != 0u) {
        const struct bbp_elf64_segment_plan *allocated =
            &plan->segments[--index];
        if (allocated->page_count != 0u)
            (void)boot->FreePages(allocated->page_base,
                                  (EFI_UINTN)allocated->page_count);
    }
    return status;
}

static void free_segments(EFI_BOOT_SERVICES *boot,
                          const struct bbp_elf64_plan *plan)
{
    size_t index;
    for (index = 0u; index < plan->segment_count; index++) {
        const struct bbp_elf64_segment_plan *segment = &plan->segments[index];
        if (segment->page_count != 0u)
            (void)boot->FreePages(segment->page_base,
                                  (EFI_UINTN)segment->page_count);
    }
}

static int physical_range_loaded(const struct bbp_elf64_plan *plan,
                                 uint64_t address, uint64_t size)
{
    size_t index;
    uint64_t end;
    if (size == 0u || address > UINT64_MAX - size) return 0;
    end = address + size;
    for (index = 0u; index < plan->segment_count; index++) {
        const struct bbp_elf64_segment_plan *segment = &plan->segments[index];
        uint64_t segment_end = segment->physical_address + segment->memory_size;
        if (address >= segment->physical_address && end <= segment_end)
            return 1;
    }
    return 0;
}

static const struct bbp_header *find_header(const struct bbp_elf64_plan *plan)
{
    static const uint8_t magic[BBP_MAGIC_LEN] = BBP_HEADER_MAGIC;
    const struct bbp_header *found = NULL;
    size_t segment_index;
    for (segment_index = 0u; segment_index < plan->segment_count;
         segment_index++) {
        const struct bbp_elf64_segment_plan *segment =
            &plan->segments[segment_index];
        uint64_t offset;
        if (segment->file_size < sizeof(struct bbp_header)) continue;
        for (offset = 0u; offset <= segment->file_size - sizeof(struct bbp_header);
             offset += 8u) {
            const struct bbp_header *candidate = (const struct bbp_header *)(
                uintptr_t)(segment->physical_address + offset);
            if (!bytes_equal(candidate->magic, magic, sizeof(magic))) continue;
            if (found != NULL || bbp_verify_header(candidate) != BBP_OK)
                return NULL;
            found = candidate;
        }
    }
    return found;
}

static int validate_header_contract(const struct bbp_header *header,
                                    const struct bbp_elf64_plan *plan)
{
    const struct bbp_tag_request *requests;
    uint64_t actual_virtual_base = 0u;
    unsigned seen = 0u;
    uint32_t index;
    size_t segment_index;
    for (segment_index = 0u; segment_index < plan->segment_count;
         segment_index++) {
        const struct bbp_elf64_segment_plan *segment =
            &plan->segments[segment_index];
        if (segment->page_count != 0u &&
            segment->page_base == plan->physical_base) {
            actual_virtual_base = segment->virtual_address -
                (segment->physical_address - segment->page_base);
            break;
        }
    }
    if (header->entry_point != plan->entry ||
        (header->flags & ~BBP_SUPPORTED_HEADER_FLAGS) != 0u ||
        header->paging_mode != BBP_PAGING_4LEVEL ||
        header->kernel_virtual_base == 0u ||
        header->kernel_virtual_base != actual_virtual_base ||
        header->reserved0 != 0u ||
        header->request_count > BBP_MAX_REQUESTS)
        return 0;
    if (header->request_count == 0u ||
        !physical_range_loaded(plan, header->requests,
            (uint64_t)header->request_count * sizeof(struct bbp_tag_request)))
        return 0;
    requests = (const struct bbp_tag_request *)(uintptr_t)header->requests;
    for (index = 0u; index < header->request_count; index++) {
        uint64_t bit = 0u;
        if (requests[index].reserved != 0u ||
            (requests[index].flags & ~(uint64_t)BBP_REQ_OPTIONAL) != 0u)
            return 0;
        if (requests[index].tag_id == BBP_TAG_HHDM) bit = 1u;
        else if (requests[index].tag_id == BBP_TAG_MEMORY_MAP) bit = 2u;
        else if (requests[index].tag_id == BBP_TAG_KERNEL_ADDRESS) bit = 4u;
        else if ((requests[index].flags & BBP_REQ_OPTIONAL) == 0u) return 0;
        if (bit != 0u && (seen & bit) != 0u) return 0;
        seen |= (unsigned)bit;
    }
    return seen == 7u;
}

static uint64_t table_new(struct page_pool *pool)
{
    uint64_t address;
    if (pool->used == pool->count) return 0u;
    address = pool->base + pool->used * EFI_PAGE_SIZE;
    pool->used++;
    return address;
}

static int map_page(struct page_pool *pool, uint64_t pml4_address,
                    uint64_t virtual_address, uint64_t physical_address,
                    uint64_t flags)
{
    uint64_t *table = (uint64_t *)(uintptr_t)pml4_address;
    unsigned shifts[3] = {39u, 30u, 21u};
    unsigned level;
    for (level = 0u; level < 3u; level++) {
        size_t index = (size_t)((virtual_address >> shifts[level]) & 0x1ffu);
        if ((table[index] & X86_PTE_PRESENT) == 0u) {
            uint64_t next = table_new(pool);
            if (next == 0u) return 0;
            table[index] = next | X86_PTE_PRESENT | X86_PTE_WRITABLE;
        }
        if ((table[index] & X86_PTE_LARGE) != 0u) return 0;
        table = (uint64_t *)(uintptr_t)(table[index] & UINT64_C(0x000ffffffffff000));
    }
    {
        size_t index = (size_t)((virtual_address >> 12u) & 0x1ffu);
        if ((table[index] & X86_PTE_PRESENT) != 0u) return 0;
        table[index] = (physical_address & UINT64_C(0x000ffffffffff000)) |
                       flags | X86_PTE_PRESENT;
    }
    return 1;
}

static int build_page_tables(struct page_pool *pool,
                              const struct bbp_elf64_plan *plan,
                              int enable_nx, int unmap_null,
                              uint64_t *out_pml4)
{
    uint64_t pml4_address = table_new(pool);
    uint64_t identity_pdpt = table_new(pool);
    uint64_t hhdm_pdpt = table_new(pool);
    uint64_t *pml4;
    unsigned gb;
    size_t segment_index;
    if (pml4_address == 0u || identity_pdpt == 0u || hhdm_pdpt == 0u)
        return 0;
    pml4 = (uint64_t *)(uintptr_t)pml4_address;
    pml4[0] = identity_pdpt | X86_PTE_PRESENT | X86_PTE_WRITABLE;
    pml4[256] = hhdm_pdpt | X86_PTE_PRESENT | X86_PTE_WRITABLE;

    for (gb = 0u; gb < 4u; gb++) {
        uint64_t identity_pd = table_new(pool);
        uint64_t hhdm_pd = table_new(pool);
        uint64_t *identity_entries;
        uint64_t *hhdm_entries;
        unsigned mb;
        if (identity_pd == 0u || hhdm_pd == 0u) return 0;
        ((uint64_t *)(uintptr_t)identity_pdpt)[gb] =
            identity_pd | X86_PTE_PRESENT | X86_PTE_WRITABLE;
        ((uint64_t *)(uintptr_t)hhdm_pdpt)[gb] =
            hhdm_pd | X86_PTE_PRESENT | X86_PTE_WRITABLE;
        identity_entries = (uint64_t *)(uintptr_t)identity_pd;
        hhdm_entries = (uint64_t *)(uintptr_t)hhdm_pd;
        for (mb = 0u; mb < 512u; mb++) {
            uint64_t physical = (uint64_t)gb * UINT64_C(0x40000000) +
                                (uint64_t)mb * UINT64_C(0x200000);
            hhdm_entries[mb] = physical | X86_PTE_PRESENT |
                X86_PTE_WRITABLE | X86_PTE_LARGE;
            if (physical != 0u) {
                identity_entries[mb] = physical | X86_PTE_PRESENT |
                    X86_PTE_WRITABLE | X86_PTE_LARGE;
            } else {
                uint64_t first_pt = table_new(pool);
                unsigned page;
                if (first_pt == 0u) return 0;
                identity_entries[mb] = first_pt | X86_PTE_PRESENT |
                    X86_PTE_WRITABLE;
                for (page = unmap_null ? 1u : 0u; page < 512u; page++)
                    ((uint64_t *)(uintptr_t)first_pt)[page] =
                        (uint64_t)page * EFI_PAGE_SIZE | X86_PTE_PRESENT |
                        X86_PTE_WRITABLE;
            }
        }
    }

    for (segment_index = 0u; segment_index < plan->segment_count;
         segment_index++) {
        const struct bbp_elf64_segment_plan *segment =
            &plan->segments[segment_index];
        uint64_t delta = segment->physical_address - segment->page_base;
        uint64_t virtual_page = segment->virtual_address - delta;
        uint64_t page;
        uint64_t flags = 0u;
        if ((segment->flags & BBP_ELF64_PF_W) != 0u)
            flags |= X86_PTE_WRITABLE;
        if (enable_nx && (segment->flags & BBP_ELF64_PF_X) == 0u)
            flags |= X86_PTE_NX;
        for (page = 0u; page < segment->page_count; page++) {
            if (!map_page(pool, pml4_address,
                          virtual_page + page * EFI_PAGE_SIZE,
                          segment->page_base + page * EFI_PAGE_SIZE, flags))
                return 0;
        }
    }
    *out_pml4 = pml4_address;
    return 1;
}

static bbp_uefi_firmware_status firmware_get_map(
    void *context, size_t *map_size, void *map, uintptr_t *key,
    size_t *descriptor_size, uint32_t *descriptor_version)
{
    struct firmware_context *firmware = (struct firmware_context *)context;
    EFI_STATUS status = firmware->boot->GetMemoryMap(
        (EFI_UINTN *)map_size, (EFI_MEMORY_DESCRIPTOR *)map, (EFI_UINTN *)key,
        (EFI_UINTN *)descriptor_size, descriptor_version);
    if (status == EFI_SUCCESS) return BBP_UEFI_FIRMWARE_SUCCESS;
    if (status == EFI_BUFFER_TOO_SMALL)
        return BBP_UEFI_FIRMWARE_BUFFER_TOO_SMALL;
    if (status == EFI_INVALID_PARAMETER)
        return BBP_UEFI_FIRMWARE_INVALID_PARAMETER;
    return BBP_UEFI_FIRMWARE_ERROR;
}

static int preflight_memory_geometry(EFI_BOOT_SERVICES *boot)
{
    EFI_MEMORY_DESCRIPTOR *map = NULL;
    EFI_UINTN capacity = 0u;
    unsigned attempt;
    for (attempt = 0u; attempt < 3u; attempt++) {
        EFI_UINTN map_size = capacity;
        EFI_UINTN key = 0u;
        EFI_UINTN descriptor_size = 0u;
        uint32_t descriptor_version = 0u;
        EFI_STATUS status = boot->GetMemoryMap(
            &map_size, map, &key, &descriptor_size, &descriptor_version);
        size_t index;
        if (status == EFI_BUFFER_TOO_SMALL) {
            EFI_UINTN slack;
            if (descriptor_size < sizeof(EFI_MEMORY_DESCRIPTOR) ||
                descriptor_size > (EFI_UINTN)-1 / 8u)
                goto failure;
            slack = descriptor_size * 8u;
            if (map_size > (EFI_UINTN)-1 - slack) goto failure;
            if (map != NULL) boot->FreePool(map);
            map = NULL;
            capacity = map_size + slack;
            if (boot->AllocatePool(EfiLoaderData, capacity,
                                   (void **)&map) != EFI_SUCCESS)
                goto failure;
            continue;
        }
        if (status != EFI_SUCCESS || descriptor_size == 0u ||
            map_size % descriptor_size != 0u)
            goto failure;
        for (index = 0u; index < (size_t)(map_size / descriptor_size); index++) {
            const EFI_MEMORY_DESCRIPTOR *descriptor =
                (const EFI_MEMORY_DESCRIPTOR *)((const uint8_t *)map +
                    index * descriptor_size);
            uint64_t length;
            uint64_t end;
            if (descriptor->NumberOfPages == 0u ||
                descriptor->NumberOfPages > UINT64_MAX / EFI_PAGE_SIZE)
                goto failure;
            length = descriptor->NumberOfPages * EFI_PAGE_SIZE;
            if (descriptor->PhysicalStart > UINT64_MAX - length)
                goto failure;
            end = descriptor->PhysicalStart + length;
            if (descriptor->Type != EfiMemoryMappedIO &&
                descriptor->Type != EfiMemoryMappedIOPortSpace &&
                descriptor->Type != EfiReservedMemoryType &&
                end > BBP_IDENTITY_LIMIT)
                goto failure;
        }
        boot->FreePool(map);
        return 1;
    }
failure:
    if (map != NULL) boot->FreePool(map);
    return 0;
}

static bbp_uefi_firmware_status firmware_exit(void *context,
                                               void *image_handle,
                                               uintptr_t key)
{
    struct firmware_context *firmware = (struct firmware_context *)context;
    EFI_STATUS status = firmware->boot->ExitBootServices(image_handle, key);
    if (status == EFI_SUCCESS) return BBP_UEFI_FIRMWARE_SUCCESS;
    if (status == EFI_INVALID_PARAMETER)
        return BBP_UEFI_FIRMWARE_INVALID_PARAMETER;
    return BBP_UEFI_FIRMWARE_ERROR;
}

static void *firmware_allocate(void *context, size_t size)
{
    struct firmware_context *firmware = (struct firmware_context *)context;
    void *allocation = NULL;
    if (firmware->boot->AllocatePool(EfiLoaderData, size, &allocation) !=
        EFI_SUCCESS)
        return NULL;
    return allocation;
}

static void firmware_free(void *context, void *allocation)
{
    struct firmware_context *firmware = (struct firmware_context *)context;
    if (allocation != NULL) (void)firmware->boot->FreePool(allocation);
}

static uint32_t memory_type(uint32_t type)
{
    switch (type) {
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
        return BBP_MEM_BOOTLOADER_RECLAIM;
    case EfiConventionalMemory: return BBP_MEM_USABLE;
    case EfiUnusableMemory: return BBP_MEM_BAD_MEMORY;
    case EfiACPIReclaimMemory: return BBP_MEM_ACPI_RECLAIMABLE;
    case EfiACPIMemoryNVS: return BBP_MEM_ACPI_NVS;
    case EfiMemoryMappedIO:
    case EfiMemoryMappedIOPortSpace: return BBP_MEM_DEVICE_IO;
    case EfiPersistentMemory: return BBP_MEM_PERSISTENT;
    default: return BBP_MEM_RESERVED;
    }
}

static uint32_t memory_attributes(uint64_t attributes)
{
    uint32_t result = 0u;
    if ((attributes & EFI_MEMORY_RP) == 0u)
        result |= BBP_MEM_ATTR_READABLE;
    if ((attributes & (EFI_MEMORY_WP | EFI_MEMORY_RO)) == 0u)
        result |= BBP_MEM_ATTR_WRITABLE;
    if ((attributes & EFI_MEMORY_XP) == 0u)
        result |= BBP_MEM_ATTR_EXECUTABLE;
    if ((attributes & (EFI_MEMORY_WT | EFI_MEMORY_WB)) != 0u)
        result |= BBP_MEM_ATTR_CACHED;
    if ((attributes & EFI_MEMORY_WC) != 0u)
        result |= BBP_MEM_ATTR_WRITE_COMBINE;
    if ((attributes & (EFI_MEMORY_UC | EFI_MEMORY_UCE)) != 0u)
        result |= BBP_MEM_ATTR_UNCACHED;
    return result;
}

static int build_handoff(uint64_t arena_address,
                         const struct bbp_elf64_plan *plan,
                         uint64_t kernel_virtual_base,
                         const struct bbp_uefi_exit_result *exit_result,
                         uint64_t *info_address)
{
    struct bbp_info *info = (struct bbp_info *)(uintptr_t)arena_address;
    struct bbp_builder builder;
    struct bbp_tag_hhdm *hhdm;
    struct bbp_tag_memory_map *map;
    struct bbp_tag_kernel_address *kernel;
    struct bbp_memory_entry *entries;
    size_t count;
    size_t index;
    size_t tag_size;
    static const uint8_t name[] = "BearBoot OVMF";
    static const uint8_t version[] = "Wave17-proof";

    if (exit_result->memory_map_final == 0u ||
        exit_result->descriptor_version != 1u ||
        exit_result->descriptor_size < sizeof(EFI_MEMORY_DESCRIPTOR) ||
        exit_result->memory_map_size == 0u ||
        exit_result->memory_map_size % exit_result->descriptor_size != 0u)
        return 0;
    count = exit_result->memory_map_size / exit_result->descriptor_size;
    if (count == 0u || count > (SIZE_MAX - sizeof(*map)) / sizeof(*entries))
        return 0;
    tag_size = sizeof(*map) + count * sizeof(*entries);

    bbp_builder_init(&builder, (uint8_t *)info + sizeof(*info),
        arena_address + sizeof(*info),
        BBP_ARENA_PAGES * EFI_PAGE_SIZE - sizeof(*info));
    hhdm = (struct bbp_tag_hhdm *)bbp_alloc_tag(
        &builder, BBP_TAG_HHDM, 1u, sizeof(*hhdm));
    map = (struct bbp_tag_memory_map *)bbp_alloc_tag(
        &builder, BBP_TAG_MEMORY_MAP, 1u, tag_size);
    kernel = (struct bbp_tag_kernel_address *)bbp_alloc_tag(
        &builder, BBP_TAG_KERNEL_ADDRESS, 1u, sizeof(*kernel));
    if (hhdm == NULL || map == NULL || kernel == NULL || builder.overflow)
        return 0;
    hhdm->offset = BBP_HHDM_OFFSET;
    map->entry_count = (uint32_t)count;
    map->entry_size = sizeof(*entries);
    entries = (struct bbp_memory_entry *)((uint8_t *)map + sizeof(*map));
    for (index = 0u; index < count; index++) {
        const EFI_MEMORY_DESCRIPTOR *descriptor =
            (const EFI_MEMORY_DESCRIPTOR *)((const uint8_t *)
                exit_result->memory_map + index * exit_result->descriptor_size);
        uint64_t length;
        uint64_t end;
        if (descriptor->NumberOfPages == 0u ||
            descriptor->NumberOfPages > UINT64_MAX / EFI_PAGE_SIZE)
            return 0;
        length = descriptor->NumberOfPages * EFI_PAGE_SIZE;
        if (descriptor->PhysicalStart > UINT64_MAX - length) return 0;
        end = descriptor->PhysicalStart + length;
        if (descriptor->Type != EfiMemoryMappedIO &&
            descriptor->Type != EfiMemoryMappedIOPortSpace &&
            descriptor->Type != EfiReservedMemoryType &&
            end > BBP_IDENTITY_LIMIT)
            return 0;
        entries[index].base = descriptor->PhysicalStart;
        entries[index].length = length;
        entries[index].type = memory_type(descriptor->Type);
        entries[index].attributes = memory_attributes(descriptor->Attribute);
        if (descriptor->PhysicalStart < plan->physical_end &&
            end > plan->physical_base)
            entries[index].type = BBP_MEM_KERNEL_AND_MODULES;
    }
    kernel->physical_base = plan->physical_base;
    kernel->virtual_base = kernel_virtual_base;

    bytes_copy(info->bootloader_name, name, sizeof(name) - 1u);
    bytes_copy(info->bootloader_version, version, sizeof(version) - 1u);
    info->architecture = BBP_ARCH_X86_64;
    info->cpu_count = 1u;
    if (bbp_builder_finalize(&builder, info, arena_address) == 0u)
        return 0;
    *info_address = arena_address;
    return 1;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table)
{
    EFI_BOOT_SERVICES *boot;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
    void *kernel_file = NULL;
    size_t kernel_file_size = 0u;
    struct bbp_elf64_plan plan;
    const struct bbp_header *header;
    uint64_t arena_address = 0u;
    uint64_t stack_address = 0u;
    uint64_t tables_address = 0u;
    struct page_pool tables;
    uint64_t pml4_address = 0u;
    struct firmware_context firmware;
    struct bbp_uefi_exit_ops exit_ops;
    struct bbp_uefi_exit_result exit_result;
    bbp_uefi_exit_status exit_status;
    uint64_t info_address = 0u;
    uint64_t stack_top;
    uint64_t entry;
    uint64_t kernel_virtual_base;
    int unmap_null;
    int segments_loaded = 0;
    const char *failure_reason = NULL;

    serial_init();
    serial_puts("BBP-UEFI-LOADER: OVMF entry\n");
    if (system_table == NULL || system_table->BootServices == NULL)
        return fail("system table");
    boot = system_table->BootServices;
    if (read_kernel(image, system_table, &kernel_file, &kernel_file_size,
                    &loaded_image) != EFI_SUCCESS)
        return fail("open \\kernel.elf");
    if (bbp_elf64_plan(kernel_file, kernel_file_size, &plan) != BBP_ELF64_OK) {
        failure_reason = "ELF64 plan";
        goto cleanup;
    }
    if (load_segments(boot, kernel_file, &plan) != EFI_SUCCESS) {
        failure_reason = "PT_LOAD allocation";
        goto cleanup;
    }
    segments_loaded = 1;
    header = find_header(&plan);
    if (header == NULL || !validate_header_contract(header, &plan)) {
        failure_reason = "Bear Header";
        goto cleanup;
    }
    kernel_virtual_base = header->kernel_virtual_base;
    serial_puts("BBP-UEFI-LOADER: ELF64 + Bear Header verified\n");
    boot->FreePool(kernel_file);
    kernel_file = NULL;

    if (loaded_image == NULL || (uint64_t)(uintptr_t)loaded_image->ImageBase >=
            BBP_IDENTITY_LIMIT ||
        loaded_image->ImageSize > BBP_IDENTITY_LIMIT -
            (uint64_t)(uintptr_t)loaded_image->ImageBase) {
        failure_reason = "EFI image above identity map";
        goto cleanup;
    }
    if (allocate_low_pages(boot, BBP_ARENA_PAGES, &arena_address) != EFI_SUCCESS ||
        allocate_low_pages(boot, BBP_STACK_PAGES, &stack_address) != EFI_SUCCESS ||
        allocate_low_pages(boot, BBP_PAGE_TABLE_PAGES, &tables_address) !=
            EFI_SUCCESS) {
        failure_reason = "handoff allocations";
        goto cleanup;
    }

    tables.base = tables_address;
    tables.used = 0u;
    tables.count = BBP_PAGE_TABLE_PAGES;
    unmap_null = (header->flags & BBP_HF_UNMAP_NULL_PAGE) != 0u;
    if (!preflight_memory_geometry(boot)) {
        failure_reason = "memory geometry exceeds 4 GiB contract";
        goto cleanup;
    }
    if (!build_page_tables(&tables, &plan, 0, unmap_null, &pml4_address)) {
        failure_reason = "page tables";
        goto cleanup;
    }
    serial_puts("BBP-UEFI-LOADER: arena + stack + page tables ready\n");

    firmware.boot = boot;
    exit_ops.context = &firmware;
    exit_ops.get_memory_map = firmware_get_map;
    exit_ops.exit_boot_services = firmware_exit;
    exit_ops.allocate = firmware_allocate;
    exit_ops.free = firmware_free;
    bytes_zero(&exit_result, sizeof(exit_result));
    exit_status = bbp_uefi_exit_boot_services(&exit_ops, image, &exit_result);
    if (exit_status != BBP_UEFI_EXIT_OK) {
        failure_reason = "ExitBootServices";
        goto cleanup;
    }
    serial_puts("BBP-UEFI-LOADER: ExitBootServices complete\n");

    if (!build_handoff(arena_address, &plan, kernel_virtual_base, &exit_result,
                       &info_address))
        fail_after_exit("final memory map handoff");
    serial_puts("BBP-UEFI-LOADER: INFO sealed, transferring RDI\n");
    stack_top = (stack_address + BBP_STACK_PAGES * EFI_PAGE_SIZE) & ~UINT64_C(15);
    entry = plan.entry;
    __asm__ volatile(
        "cli\n\t"
        "movq %0, %%cr3\n\t"
        "movq %1, %%rsp\n\t"
        "xorq %%rbp, %%rbp\n\t"
        "movq %2, %%rdi\n\t"
        "jmp *%3\n\t"
        :
        : "r"(pml4_address), "r"(stack_top), "r"(info_address), "r"(entry)
        : "rdi", "memory");
    __builtin_unreachable();

cleanup:
    if (tables_address != 0u)
        (void)boot->FreePages(tables_address, BBP_PAGE_TABLE_PAGES);
    if (stack_address != 0u)
        (void)boot->FreePages(stack_address, BBP_STACK_PAGES);
    if (arena_address != 0u)
        (void)boot->FreePages(arena_address, BBP_ARENA_PAGES);
    if (segments_loaded) free_segments(boot, &plan);
    if (kernel_file != NULL) (void)boot->FreePool(kernel_file);
    return fail(failure_reason);
}
