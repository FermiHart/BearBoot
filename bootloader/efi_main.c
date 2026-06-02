/*
 * efi_main.c — reference UEFI bootloader entry for the Bear Boot Protocol.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * This is a SKELETON showing the BBP handoff sequence with gnu-efi. The
 * hardware-collection functions (collect_*) are declared here and must be
 * implemented against your firmware; what matters for the protocol is the
 * ORDER and that every tag is sealed before ExitBootServices, and the info
 * CRC is sealed last. Pointer in RDI at the jump (System V / kernel ABI).
 */
#include <efi.h>
#include <efilib.h>

#include <bbp/bbp.h>
#include "bbp_build.h"

/* Scratch arena for the info struct + all tags. 1 MiB is plenty; allocate it
 * as BootServicesData→convert, or better, EfiLoaderData so it survives. */
#define BBP_ARENA_BYTES (1u << 20)

/* Provided by the rest of the loader (ELF loader, firmware glue). */
extern struct bbp_header *bbp_load_kernel(CHAR16 *path);  /* maps .bbp_hdr */
extern void  *bbp_alloc_pages(UINTN bytes, bbp_phys_t *out_phys);
extern UINT64 bbp_now_ns(void);

/* Hardware collectors: each appends one tag via the builder. */
extern void collect_memory_map(struct bbp_builder *, EFI_SYSTEM_TABLE *);
extern void collect_hhdm(struct bbp_builder *, bbp_virt_t offset);
extern void collect_kernel_address(struct bbp_builder *, bbp_phys_t, bbp_virt_t);
extern void collect_framebuffer(struct bbp_builder *, EFI_SYSTEM_TABLE *);
extern void collect_acpi(struct bbp_builder *, EFI_SYSTEM_TABLE *);
extern void collect_smp(struct bbp_builder *);
extern void collect_security(struct bbp_builder *);   /* TPM + measured boot */
extern void collect_metrics(struct bbp_builder *, UINT64 start_ns);
extern void collect_hypervisor(struct bbp_builder *);

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    UINT64 start_ns;
    InitializeLib(image, st);
    start_ns = bbp_now_ns();

    /* 1. Load kernel ELF, get its Bear Header (from .bbp_hdr). */
    struct bbp_header *kh = bbp_load_kernel(L"\\kernel.elf");
    if (!kh) { Print(L"BBP: no kernel/header\n"); return EFI_LOAD_ERROR; }

    /* 2. Allocate the info+tag arena. */
    bbp_phys_t arena_phys, info_phys;
    void *arena = bbp_alloc_pages(BBP_ARENA_BYTES, &arena_phys);

    /* Reserve the info struct at the front of the arena. */
    struct bbp_info *info = (struct bbp_info *)arena;
    info_phys = arena_phys;
    bbp_phys_t builder_phys = arena_phys + sizeof(struct bbp_info);

    struct bbp_builder b;
    bbp_builder_init(&b, (uint8_t *)arena + sizeof(struct bbp_info),
                     builder_phys, BBP_ARENA_BYTES - sizeof(struct bbp_info));

    /* 3. Honor the kernel's request tags + always-useful tags. The HHDM
     *    offset is the loader's choice of where it direct-maps RAM; the
     *    kernel reuses it. */
    bbp_virt_t hhdm = 0xFFFF800000000000ULL;
    collect_hhdm(&b, hhdm);
    collect_kernel_address(&b, /*phys*/0, kh->kernel_virtual_base);
    collect_memory_map(&b, st);
    collect_acpi(&b, st);
    if (kh->flags & BBP_HF_FRAMEBUFFER_WANTED) collect_framebuffer(&b, st);
    if (kh->flags & BBP_HF_SMP_BOOT_ALL)       collect_smp(&b);
    collect_security(&b);     /* extends TPM PCRs, records measurement log */
    collect_hypervisor(&b);
    collect_metrics(&b, start_ns);

    if (b.overflow) { Print(L"BBP: tag arena overflow\n"); return EFI_BUFFER_TOO_SMALL; }

    /* 4. Fill loader identity + timestamps, then seal the info CRC. */
    for (int i = 0; i < 16; i++) info->magic[i] = 0;
    info->architecture       = BBP_ARCH_X86_64;
    info->cpu_count          = 1;  /* set from collect_smp */
    info->bootloader_start_ts= start_ns;
    info->kernel_load_ts     = bbp_now_ns();
    info->handoff_ts         = 0;  /* set just before jump */
    /* CopyMem(info->bootloader_name, "BearBoot", 8); etc. */

    /* 5. Exit boot services (real code retries on map-key change). */
    UINTN map_size = 0, map_key = 0, desc_size = 0; UINT32 desc_ver = 0;
    EFI_MEMORY_DESCRIPTOR *map = NULL;
    uefi_call_wrapper(st->BootServices->GetMemoryMap, 5,
                      &map_size, map, &map_key, &desc_size, &desc_ver);
    /* ... allocate map, GetMemoryMap again, then: */
    uefi_call_wrapper(st->BootServices->ExitBootServices, 2, image, map_key);

    info->handoff_ts = bbp_now_ns();
    bbp_builder_finalize(&b, info, info_phys);

    /* 6. Jump to the kernel with info pointer in RDI (System V). */
    __asm__ volatile(
        "movq %0, %%rdi\n\t"
        "jmp  *%1\n\t"
        :
        : "r"((uint64_t)info_phys), "r"((uint64_t)kh->entry_point)
        : "rdi", "memory"
    );
    __builtin_unreachable();
    return EFI_SUCCESS;
}
