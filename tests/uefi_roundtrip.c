/* uefi_roundtrip.c — OVMF-loaded BBP builder/parser proof.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This is deliberately a small EFI application, not a bootloader. It proves
 * PE/COFF loading plus the real BBP builder and bounded parser in pre-EBS
 * firmware context. It does not exercise ELF loading, Bear Header discovery,
 * firmware collectors, ExitBootServices, paging, or kernel transfer.
 */
#include <stdint.h>
#include <stddef.h>

#include <bbp/bbp.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

typedef void *efi_handle_t;
typedef struct efi_system_table efi_system_table_t;
typedef uint64_t efi_status_t;

#define EFI_SUCCESS 0
#define BBP_TAG_UEFI_PROOF BBP_TAG_ID(BBP_CAT_VENDOR, 4)

struct bbp_tag_uefi_proof {
    struct bbp_tag_header header;
    uint64_t marker;
};

static uint8_t arena[32 * 1024] __attribute__((aligned(16)));
static uint8_t guest_exit = 0x11; /* isa-debug-exit status 35: failure */

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
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x80);
    outb(0x3F8, 0x01);
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x03);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);
}

static void serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            while (!(inb(0x3FD) & 0x20)) { }
            outb(0x3F8, '\r');
        }
        while (!(inb(0x3FD) & 0x20)) { }
        outb(0x3F8, (uint8_t)*s++);
    }
}

static int count_tag(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(uint32_t *)user)++;
    return 0;
}

static void fail(const char *why)
{
    guest_exit = 0x11;
    serial_puts("BBP-UEFI: FAIL: ");
    serial_puts(why);
    serial_puts("\n");
}

efi_status_t efi_main(efi_handle_t image, efi_system_table_t *system_table)
{
    (void)image;
    (void)system_table;
    serial_init();
    serial_puts("BBP-UEFI: OVMF entry, running bounded round-trip\n");

    for (size_t i = 0; i < sizeof(arena); i++) arena[i] = 0;
    struct bbp_info *info = (struct bbp_info *)arena;
    uint8_t *tagbase = arena + sizeof(*info);
    size_t tag_capacity = sizeof(arena) - sizeof(*info);
    struct bbp_builder builder;
    bbp_builder_init(&builder, tagbase, (bbp_phys_t)(uintptr_t)tagbase,
                     tag_capacity);

    struct bbp_tag_hhdm *hhdm =
        bbp_alloc_tag(&builder, BBP_TAG_HHDM, 1, sizeof(*hhdm));
    struct bbp_tag_uefi_proof *proof =
        bbp_alloc_tag(&builder, BBP_TAG_UEFI_PROOF, 1, sizeof(*proof));
    if (!hhdm || !proof) {
        fail("arena allocation");
        goto done;
    }
    hhdm->offset = 0;
    proof->marker = 0x5545464942425001ULL;

    bbp_builder_finalize(&builder, info, (bbp_phys_t)(uintptr_t)info);
    if (builder.overflow) {
        fail("arena overflow");
        goto done;
    }

    struct bbp_kctx ctx;
    bbp_status_t status = bbp_init_bounded(
        &ctx, info, 0, (bbp_phys_t)(uintptr_t)tagbase, tag_capacity);
    if (status != BBP_OK) {
        fail(bbp_strstatus(status));
        goto done;
    }

    uint32_t count = 0;
    if (bbp_for_each_tag(&ctx, count_tag, &count) != 2 || count != 2) {
        fail("tag count");
        goto done;
    }
    if (!bbp_find_tag(&ctx, BBP_TAG_UEFI_PROOF)) {
        fail("proof tag missing");
        goto done;
    }

    proof->marker ^= 1;
    if (bbp_find_tag(&ctx, BBP_TAG_UEFI_PROOF)) {
        fail("tamper accepted");
        goto done;
    }

    guest_exit = 0x10; /* isa-debug-exit status 33: success */
    serial_puts("BBP-UEFI: PASS\n");

done:
    outb(0xF4, guest_exit);
    for (;;) __asm__ volatile("hlt");
    return EFI_SUCCESS;
}
