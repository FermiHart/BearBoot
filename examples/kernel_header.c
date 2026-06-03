/*
 * kernel_header.c — example BBP kernel: publishes a Bear Header in .bbp_hdr,
 * declares its request tags, and consumes the handoff via the kernel parser.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Build freestanding (see Makefile target `example`). This is reference code
 * showing the contract; wire kernel_main() into your real entry trampoline.
 */
#include <bbp/bbp.h>
#include "../kernel/bbp_kernel.h"

/* ------------------------------------------------------------------ *
 *  1. Request tags: what we want the bootloader to hand us.
 *     Kept in a normal section; the header points at it physically.
 * ------------------------------------------------------------------ */
/* External linkage + `used` so the symbol survives (the header's `requests`
 * field is 0 until bbp_stamp patches in this array's address post-link, so
 * nothing references it at compile time and a static would be GC'd). */
__attribute__((used))
const struct bbp_tag_request bbp_requests[] = {
    { BBP_TAG_MEMORY_MAP,     0,                .reserved = 0 },
    { BBP_TAG_HHDM,           0,                .reserved = 0 },
    { BBP_TAG_KERNEL_ADDRESS, 0,                .reserved = 0 },
    { BBP_TAG_ACPI,           0,                .reserved = 0 },
    { BBP_TAG_FRAMEBUFFER,    BBP_REQ_OPTIONAL, .reserved = 0 },
    { BBP_TAG_SMP,            BBP_REQ_OPTIONAL, .reserved = 0 },
    { BBP_TAG_SECURITY,       BBP_REQ_OPTIONAL, .reserved = 0 },
    { BBP_TAG_CMDLINE,        BBP_REQ_OPTIONAL, .reserved = 0 },
    { BBP_TAG_METRICS,        BBP_REQ_OPTIONAL, .reserved = 0 },
};

#define BBP_KERNEL_VIRTUAL_BASE  0xFFFFFFFF80000000ULL

/* ------------------------------------------------------------------ *
 *  2. The Bear Header itself, forced into ".bbp_hdr".
 *     KEEP(.bbp_hdr) in your linker script or the linker GC drops it
 *     and the bootloader finds no header — classic bring-up failure.
 *
 *     The `checksum` field is 0 here. A post-link tool (tools/bbp_stamp)
 *     computes CRC64/XZ over the header with checksum=0 and patches it in,
 *     because the value can't be known at compile time (requests is a
 *     physical address fixed up at link/load).
 * ------------------------------------------------------------------ */
__attribute__((section(".bbp_hdr"), used, aligned(8)))
const struct bbp_header bbp_kernel_header = {
    .magic               = BBP_HEADER_MAGIC,   /* "BEAR_BOOT", zero-padded to 16 */
    .version_major       = BBP_VERSION_MAJOR,
    .version_minor       = BBP_VERSION_MINOR,
    .header_size         = sizeof(struct bbp_header),
    .flags               = BBP_HF_ENABLE_NX
                         | BBP_HF_UNMAP_NULL_PAGE
                         | BBP_HF_HIGH_ENTROPY_KASLR
                         | BBP_HF_FRAMEBUFFER_WANTED,
    .entry_point         = 0,  /* filled by linker via ENTRY()/symbol, or stamp */
    .paging_mode         = BBP_PAGING_4LEVEL,
    .kernel_virtual_base = BBP_KERNEL_VIRTUAL_BASE,
    .request_count       = sizeof(bbp_requests) / sizeof(bbp_requests[0]),
    .reserved0           = 0,
    .requests            = 0,  /* physical addr of bbp_requests, set by stamp */
    .kernel_uuid         = { 0xB6A11F00DULL, 0xC0FFEE5235D00DULL },
    .kernel_name         = "bbp-example-kernel",
    .checksum            = 0,  /* stamped post-link */
};

/* ------------------------------------------------------------------ *
 *  3. Consume the handoff. Entry trampoline passes RDI -> info.
 * ------------------------------------------------------------------ */
static void hang(void) { for (;;) __asm__ volatile("hlt"); }

void kernel_main(const struct bbp_info *info)
{
    struct bbp_kctx k;
    bbp_status_t st = bbp_init(&k, info);
    if (st != BBP_OK) {
        /* serial_puts(bbp_strstatus(st)); */
        hang();
    }

    /* Memory map -> seed the PMM. Use bbp_tag_array(): it CLAMPS the claimed
     * entry_count to what physically fits in tag_size (ADR-0004/0006). Trusting
     * the raw entry_count would let a corrupt producer drive an OOB read. */
    const struct bbp_tag_header *t = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    if (t) {
        const struct bbp_tag_memory_map *mm = (const struct bbp_tag_memory_map *)t;
        uint32_t n = 0;
        const struct bbp_memory_entry *e = (const struct bbp_memory_entry *)
            bbp_tag_array(t, sizeof(*mm), sizeof(struct bbp_memory_entry),
                          mm->entry_count, &n);
        for (uint32_t i = 0; i < n; i++) {
            if (e[i].type == BBP_MEM_USABLE) {
                /* pmm_add_region(e[i].base, e[i].length); */
            }
        }
    }

    /* HHDM offset is already inside k (set by bbp_init). Use it to build
     * the kernel's own direct map: virt = phys + k.hhdm_offset. */

    /* ACPI -> hand RSDP to the ACPI subsystem. */
    if ((t = bbp_find_tag(&k, BBP_TAG_ACPI))) {
        const struct bbp_tag_acpi *a = (const struct bbp_tag_acpi *)t;
        (void)a->rsdp_address; /* acpi_init(a->rsdp_address); */
    }

    /* Framebuffer (optional). */
    if ((t = bbp_find_tag(&k, BBP_TAG_FRAMEBUFFER))) {
        const struct bbp_tag_framebuffer *fb = (const struct bbp_tag_framebuffer *)t;
        (void)fb->address; /* console_init(fb); */
    }

    /* Security / measured boot (optional). The measurement log lives OUT of
     * the tag; verify its CRC (ADR-0006) before trusting it. */
    if ((t = bbp_find_tag(&k, BBP_TAG_SECURITY))) {
        const struct bbp_tag_security *s = (const struct bbp_tag_security *)t;
        if (s->measurement_count && s->measurements) {
            size_t log_len = (size_t)s->measurement_count * sizeof(struct bbp_measurement);
            if (bbp_verify_blob(&k, s->measurements, log_len,
                                s->measurements_crc, 0) == BBP_OK) {
                /* tpm2_replay_log(phys->virt(s->measurements), s->measurement_count); */
            }
        }
        if (s->tpm_version >= 0x0200) { /* tpm2_init(s); */ }
        if (s->entropy_size && s->entropy_data) {
            if (bbp_verify_blob(&k, s->entropy_data, s->entropy_size,
                                s->entropy_crc, 0) == BBP_OK) {
                /* csprng_seed(phys->virt(s->entropy_data), s->entropy_size); */
            }
        }
    }

    /* SMP (optional) -> bring up APs. */
    if ((t = bbp_find_tag(&k, BBP_TAG_SMP))) {
        const struct bbp_tag_smp *smp = (const struct bbp_tag_smp *)t;
        if (smp->cpu_count > 1) { /* smp_boot(smp); */ }
    }

    hang(); /* scheduler_start(); */
}

/* ------------------------------------------------------------------ *
 *  Minimal entry trampoline. The producer jumps here with the info
 *  pointer in RDI (System V). We set up a stack and call kernel_main.
 *  Real kernels do far more (GDT/IDT, BSS clear); this is the contract
 *  surface the linker script's ENTRY(_start) needs.
 * ------------------------------------------------------------------ */
__attribute__((used)) static uint8_t bbp_boot_stack[16384] __attribute__((aligned(16)));

__attribute__((naked, used)) void _start(void)
{
    __asm__ volatile(
        "lea bbp_boot_stack(%rip), %rsp\n\t"
        "add $16384, %rsp\n\t"
        "and $-16, %rsp\n\t"        /* 16-byte align per System V */
        "xor %rbp, %rbp\n\t"
        "call kernel_main\n\t"      /* RDI already holds info ptr  */
        "1: hlt\n\t"
        "jmp 1b\n\t"
    );
}
