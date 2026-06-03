/* test/linker.ld — higher-half link for the Limine BBP adapter harness.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Limine loads a higher-half kernel: symbols resolve to the -2 GiB virtual
 * window while Limine picks the physical load base and reports it via the
 * kernel-address response (that physical/virtual pair is exactly the kernel
 * slide the adapter uses to physical-ize its arena). The .limine_requests*
 * sections MUST be KEEP()'d and reachable so the bootloader finds the request
 * markers — the adapter equivalent of KEEP(.bbp_hdr) for native BBP boot.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;

PHDRS
{
    requests PT_LOAD FLAGS(6);   /* RW  — Limine request markers       */
    text     PT_LOAD FLAGS(5);   /* R-X */
    rodata   PT_LOAD FLAGS(4);   /* R   */
    data     PT_LOAD FLAGS(6);   /* RW  */
}

SECTIONS
{
    . = KERNEL_VMA;

    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :requests

    . = ALIGN(0x1000);
    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(0x1000);
    .data : {
        *(.data .data.*)
    } :data

    .bss (NOLOAD) : {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
        *(.comment)
    }
}
