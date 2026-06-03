/* linker.ld — reference higher-half linker script for a BBP kernel.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Higher-half at -2GiB (0xFFFFFFFF80000000), loaded at a low physical base
 * (2 MiB). VMA != LMA, so AT(...) places load addresses in the low range
 * while symbols resolve to the high virtual range. The Bear Header MUST be
 * KEEP()'d or the linker garbage-collects it and the producer finds no header
 * (ADR-0007 / classic bring-up failure); it is placed FIRST so a producer
 * scanning the image for the magic finds it immediately.
 */

ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;   /* virtual base (symbols)        */
KERNEL_LMA = 0x200000;             /* physical load base (2 MiB)    */

PHDRS
{
    headers PT_LOAD FLAGS(4);   /* R   — .bbp_hdr + rodata */
    text    PT_LOAD FLAGS(5);   /* R-X */
    data    PT_LOAD FLAGS(6);   /* RW  */
}

SECTIONS
{
    . = KERNEL_VMA;

    .bbp_hdr : AT(KERNEL_LMA) ALIGN(8) {
        KEEP(*(.bbp_hdr))       /* never GC the Bear Header */
    } :headers

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    } :headers

    .text : ALIGN(4K) {
        *(.text .text.*)
    } :text

    .data : ALIGN(4K) {
        *(.data .data.*)
    } :data

    .bss (NOLOAD) : ALIGN(4K) {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
        *(.comment)
    }
}
