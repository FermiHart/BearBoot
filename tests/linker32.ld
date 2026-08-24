/* linker32.ld — flat 1 MiB load for the Multiboot1 round-trip test.
 *   Author: F E R M I  ∞  H A R T
 *   SPDX-License-Identifier: BSD-3-Clause */
ENTRY(_start)
PHDRS
{
    text PT_LOAD FLAGS(5); /* read + execute */
    data PT_LOAD FLAGS(6); /* read + write */
}
SECTIONS
{
    . = 1M;
    .multiboot : { KEEP(*(.multiboot)) } :text
    .text : { *(.text .text.*) } :text
    .rodata : { *(.rodata .rodata.*) } :text
    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss : { *(COMMON) *(.bss .bss.*) } :data
}
