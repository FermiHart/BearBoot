/* linker32.ld — flat 1 MiB load for the Multiboot1 round-trip test.
 *   Author: F E R M I  ∞  H A R T
 *   SPDX-License-Identifier: BSD-3-Clause */
ENTRY(_start)
SECTIONS
{
    . = 1M;
    .multiboot : { KEEP(*(.multiboot)) }
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(COMMON) *(.bss .bss.*) }
}
