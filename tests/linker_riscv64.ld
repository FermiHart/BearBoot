/* OpenSBI next-stage payload at the conventional QEMU virt address.
 * SPDX-License-Identifier: BSD-3-Clause */
ENTRY(_start)
PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x80200000;
    __image_start = .;
    .text : ALIGN(8) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.*) } :text
    .data : ALIGN(16) { *(.sdata .sdata.*) *(.data .data.*) } :data
    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(16);
        __stack_bottom = .;
        . += 16K;
        __stack_top = .;
        . = ALIGN(16);
        __bss_end = .;
    } :data
    __image_end = ALIGN(4K);
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

ASSERT(_start == 0x80200000, "RV64 entry moved")
ASSERT(__image_end < 0x84000000, "RV64 proof image exceeds its reserved window")
