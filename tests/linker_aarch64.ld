/* Raw AArch64 Linux Image loaded by QEMU virt at RAM base + 0x80000.
 * SPDX-License-Identifier: BSD-3-Clause */
ENTRY(_start)
PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x40080000;
    __image_start = .;

    .text : ALIGN(8) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.*) } :text
    .data : ALIGN(16) { *(.data .data.*) } :data

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
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

ASSERT(_start == 0x40080000, "AArch64 Image entry moved")
ASSERT(__image_end < 0x44000000, "AArch64 proof image exceeds its reserved window")
