ENTRY(_start)

KERNEL_VMA = 0xffffffff80000000;
KERNEL_LMA = 0x00400000;

PHDRS
{
    header PT_LOAD FLAGS(4);
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_VMA;
    .bbp_hdr : AT(ADDR(.bbp_hdr) - KERNEL_VMA + KERNEL_LMA) {
        KEEP(*(.bbp_hdr))
    } :header

    .rodata ALIGN(0x1000) : AT(ADDR(.rodata) - KERNEL_VMA + KERNEL_LMA) {
        *(.rodata .rodata.*)
    } :header

    .text ALIGN(0x1000) : AT(ADDR(.text) - KERNEL_VMA + KERNEL_LMA) {
        *(.text .text.*)
    } :text

    .data ALIGN(0x1000) : AT(ADDR(.data) - KERNEL_VMA + KERNEL_LMA) {
        *(.data .data.*)
    } :data

    .bss ALIGN(0x1000) (NOLOAD) : AT(ADDR(.bss) - KERNEL_VMA + KERNEL_LMA) {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ : { *(.eh_frame .note .comment) }
}
