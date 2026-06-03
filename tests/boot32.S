/* boot32.S — Multiboot1 entry for the BBP QEMU round-trip test (32-bit).
 *   Author: F E R M I  ∞  H A R T
 *   SPDX-License-Identifier: BSD-3-Clause */
.set MB_MAGIC,    0x1BADB002
.set MB_FLAGS,    0x00000000
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

.section .multiboot, "a"
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM

.section .bss
.align 16
stack_bottom:
.skip 16384
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    movl $stack_top, %esp
    andl $-16, %esp
    call kmain
1:  hlt
    jmp 1b
.size _start, . - _start
