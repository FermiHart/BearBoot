/* test/boot.S — Limine entry stub for the BBP MINIX adapter harness.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Limine hands control in 64-bit long mode, paging on, higher-half mapped,
 * with a valid stack already. We set up our own known-good stack anyway
 * (16-byte aligned per the System V AMD64 ABI before a CALL) and jump to C.
 */
.section .text
.global _start
.type _start, @function
_start:
    cld
    leaq    boot_stack_top(%rip), %rsp   /* our own stack                  */
    andq    $-16, %rsp                   /* 16-byte align before CALL      */
    xorq    %rbp, %rbp                   /* terminate stack-trace chain    */
    call    harness_main                 /* never returns (qemu_exit)      */
1:  cli
    hlt
    jmp     1b
.size _start, . - _start

.section .bss
.align 16
boot_stack:
    .skip 0x4000                         /* 16 KiB boot stack              */
boot_stack_top:
