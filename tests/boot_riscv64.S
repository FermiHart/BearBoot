/* RV64 OpenSBI entry for the BearBoot machine round-trip proof.
 * SPDX-License-Identifier: BSD-3-Clause */

.section .text.boot, "ax"
.align 3
.global _start
.type _start, @function
_start:
    csrci sstatus, 2
    mv s0, a0
    mv s1, a1

    la t0, __bss_start
    la t1, __bss_end
.Lclear_bss:
    bgeu t0, t1, .Lbss_done
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lclear_bss
.Lbss_done:
    la sp, __stack_top
    andi sp, sp, -16
    mv a0, s1
    call riscv64_producer
.Lhalt:
    wfi
    j .Lhalt
.size _start, . - _start

/* The first AAPCS argument and BBP handoff register are both A0. */
.global bbp_riscv64_handoff
.type bbp_riscv64_handoff, @function
bbp_riscv64_handoff:
    tail riscv64_consumer
.size bbp_riscv64_handoff, . - bbp_riscv64_handoff

.section .note.GNU-stack, "", @progbits
