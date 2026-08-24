/* AArch64 Linux Image entry for the BearBoot machine round-trip proof.
 * SPDX-License-Identifier: BSD-3-Clause */

.section .text.boot, "ax"
.balign 8
.global _start
.type _start, %function
_start:
    b .Lentry
    .long 0
    .quad 0x00080000
    .quad __image_end - _start
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .long 0x644d5241
    .long 0

.Lentry:
    msr daifset, #0xf
    mov x19, x0

    adrp x1, __bss_start
    add x1, x1, :lo12:__bss_start
    adrp x2, __bss_end
    add x2, x2, :lo12:__bss_end
.Lclear_bss:
    cmp x1, x2
    b.hs .Lbss_done
    str xzr, [x1], #8
    b .Lclear_bss
.Lbss_done:
    adrp x1, __stack_top
    add x1, x1, :lo12:__stack_top
    and sp, x1, #-16
    mov x0, x19
    bl aarch64_producer
.Lhalt:
    wfe
    b .Lhalt
.size _start, . - _start

/* AAPCS64 puts the first argument in X0. Branching instead of calling keeps
 * that exact architectural handoff intact at the consumer entry point. */
.global bbp_aarch64_handoff
.type bbp_aarch64_handoff, %function
bbp_aarch64_handoff:
    b aarch64_consumer
.size bbp_aarch64_handoff, . - bbp_aarch64_handoff

.section .note.GNU-stack, "", %progbits
