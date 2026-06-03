# BBP port — linux-0.01 (Limine-booted, native i386)

A **native** Bear Boot Protocol OSIF for linux-0.01-modern — Linus Torvalds'
first kernel (1991), ported to boot under Limine on modern x86 + QEMU. Written
from scratch, **not** a copy of the MINIX or tinalinux ports.

## Why it is the simplest BBP port that exists

linux-0.01 runs **identity-mapped**: `mm/memory.c` hardcodes `pg_dir = 0`, which
maps the first 8 MiB with `virt == phys`. So the single hardest thing in BBP —
the HHDM chicken-and-egg (SPEC §10.1) — collapses to nothing:

| concern    | MINIX (Limine adapter) | tinalinux (native OSIF) | **linux-0.01 (native OSIF)**       |
|------------|------------------------|-------------------------|------------------------------------|
| arch       | x86_64 higher-half     | x86_64 higher-half      | **i386, identity-mapped**          |
| HHDM       | Limine hhdm response   | `page_offset_base`      | **0** (virt == phys)               |
| handoff    | §10.1(b) init_ex       | §10.1(b) init_ex        | **§10.1(a) bbp_init, hint 0**      |
| memory map | Limine memmap          | firmware `e820_table`   | **config.h HIGH_MEMORY (fixed)**   |
| kernel base| Limine kernel-address  | `phys_base` / `_text`   | **0 / 0** (linked+loaded at phys 0)|
| ACPI/cmdline/fb | from firmware     | from firmware           | **none — 1991 kernel**             |
| log / panic| COM1 / hlt             | printk / panic          | **printk / panic**                 |

There is no firmware to query and no higher-half alias to translate. The port
produces exactly the 3 tags the kernel can truthfully describe — HHDM,
MEMORY_MAP, KERNEL_ADDRESS — and **fabricates nothing** for the hardware Linus'
kernel predates (ACPI, cmdline, framebuffer, SMP, TPM).

## The single-alias property (no dual-alias bug, for free)

The MINIX port must juggle a kernel-image alias and an HHDM alias for its
scratch arena. Here the kernel is identity-mapped, so the static arena has
`arena_phys == arena_virt`. One alias. The classic BBP bring-up fault is
structurally impossible — for the most elementary reason: the HHDM offset is 0.

## The binding seam (osif.c is freestanding, the kernel makes it real)

`osif.c` has **zero** kernel includes, so it compiles for `make scaffold-check`
and the hosted harness. Its OSIF primitives are `__weak` freestanding fallbacks
(COM1 serial / cli;hlt / static arena / rdtsc). The kernel glue `linux01_bbp.c`
provides **strong** overrides bound to `printk` / `panic`. Same `osif.o`, two
worlds, chosen at link time — no `#ifdef` in core or port.

## The one real friction point: C89 vs C99

linux-0.01 compiles `-std=gnu89` (K&R-era source). The BBP core needs C99+
(`for`-initializer declarations). They are reconciled by compiling the BBP
translation units with their **own** `-std=gnu11`, independent of the kernel's
gnu89 build — the port never drags the frozen core down to gnu89. See
`integration.md` §2.

## Files

    osif.{c,h}        OSIF: weak freestanding hooks + identity phys_to_virt
    adapter.{c,h}     native RAM-model -> BBP adapter (HHDM/MEMORY_MAP/KERNEL_ADDRESS)
    linux01_bbp.{c,h} kernel glue: strong printk/panic hooks + main() call site
    compat/           <stdint.h>/<stddef.h> shims for the frozen core under
                      the kernel -nostdinc -m32 build
    Makefile          scaffold-check (freestanding elf32-i386) + hosted test
    test/harness.c    hosted rig: real adapter on the linux-0.01 RAM model
    test/serial.log   hosted PASS evidence
    CONFORMANCE.md    the conformance report
    integration.md    exact vendoring paths, build hooks, call site, consumers

## Verify

    make scaffold-check CROSS=x86_64-elf-   # compiles+links vs frozen core, elf32-i386
    make test                               # hosted: "linux-0.01 adapter ok, 3 tags … PASS"

Hosted proof (see CONFORMANCE.md / test/serial.log):

    bbp: linux-0.01 adapter ok, 3 tags, hhdm=0x0
    RESULT: PASS - native adapter validated on the linux-0.01 RAM model

3 CRC-64/XZ-sealed tags (HHDM, MEMORY_MAP, KERNEL_ADDRESS) synthesized from the
kernel's fixed RAM model (640K + 7M usable, 640K-1M hole reserved) and validated
by the frozen parser; the integration is additive and non-fatal.

The ABI-frozen BBP core (`include/bbp/*`, `bbp_kernel.c`, `bbp_build.c`) is
**unmodified** — pinned to commit 9257abe.

— F E R M I ∞ H A R T  <contact@fermihart.com>
