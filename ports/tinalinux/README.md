# BBP port — TinaLinux x86_64 (native Linux boot)

A **native** Bear Boot Protocol OSIF for TinaLinux (a Linux 6.12 derivative),
written from scratch — **not** a copy of the MINIX port.

## Why it is built from zero, not adapted from MINIX

The MINIX port is a **Limine→BBP adapter**: it translates Limine response
structs. TinaLinux is **not booted by Limine** — it boots through the native
Linux x86_64 path (EFI stub / BIOS → `boot_params`). Copying the MINIX adapter
would be fiction. So this port is a real OSIF anchored on the **native Linux
boot sources**:

| concern    | MINIX (Limine adapter) | **TinaLinux (native OSIF)**          |
|------------|------------------------|--------------------------------------|
| memory map | Limine memmap structs  | `e820_table` (firmware E820)         |
| HHDM       | `limine_hhdm_offset`   | `page_offset_base` (== `__va`)       |
| kernel base| Limine kernel-address  | `phys_base` / `_text`                |
| ACPI RSDP  | Limine rsdp response   | `acpi_os_get_root_pointer()`         |
| cmdline    | fixed string           | `saved_command_line`                 |
| log        | COM1 polled            | **`printk`**                         |
| panic      | hlt                    | **`panic()`**                        |
| alloc      | 64 KiB static arena    | **`__get_free_pages()`** (direct map)|
| now_ns     | rdtsc @ nominal 1 GHz  | **`ktime_get_ns()`**                 |

## The binding seam (osif.c is freestanding, the kernel makes it real)

`osif.c` has **zero** `<linux/…>` includes, so it compiles for `make
scaffold-check` and the hosted harness. Its five OSIF primitives are
`__weak` freestanding fallbacks. The kernel glue `tina_bbp.c` provides **strong**
overrides bound to `printk` / `panic` / `__get_free_pages` / `ktime_get_ns`.
Same `osif.o`, two worlds, chosen at link time — no `#ifdef` in core or port.

## The structural advantage over MINIX (no dual-alias bug)

The MINIX port must juggle a *kernel-image alias* and an *HHDM alias* for its
scratch arena (the arena is a kernel symbol) — conflating them is THE classic
BBP bring-up fault. Here the glue allocates the arena with `__get_free_pages`,
so it lives in the Linux **direct map**, where
`__pa(arena) == arena − page_offset_base` and `phys_to_virt == __va` are the
**same** linear relation. One alias. The hazard is structurally absent.

## Files

    osif.{c,h}        OSIF: weak freestanding hooks + phys_to_virt arithmetic
    adapter.{c,h}     native Linux->BBP adapter (e820/ACPI/kslide/cmdline -> tags)
    tina_bbp.{c,h}    kernel glue: strong hooks (printk/__get_free_pages/ktime)
                      + the late_initcall call site + tag accessors
    compat/           <stdint.h>/<stddef.h> shims for the frozen core under
                      the kernel -nostdinc build (defer to _LINUX_TYPES_H)
    Makefile          scaffold-check (freestanding) + hosted test (no QEMU)
    test/harness.c    hosted rig: real adapter on representative e820 data
    test/serial.log   REAL kernel boot evidence (headless QEMU+KVM)
    CONFORMANCE.md    the conformance report
    integration.md    exact vendoring paths, build hooks, call site, consumers

## Verify

    make scaffold-check   # compiles+links vs the ABI-frozen core, -nostdinc
    make test             # hosted: "tinalinux adapter ok, 5 tags … PASS"

Real-boot proof (see CONFORMANCE.md / test/serial.log):

    bbp: tinalinux adapter ok, 5 tags, hhdm=0xffff91e140000000

5 CRC-64/XZ-sealed tags (HHDM, MEMORY_MAP, KERNEL_ADDRESS, ACPI, CMDLINE)
synthesized from real e820 + ACPI + cmdline and validated by the frozen parser
at `late_initcall`; the kernel then continued to the jash prompt — the port is
**additive and non-fatal**.

The ABI-frozen BBP core (`include/bbp/*`, `bbp_kernel.c`, `bbp_build.c`) is
**unmodified** — verified byte-identical to the canonical BearBoot core.

— F E R M I ∞ H A R T  <contact@fermihart.com>
