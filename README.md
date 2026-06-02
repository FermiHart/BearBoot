# Bear Boot Protocol (BBP) v1.0

A tag-based, UUID-versioned, multi-architecture boot protocol with native
measured-boot, boot observability, and CRC64-checksummed structures.

    Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
    License: BSD-3-Clause + Patent Grant (see LICENSE)
    Status:  v1.1 — ABI frozen. Validated end to end:
             - 45/45 host self-test checks pass (incl. adversarial suite)
             - kernel-side compiles freestanding with x86_64-elf-gcc 16.1.0
               (-Wall -Wextra -Werror -mno-red-zone -mcmodel=kernel)
             - parser fuzzer survives 20k+ malformed inputs (no crash/hang)
             - example links into a higher-half kernel.elf, stamped by
               bbp_stamp and cross-verified by the C runtime (CRCs agree)
             - DYNAMIC round-trip boots under QEMU: real producer builds the
               info+tags, real parser validates + walks it -> "BBP-QEMU: PASS"
             Design rationale recorded as ADRs in docs/adr/.

BBP descends from the Aether Boot Protocol draft, rebranded and hardened into
a stable on-the-wire ABI shared between an UEFI/BIOS bootloader and a
(possibly higher-half) kernel. It is designed to be dropped into the MINIX
x86_64 port.


## Why BBP over stivale2

| Concern         | stivale2          | Bear Boot Protocol                          |
|-----------------|-------------------|---------------------------------------------|
| Architectures   | x86_64, i686      | x86_64, AArch64, RISC-V, LoongArch          |
| Security        | none              | TPM 2.0, measured boot, Secure Boot tags    |
| Extensibility   | simple tags       | UUID + category + per-tag version           |
| Framebuffer     | basic RGB         | HDR, multi-display, EDID, color spaces      |
| SMP             | basic             | full topology, hotplug, heterogeneous       |
| Observability   | none              | boot phase metrics, timestamps              |
| PCIe            | via ACPI          | explicit topology with BARs                 |
| Integrity       | none              | **CRC64/XZ on info AND every tag**          |
| Higher-half     | HHDM tag          | HHDM + KERNEL_ADDRESS tags                  |
| Boot chain      | no                | `next_context` multistage handoff           |


## Layout

    include/bbp/bbp.h         Canonical ABI: header, info, tag structs.
                              Every struct guarded by _Static_assert(sizeof).
    include/bbp/bbp_crc64.h   CRC-64/XZ (ECMA-182), freestanding, header-only.
    kernel/bbp_kernel.{c,h}   Kernel-side parser: validate + find tags by UUID.
                              HHDM-aware (works after you switch CR3). No libc.
    bootloader/bbp_build.{c,h} Bootloader-side tag builder (arena + CRC sealing).
    bootloader/efi_main.c     Reference UEFI handoff sequence (gnu-efi skeleton).
    examples/kernel_header.c  A kernel publishing its Bear Header in .bbp_hdr.
    tests/abi_selftest.c      Host regression suite (CRC vector, ABI sizes,
                              builder<->parser round-trip, CRC tamper detection).
    SPEC.md                   Full normative specification.


## Build & test

    make test          # host-compile + run the self-test (45 checks)
    make freestanding  # cross-compile kernel-side as a kernel would (x86_64-elf-)
    make kernel        # link the example into a stamped, bootable kernel.elf
    make fuzz          # build + smoke-run the parser fuzzer (adversarial corpus)
    make qemu          # build the Multiboot1 bare-metal round-trip kernel
    make abi           # fastest gate: do the _Static_asserts hold?
    make check         # abi + test + fuzz (everything without a cross toolchain)

Override the cross prefix: `make freestanding CROSS=x86_64-elf-`.

Dynamic proof on bare metal:

    make qemu
    qemu-system-i386 -kernel build/roundtrip.elf -serial stdio -display none
    # -> BBP-QEMU: boot ok / memmap entries=0x2 / BBP-QEMU: PASS


## The contract in 6 lines

1. Kernel emits a `struct bbp_header` (magic `BEAR_BOOT`) into section
   `.bbp_hdr` — KEEP() it in your linker script or the GC drops it.
2. Header lists `struct bbp_tag_request[]`: which tags it wants.
3. Bootloader builds a `struct bbp_info` (magic `BEAR_INFO`) + a chain of
   tags in an arena, sealing CRC64 on each tag and on the info.
4. Bootloader jumps to `entry_point` with the **physical** info pointer in
   RDI (x86_64) / X0 (AArch64) / A0 (RISC-V).
5. Kernel calls `bbp_init()` → validates magic, version, size, CRC; picks up
   the HHDM offset automatically.
6. Kernel calls `bbp_find_tag(&k, BBP_TAG_*)` — corrupt tags are rejected by
   CRC and treated as absent.


## Integrating into the MINIX port

- Add `-I.../BearBoot/include` to the kernel CFLAGS.
- Compile `kernel/bbp_kernel.c` into the kernel; declare the Bear Header in
  your kernel (see `examples/kernel_header.c`) and `KEEP(*(.bbp_hdr))` in the
  linker script, placed early so the loader finds it.
- The `entry_point`, `requests` physical pointer, and header `checksum` are
  not known at compile time; stamp them post-link (a `tools/bbp_stamp` pass —
  computes CRC64 over the header with checksum=0 and patches the fields). The
  header is laid out so this is a fixed-offset patch.
- On the loader side, port the `collect_*` functions in `efi_main.c` to your
  firmware glue; the builder API (`bbp_build.c`) is firmware-agnostic.


## ABI stability

`version_major` bumps on any breaking change. Within a major version, new
tags may be added (kernels ignore unknown tags) and new fields may be appended
to the END of a variable-length tag's fixed struct only if `tag_version` is
bumped and old readers still parse the prefix. The `_Static_assert`s in bbp.h
are the enforcement mechanism — a layout drift fails the build, not the boot.
