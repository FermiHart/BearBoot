# Bear Boot Protocol (BBP)

**A complementary, verifiable boot-handoff layer.** BBP does not replace your
bootloader. It works *alongside* Limine, the UEFI stub, or the native Linux boot
path: it takes the platform data those mechanisms already discovered and
re-expresses it as a tag list that is **UUID-versioned, CRC-64/XZ-sealed, and
parsed by a hardened, adversarial-input-safe consumer.**

```
   Author:  F E R M I  ∞  H A R T  <contact@fermihart.com>
   License: BSD-3-Clause + Patent Grant (see LICENSE)
   Status:  v1.1 — ABI frozen. x86_64 proven end-to-end (see STATUS.md).
```

> **What BBP is:** a thin integrity + portability layer between *whatever booted
> you* and your kernel. A small frozen ABI (`include/bbp/bbp.h`), a defensive
> kernel-side parser (`kernel/bbp_kernel.c`), a producer-side tag builder
> (`bootloader/bbp_build.c`), and an OS-interface (OSIF) seam so the same core
> drops into different kernels.
>
> **What BBP is not:** a bootloader. It does not own the disk, the ELF loader,
> SMP bring-up, or `ExitBootServices`. Limine / UEFI / the Linux boot path keep
> doing that. BBP rides on top and hands your kernel a checksummed, validated
> view of the result.

---

## Why a complementary layer?

The boot→kernel handoff is the moment a kernel ingests its most security-
critical input (the memory map, ACPI pointers, the command line) — and most
protocols hand it over as **plain, unchecked structs**. A single corrupt or
hostile field there can fault or mislead the kernel before any defenses exist.

BBP adds one honest thing at that seam: **every structure is CRC-64/XZ-sealed,
and the kernel-side parser treats the entire handoff as untrusted input** —
bounds every length, validates structure before dereferencing, rejects
overflowing/wrapping pointers, clamps forged array counts, and bounds cyclic tag
chains. A bad producer can make the kernel *refuse to boot*; it must not be able
to make it fault, hang, or consume forged data. (See `SECURITY.md`.)

You keep your bootloader. You gain an integrity-checked, portable handoff.

---

## Proven today: two real OS integrations

BBP is not a paper ABI. The same frozen core is wired into two different kernels
through the OSIF seam, each with its own producer of tags:

| Integration | How it produces tags | Status |
|-------------|----------------------|--------|
| **`ports/tinalinux/`** | **native** Linux path — `e820_table`, `acpi_os_get_root_pointer()`, `saved_command_line`, `page_offset_base` | **boots under QEMU+KVM**; serial log shows `bbp: tinalinux adapter ok, 5 tags` (see `ports/tinalinux/test/serial.log`) |
| **`ports/minix/`** | **Limine adapter** — translates Limine responses into BBP tags | builds + links against the frozen core; standalone Limine harness |

The TinaLinux port is the clearest demonstration of the idea: it sits **next to**
the native Linux boot path (does not disturb it), and at `late_initcall`
synthesizes a CRC-sealed tag view of the real firmware tables. Additive,
non-fatal, complementary — exactly the design intent.

---

## Layout

```
include/bbp/bbp.h          Canonical frozen ABI: header, info, tag structs.
                           Every struct guarded by _Static_assert(sizeof).
include/bbp/bbp_crc64.h    CRC-64/XZ (ECMA-182), freestanding, header-only.
include/bbp/bbp_osif.h     OS-interface contract: the seam a port implements.

kernel/bbp_kernel.{c,h}    Defensive kernel-side parser. HHDM-aware, no libc,
                           treats the whole handoff as untrusted input.
bootloader/bbp_build.{c,h} Producer-side tag builder (arena + CRC sealing).
bootloader/efi_main.c      Reference UEFI producer SKELETON (gnu-efi). A base to
                           port against your firmware — not a finished loader.

ports/tinalinux/           Native Linux->BBP OSIF (boots under QEMU; see above).
ports/minix/               Limine->BBP adapter OSIF.

examples/kernel_header.c   A kernel publishing its Bear Header in .bbp_hdr.
tools/bbp_stamp.py         Post-link header stamper (entry/requests/checksum).
tests/                     Host self-test, ABI asserts, parser fuzzer, QEMU rig.
SPEC.md                    Full normative specification.
STATUS.md                  Honest maturity matrix: live / skeleton / roadmap.
docs/adr/                  Architecture Decision Records (the "why").
```

---

## Build & test

```sh
make check         # fastest full gate: ABI asserts + self-test + fuzzer
make test          # host-compile + run the self-test (adversarial suite incl.)
make freestanding  # cross-compile the kernel-side as a kernel would (x86_64-elf-)
make fuzz          # parser fuzzer over a malformed-input corpus
make qemu          # bare-metal round-trip: real producer -> real parser -> PASS
```

Verify a port against the frozen core (example: TinaLinux):

```sh
cd ports/tinalinux
make scaffold-check   # compiles+links the port vs the frozen core (freestanding)
make test             # hosted: "bbp: tinalinux adapter ok, 5 tags … PASS"
```

---

## The contract in 6 lines

1. The kernel emits a `struct bbp_header` (magic `BEAR_BOOT`) into section
   `.bbp_hdr`, listing the tags it wants (`struct bbp_tag_request[]`).
2. A producer (a bootloader, or an in-kernel adapter like the ports here)
   collects platform data into a `struct bbp_info` (magic `BEAR_INFO`) + a chain
   of tags in an arena, sealing CRC-64 on each tag and on the info.
3. Control reaches the kernel entry with the **physical** info pointer in
   RDI (x86_64) / X0 (AArch64) / A0 (RISC-V).
4. The kernel calls `bbp_init()` → validates magic, version, size, CRC; picks up
   the HHDM offset automatically.
5. The kernel calls `bbp_find_tag(&k, BBP_TAG_*)` — corrupt tags fail CRC and are
   treated as absent; a forged length can never drive an out-of-bounds read.
6. Out-of-line blobs (cmdline, measurement log, EDID) are verified with
   `bbp_verify_blob()` before they are trusted.

---

## ABI stability

`version_major` bumps on any breaking change. Within a major version, new tags
may be added (kernels ignore unknown tags) and fields may be appended to the END
of a variable-length tag only with a `tag_version` bump, old readers still
parsing the prefix. The `_Static_assert`s in `bbp.h` are the enforcement
mechanism: layout drift fails the **build**, not the boot.

---

## Status & honesty

This project states plainly what is exercised vs. what is structure-only. See
**[STATUS.md](STATUS.md)** for the maturity matrix (x86_64 is proven end-to-end;
AArch64/RISC-V/LoongArch exist in the ABI but are not yet exercised; the SECURITY
tags are defined framing, not a measuring producer). Trust is the product.

— F E R M I  ∞  H A R T
