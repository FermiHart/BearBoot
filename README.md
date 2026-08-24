<p align="center">
  <picture>
    <source media="(max-width: 600px)" srcset="readme/hero-proof-geometry-mobile.svg">
    <img src="readme/hero-proof-geometry.svg" width="100%" alt="BearBoot proof geometry derived from the frozen ABI, parser, builder, and adversarial tests">
  </picture>
</p>

# Bear Boot Protocol (BBP)

**A complementary, verifiable boot-handoff layer.** BBP does not replace your
bootloader. It works *alongside* Limine, the UEFI stub, or the native Linux boot
path: it takes the platform data those mechanisms already discovered and
re-expresses it as a tag list that is **UUID-versioned, CRC-64/XZ-sealed, and
parsed by a hardened, adversarial-input-safe consumer.**

```
   Author:  F E R M I  ∞  H A R T  <contact@fermihart.com>
   License: BSD-3-Clause + Patent Grant (see LICENSE)
    Status:  SDK 1.3.0 / BBP wire 1.1 — ABI frozen. x86_64 end-to-end.
             Latest release: SDK 1.3.0. AArch64/RV64 machine proofs included.
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

## Proven today: four OS integrations

BBP is not a paper ABI. The same frozen core is wired into four different kernels
through the OSIF seam, each with its own producer of tags:

| Integration | How it produces tags | Status |
|-------------|----------------------|--------|
| **`ports/tinalinux/`** | **native** Linux path — `e820_table`, `acpi_os_get_root_pointer()`, `saved_command_line`, `page_offset_base` | **boots under QEMU+KVM**; serial log shows `bbp: tinalinux adapter ok, 5 tags` (see `ports/tinalinux/test/serial.log`) |
| **`ports/minix/`** | **Limine adapter** — translates Limine responses into BBP tags | real MINIX boot record shows 6 validated tags in `ports/minix/test/serial.log` |
| **`ports/linux01/`** | **native identity-mapped adapter** — describes the 1991 fixed RAM model without inventing modern firmware | in-kernel QEMU record shows 3 validated tags and a normal userspace handoff |
| **`ports/josh/`** | **Limine + PMM adapter** — bounded walk window and verified boot-entropy payload | real QEMU record shows 5 tags and CRC-verified entropy seeding the CSPRNG |

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
include/bbp/bbp_v2.h       Experimental offline v2 capsule byte layout/API.

kernel/bbp_kernel.{c,h}    Defensive kernel-side parser. HHDM-aware, no libc,
                           treats the whole handoff as untrusted input.
bootloader/bbp_build.{c,h} Producer-side tag builder (arena + CRC sealing).
bootloader/bbp_import*.c   Bounded Limine, Multiboot2, and UEFI translators.
v2/ and bridge/            Freestanding v2 capsule core and explicit v1.1 bridge.
bootloader/efi_main.c      Reference UEFI producer SKELETON (gnu-efi). A base to
                           port against your firmware — not a finished loader.

ports/tinalinux/           Native Linux->BBP OSIF (boots under QEMU; see above).
ports/minix/               Limine->BBP adapter OSIF.
ports/linux01/             Identity-mapped adapter for the Linux 0.01 RAM model.
ports/josh/                PMM-backed Josh-Bear adapter with a walk window.

examples/kernel_header.c   A kernel publishing its Bear Header in .bbp_hdr.
examples/sdk_roundtrip.c   Minimal C SDK onboarding + deterministic report.
sdk/c/                     Versioned standalone C SDK package surface.
sdk/rust/bbp-wire/         Dependency-free no_std slice validator crate.
tools/bbp_stamp.py         Post-link header stamper (entry/requests/checksum).
tools/package_sdk.py       Reproducible, allowlisted C + host SDK archives.
tests/                     Host self-test, ABI asserts, parser fuzzer, QEMU rig.
SPEC.md                    Full normative specification.
STATUS.md                  Honest maturity matrix: live / skeleton / roadmap.
docs/adr/                  Architecture Decision Records (the "why").
```

---

## Build & test

```sh
make check         # complete host gate: core, fuzz, importers, tools, SDK, docs
make test          # host-compile + run the self-test (adversarial suite incl.)
make freestanding  # cross-compile the kernel-side as a kernel would (x86_64-elf-)
make fuzz          # parser fuzzer over a malformed-input corpus
make qemu          # build + boot the bare-metal round-trip under QEMU/TCG
make qemu-aarch64  # AArch64 X0 handoff + QEMU Device Tree under TCG
make qemu-riscv64  # RV64 A0 handoff + QEMU Device Tree via OpenSBI
make qemu-uefi     # OVMF-load an x86_64 EFI builder/parser proof under TCG
make importers-test # host-test bounded boot-source translation and failures
make bbpctl-test   # verify host capture parsing, evidence, and corrupt fixtures
make v2-test       # adversarial v2 capsule, digest, and v1.1 bridge proof
make v2-profile-test # validate experimental native Profile 0 semantics
make v2-vectors-test # independent Python encoder consumed by the C parser
make v2-fuzz       # bounded malformed capsule + Profile 0 campaign
make tpm2-measure-test # extend the canonical v2 measurement into an emulated TPM2 PCR
make auth-envelope-test # host-only HMAC authentication and anti-rollback policy
make v2-portability # compile the v2 Draft core for x86_64, AArch64, and RV64
make sdk-check     # extracted C/host packages + no_std Rust parity tests
make sdk-package   # reproducible local archives under build/dist/
```

`make qemu-aarch64` requires `aarch64-linux-gnu-gcc`,
`aarch64-linux-gnu-objcopy`, GNU `timeout`, and `qemu-system-aarch64`.
`make qemu-riscv64` requires `riscv64-linux-gnu-gcc`, GNU `timeout`, and
`qemu-system-riscv64`.

The OVMF target proves PE/COFF loading and executes the real builder plus
bounded parser in pre-`ExitBootServices` firmware context. It does not turn the
reference `bootloader/efi_main.c` skeleton into a complete ELF loader or prove
its collectors, paging, EBS, and kernel-transfer path.

The AArch64 target boots a raw Linux Image on QEMU `virt`, receives its
QEMU-generated Device Tree in X0, copies and CRC-seals it into a v1.1 handoff,
then enters the consumer with INFO in X0. It proves the architecture register
contract and bounded parser on a second ISA; it is not an AArch64 OS port or
firmware loader.

The RV64 target enters through OpenSBI with hart ID in A0 and QEMU's Device
Tree in A1, then re-enters the BearBoot consumer with INFO in A0. Like the
AArch64 target, it is a bounded machine proof, not an OS port or loader.

`tools/bbpctl.py` inspects and verifies host-only `.bbpc` v1 captures and emits
the same canonical evidence stream as the core. BBPC is an archival/test
container, not a boot handoff or preview of the future BBP v2 wire format. See
`docs/bbpc-v1.md`.

The separate BBP v2 contiguous capsule is an offline-only Draft. It does not
change or negotiate the frozen v1.1 ABI. `make v2-test` proves its bounded
parser, deterministic builder, layout-independent digest stream, and explicit
v1.1 bridge. Experimental Profile 0 adds a separate semantic validator without
coupling the generic parser to a registry; see `docs/rfc/0001-bbp-v2-capsule.md`
and `docs/rfc/0002-bbp-v2-profile-0.md`.

The importer suite translates bounded Limine snapshots, raw Multiboot2 bytes,
and normalized final UEFI snapshots into the same BBP builder. It proves
failure-atomic host translation, not live firmware collection; see
`docs/adr/0011-boot-source-importers.md`.

## SDK onboarding

The C SDK, host tools, and Rust crate share release version `1.3.0`. The
compatible boot wire remains BBP v1.1. Build the allowlisted archives, then
exercise the same flow an extracted C consumer runs:

```sh
make sdk-package
make sdk-check
```

Inside the C archive, `make onboarding` compiles the complete SDK and writes a
deterministic `build/conformance.json`. The report is a host builder/parser
profile, not a firmware or machine-boot claim. The `bbp-wire` crate is always
`no_std`, has no dependencies or allocator, validates caller-owned slices, and
never dereferences physical addresses. See `docs/adr/0012-sdk-packaging.md`.

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
4. The kernel calls `bbp_init_bounded()` with its mapped tag arena → validates
   magic, version, size and CRC before a bounded HHDM/tag walk.
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
AArch64 and RV64 have reproducible machine handoff proofs; LoongArch remains
roadmap; the SECURITY tags are framing, not a measuring producer).
Trust is the product.

— F E R M I  ∞  H A R T
