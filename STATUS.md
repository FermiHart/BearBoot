# BBP — Maturity & Honesty Matrix

This file states plainly what is **exercised**, what is **structure-only**, and
what is **roadmap**. No claim here is made that a `make` target does not back up.
Trust is the product — read this before you rely on anything.

Legend:
- 🟢 **LIVE** — exercised end-to-end with a reproducible proof in this repo.
- 🟡 **SKELETON / STRUCTURE** — the ABI/code path exists and compiles, but it is
  a reference base or a definition, not a finished, exercised implementation.
- 🔴 **ROADMAP** — designed for in the ABI, not yet built.

---

## Core protocol

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Frozen ABI (`bbp.h`) with `_Static_assert` on every struct | 🟢 LIVE | `make abi` — layout drift fails the build |
| CRC-64/XZ on info + every tag | 🟢 LIVE | `make test` self-test incl. tamper detection |
| Defensive kernel-side parser | 🟢 LIVE | `bbp_init_bounded` fails closed on invalid mapped extents; all four in-tree ports use it; immutable handoff memory remains a consumer precondition |
| Canonical boot-evidence stream | 🟢 LIVE | domain-separated fixed INFO + each validated tag exactly once; byte framing asserted by `make test` |
| `bbpctl` + BBPC v1 host captures | 🟢 LIVE | standard-library inspector/verifier/evidence tool with deterministic valid and adversarial fixtures under `make bbpctl-test`; not wire ABI |
| Versioned C/host SDK packages | 🟢 LIVE | reproducible allowlisted archives, manifest verification, extracted `make onboarding`, and deterministic JSON conformance under `make sdk-check`; host profile only |
| Rust `bbp-wire` crate | 🟢 HOST-TESTED | dependency-free, always `no_std`, allocator-free slice validation with no unsafe code or physical-pointer API; framing/CRC parity under `make sdk-check` |
| `bbp_verify_blob()` out-of-line integrity | 🟢 LIVE | exercised by the TinaLinux hosted test (cmdline CRC) |
| `bbp_tag_array()` forged-count clamping | 🟢 LIVE | self-test + used in port consumers |
| Producer-side tag builder (`bbp_build.c`) | 🟢 LIVE | round-trip: builder → parser agree on CRCs |
| Bare-metal round-trip proof | 🟢 LIVE | `make qemu` boots under QEMU/TCG, requires serial `BBP-QEMU: PASS` plus guest status 33, and fails on timeout/error |
| UEFI/OVMF builder-parser proof | 🟢 LIVE | `make qemu-uefi` OVMF-loads an x86_64 PE/COFF app and requires `BBP-UEFI: PASS` plus guest status 33; not a full loader proof |
| AArch64 X0 + Device Tree proof | 🟢 LIVE | `make qemu-aarch64` boots a raw Image on QEMU `virt`, constructs memory-map/kernel-address tags, carries a CRC-sealed copy of QEMU's X0 DTB, re-enters the consumer with INFO in X0, and rejects payload/tag tamper; not an OS port |
| RV64 A0 + Device Tree proof | 🟢 LIVE | `make qemu-riscv64` boots through OpenSBI on QEMU `virt`, constructs memory-map/kernel-address tags, carries a CRC-sealed copy of QEMU's A1 DTB, re-enters the consumer with INFO in A0, and rejects payload/tag tamper; not an OS port |
| BBP v2 contiguous capsule Draft | 🟢 HOST-TESTED / MULTI-ISA COMPILED | offline-only parser, deterministic builder, canonical digest, v1.1 bridge, independent Python/C vectors, fuzzing, and native Profile 0 under `make v2-test`, `make v2-profile-test`, `make v2-vectors-test`, `make v2-fuzz`, and `make v2-portability`; layout and profile are experimental, not frozen or deployed |

## OS integrations (the OSIF seam)

| Integration | State | Proof / note |
|-------------|:-----:|--------------|
| `ports/tinalinux/` — native Linux OSIF | 🟢 LIVE | boots under QEMU+KVM; `bbp: tinalinux adapter ok, 5 tags, hhdm=0x…` in `ports/tinalinux/test/serial.log`; 5 CRC-sealed tags from real e820+ACPI+cmdline at `late_initcall` |
| `ports/minix/` — Limine adapter OSIF | 🟢 RECORDED | real MINIX boot evidence in `ports/minix/test/serial.log`; current root CI scaffold-checks but does not reproduce the external OS boot |
| `ports/linux01/` — native identity-mapped OSIF | 🟢 RECORDED | in-kernel QEMU boot evidence in `ports/linux01/test/serial.log`; current root CI does not reproduce it |
| `ports/josh/` — Limine + PMM OSIF | 🟢 RECORDED | real QEMU boot and verified entropy evidence in `ports/josh/test/serial.log`; current root CI does not reproduce it |
| OSIF contract (`bbp_osif.h`) + weak/strong hook seam | 🟢 LIVE | four ports compile against the same frozen interface; TinaLinux exercises its hosted adapter in current CI |

## Producers / bootloader side

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Tag builder API (firmware-agnostic) | 🟢 LIVE | used by both ports + the QEMU rig |
| Limine, Multiboot2, and UEFI importers | 🟢 HOST-TESTED | `make importers-test` proves bounded, failure-atomic translation and parser roundtrips; platform collection remains external |
| `bootloader/efi_main.c` UEFI producer | 🟡 SKELETON | **explicitly a reference skeleton**: its ELF-load, collectors, final memory-map/EBS, paging, and transfer path remain incomplete. The separate OVMF harness does not execute or validate this loader path. |
| `tools/bbp_stamp.py` post-link header stamp | 🟢 LIVE | cross-verified against the C runtime CRC |

## Architectures

| Arch | State | Note |
|------|:-----:|------|
| x86_64 | 🟢 LIVE | full in-tree protocol, firmware-context, and OS integration proof inventory |
| AArch64 | 🟢 MACHINE PROOF (SDK 1.3.0) | QEMU `virt` raw Image exercises X0, little-endian v1.1, bounded parsing, QEMU memory geometry, kernel address, and a CRC-verified QEMU-generated DTB; no AArch64 OS port |
| RISC-V 64 | 🟢 MACHINE PROOF (SDK 1.3.0) | OpenSBI/QEMU `virt` exercises A0, little-endian v1.1, bounded parsing, QEMU memory geometry, kernel address, and a CRC-verified QEMU-generated DTB; no RISC-V OS port |
| LoongArch | 🔴 ROADMAP | enum reserved only |

## Security tags

| Capability | State | Note |
|------------|:-----:|------|
| SECURITY / measurement / Secure-Boot tag **definitions** | 🟡 STRUCTURE | the on-the-wire structs + `*_crc` fields exist and parse |
| Canonical v2 measurement extended into TPM2 | 🟢 MACHINE PROOF (SDK 1.3.0) | `make tpm2-measure-test` speaks TPM2 directly to `swtpm`, extends PCR 16, emits a JSON event record, and verifies the PCR equation |
| Authenticated v2 envelope and anti-rollback | 🟢 HOST PROOF (SDK 1.3.0) | HMAC-SHA256 key identity, exact extent, atomic single-writer global monotonic state, key-rotation/replay/rollback/tamper rejection; no firmware key provisioning |
| Firmware producer that measures and fills the v1.1 SECURITY log | 🔴 ROADMAP | no measuring firmware producer ships here; the tag remains framing for one |
| CRC-64/XZ = integrity, **not** authenticity | 🟢 LIVE (documented) | `SECURITY.md` is explicit: detects corruption/casual tampering, not a signing layer |

---

## One-line summary

**The protocol, defensive parser, builder, and hosted TinaLinux adapter are
reproducible on x86_64; AArch64 also has a reproducible machine handoff proof,
and four ports carry checked-in boot records.** The root CI does not reproduce
every external OS boot. The UEFI producer is a reference skeleton, LoongArch
is roadmap, and the security tags await a measuring producer. If you find a gap
between a claim and its proof, that is a bug — please open an issue.
