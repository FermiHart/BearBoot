# BBP — Maturity & Honesty Matrix

This file states plainly what is **exercised**, what is **structure-only**, and
what is **roadmap**. Each claim names its reproducible gate or the checked-in
evidence and replay limit that backs it. Trust is the product — read this before
you rely on anything.

Legend:
- 🟢 **LIVE** — exercised end-to-end with a reproducible proof in this repo.
- 🟢 **MACHINE PROOF** — executes in the named target ISA, firmware context, or
  machine emulator; it does not imply a complete OS integration.
- 🟢 **HOST-TESTED / HOST PROOF** — executes on the host; it never implies boot.
- 🟢 **RECORDED** — checked-in evidence from an external boot or integration that
  the root CI does not currently replay.
- **REPORTED / UNARCHIVED** is not a green evidence state: the conformance report
  describes a run, but no raw artifact in this repository backs it.
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
| Versioned C/host SDK packages | 🟢 LIVE (1.4.0 RC) | reproducible allowlisted archives, manifest verification, extracted onboarding and v2 examples, byte-identical vectors, and deterministic JSON conformance under `make sdk-check`; no 1.4.0 release publication is claimed yet |
| Rust `bbp-wire` crate | 🟢 HOST-TESTED (1.4.0 RC) | dependency-free, always `no_std`, allocator-free slice validation with no unsafe code or physical-pointer API; frozen v1.1 plus explicitly experimental v2/Profile 0/HMAC framing, `publish = false`, and package parity under `make sdk-check` |
| `bbp_verify_blob()` out-of-line integrity | 🟢 LIVE | exercised by the TinaLinux hosted test (cmdline CRC) |
| `bbp_tag_array()` forged-count clamping | 🟢 LIVE | self-test + used in port consumers |
| Producer-side tag builder (`bbp_build.c`) | 🟢 LIVE | round-trip: builder → parser agree on CRCs |
| Bare-metal round-trip proof | 🟢 LIVE | `make qemu` boots under QEMU/TCG, requires serial `BBP-QEMU: PASS` plus guest status 33, and fails on timeout/error |
| UEFI/OVMF builder-parser proof | 🟢 LIVE | `make qemu-uefi` OVMF-loads an x86_64 PE/COFF app and requires `BBP-UEFI: PASS` plus guest status 33; not a full loader proof |
| Constrained x86_64 UEFI loader | 🟢 MACHINE PROOF | `make qemu-uefi-loader` executes bounded higher-half ELF64 loading, physical request resolution, final map/EBS, four-level identity+HHDM paging, three required v1.1 tags, and RDI kernel transfer under OVMF/TCG; complete for this constrained contract, not a general-purpose or production loader |
| AArch64 X0 + Device Tree proof | 🟢 LIVE | `make qemu-aarch64` boots a raw Image on QEMU `virt`, constructs memory-map/kernel-address tags, carries a CRC-sealed copy of QEMU's X0 DTB, re-enters the consumer with INFO in X0, and rejects payload/tag tamper; not an OS port |
| RV64 A0 + Device Tree proof | 🟢 LIVE | `make qemu-riscv64` boots through OpenSBI on QEMU `virt`, constructs memory-map/kernel-address tags, carries a CRC-sealed copy of QEMU's A1 DTB, re-enters the consumer with INFO in A0, and rejects payload/tag tamper; not an OS port |
| BBP v2 contiguous capsule Draft | 🟢 HOST-TESTED / MULTI-ISA COMPILED | offline-only parser, deterministic builder, canonical digest, v1.1 bridge, independent vectors, fuzzing, native Profile 0, and C/Rust/host package surfaces; layout, auth, and profile remain experimental, not frozen, deployed, or negotiated from v1.1 |

## OS integrations (the OSIF seam)

The hosted gates use the port and core sources in the current checkout. Archived
machine and OS logs are historical records at the revisions named by their
conformance reports; they do not show that the current core revision was booted
inside those external OS trees.

| Integration | State | Proof / note |
|-------------|:-----:|--------------|
| `ports/tinalinux/` — native Linux OSIF | 🟢 HOST-TESTED + RECORDED | current hosted five-tag adapter gate plus historical full TinaLinux boot in `ports/tinalinux/test/serial.log`; that external record is QEMU/KVM emulator evidence, not a physical-machine run, and is not replayed here |
| `ports/minix/` — Limine adapter OSIF | 🟢 HOST-TESTED + RECORDED | current synthetic hosted gate; `ports/minix/test/serial.log` is a seven-tag Limine adapter machine harness, while `serial-all6-consumers.log` is the historical six-tag full MINIX OS record; hosted CI replays neither machine boot |
| `ports/linux01/` — native identity-mapped OSIF | 🟢 HOST-TESTED | `ports/linux01/test/serial.log` is the hosted three-tag fixed-RAM-model proof; a separate in-kernel QEMU boot is reported, but no raw in-kernel serial artifact is checked in |
| `ports/josh/` — Limine + PMM OSIF | 🟢 HOST-TESTED + RECORDED | the current hosted gate exercises six tags with verified cmdline and entropy blobs, with archived output in `ports/josh/test/run.log`; `serial.log` is a historical external five-tag Josh OS record not replayed here |
| OSIF contract (`bbp_osif.h`) + weak/strong hook seam | 🟢 LIVE | four ports compile against the frozen wire interface and run hosted adapter gates against the current checkout in CI; those gates are not OS boots |

## Producers / bootloader side

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Tag builder API (firmware-agnostic) | 🟢 LIVE | used by all four OSIF adapters and the QEMU machine rigs |
| Limine, Multiboot2, and UEFI importers | 🟢 HOST-TESTED | `make importers-test` proves bounded, failure-atomic translation and parser roundtrips; platform collection remains external |
| `bootloader/efi_main.c` constrained UEFI producer | 🟢 MACHINE PROOF | the Wave 17 OVMF/TCG gate executes its ELF-load, final memory-map/EBS, paging, three-tag builder, and kernel-transfer path; unsupported required tags fail closed, and this deliberately narrow x86_64 proof is not a general-purpose production loader |
| `tools/bbp_stamp.py` post-link header stamp | 🟢 LIVE | cross-verified against the C runtime CRC |

## Architectures

| Arch | State | Note |
|------|:-----:|------|
| x86_64 | 🟢 LIVE / MACHINE PROOF | full in-tree protocol inventory plus constrained OVMF loader and UEFI/TCG2 collector machine proofs under TCG |
| AArch64 | 🟢 MACHINE PROOF (since SDK 1.3.0) | QEMU `virt` raw Image exercises X0, little-endian v1.1, bounded parsing, QEMU memory geometry, kernel address, and a CRC-verified QEMU-generated DTB; no AArch64 OS port |
| RISC-V 64 | 🟢 MACHINE PROOF (since SDK 1.3.0) | OpenSBI/QEMU `virt` exercises A0, little-endian v1.1, bounded parsing, QEMU memory geometry, kernel address, and a CRC-verified QEMU-generated DTB; no RISC-V OS port |
| LoongArch | 🔴 ROADMAP | enum reserved only |

## Security tags

| Capability | State | Note |
|------------|:-----:|------|
| SECURITY / measurement / Secure-Boot tag **definitions** | 🟢 MACHINE-EXERCISED FRAMING | the frozen structs and `*_crc` fields parse; Wave 18 publishes one measured component, while public-key/entropy fields remain zero and no Secure Boot state is asserted |
| Firmware-independent v1.1 SECURITY collector | 🟢 HOST-TESTED | `make security-collector-test` proves validation, preflight capacity, publication atomicity, abort policy, tag CRC and out-of-line log CRC with mock callbacks |
| UEFI TCG2 PCR16 collector path | 🟢 MACHINE PROOF | `make qemu-uefi-tcg2` uses OVMF `EFI_TCG2_PROTOCOL` and persistent `swtpm`, emits/consumes a SECURITY log, and independently verifies PCR16; emulator proof only, not physical TPM, Secure Boot, provisioning, or firmware identity |
| Canonical v2 measurement extended into TPM2 | 🟢 MACHINE PROOF (since SDK 1.3.0) | `make tpm2-measure-test` speaks TPM2 directly to `swtpm`, extends PCR 16, emits a JSON event record, and verifies the PCR equation |
| Authenticated v2 HMAC envelope | 🟢 HOST PROOF (since SDK 1.3.0) | shared-key identity, exact extent, replay/rollback/tamper rejection; no public-key identity or firmware key provisioning |
| Experimental P-256 public-key policy | 🟢 HOST PROOF | `make auth2-test` proves ECDSA P-256/SHA-256 exact extents, root-signed manifests, low-S policy, key lifecycle, release/recovery roles and hostile vectors through OpenSSL; not firmware or Secure Boot |
| Durable A/B rollback policy | 🟢 HOST PROOF | `make rollback-test` proves alternating canonical journals, fsync/replace publication, torn/corrupt-slot recovery, writer serialization and sequence CAS against a caller-injected floor; `MemoryFloorProvider` is not persistent TPM NV |
| CRC-64/XZ = integrity, **not** authenticity | 🟢 LIVE (documented) | `SECURITY.md` is explicit: detects corruption/casual tampering, not a signing layer |

## Evidence and release closure

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Execution-evidence v1 contract | 🟢 HOST-TESTED | `make evidence-check` validates scoped identities, exact artifact size/SHA-256, raw serial, and verdict policy; fixtures and unauthenticated physical claims are rejected as proof by default |
| Physical hardware runner contract | 🟡 CONTRACT / NO PROOF | `docs/physical-hardware-runner.md` requires identified board metadata and byte-exact serial but explicitly provides no authenticity; no physical PASS evidence is checked in |
| Four current hosted port gates | 🟢 HOST-TESTED | `make ports-hosted-check` runs the common target for TinaLinux, Linux 0.01, Josh-Bear, and MINIX; historical external records retain separate provenance and are not current OS boots |
| SDK 1.4.0 publication policy | 🟢 HOST-TESTED / CUT PENDING | `tests.test_release_policy` checks exact assets, draft ownership, resumable upload, remote digest reconciliation, Sigstore re-verification, permission isolation and no registry credentials; the candidate is not a published release or tag |

---

## One-line summary

**The frozen v1.1 protocol, constrained x86_64 OVMF loader, UEFI/TCG2 SECURITY
collector, and all four hosted adapter gates are reproducible; AArch64 and RV64
retain machine handoff proofs, and historical external OS records are labeled
separately.** Root CI does not reproduce any archived external OS boot,
Linux01's reported in-kernel run has no raw artifact, and no physical run,
physical TPM NV, firmware P-256 verifier, or Secure Boot chain is claimed. SDK
1.4.0 and all v2/auth package surfaces remain a cut-pending candidate and
experimental respectively. If a claim exceeds its proof, please open an issue.
