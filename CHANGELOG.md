# Changelog — Bear Boot Protocol

All notable changes. BBP wire compatibility uses `MAJOR.MINOR`: MAJOR bumps on
an ABI break and MINOR on backward-compatible wire additions. SDK packages use
independent semantic versions. Rationale for major decisions is in `docs/adr/`.

## Unreleased

### BBP v2 freeze preparation (Wave 26)
- The one-shot builder rejects descriptor, payload, output, and result-pointer
  aliasing before modification, closing a failure-atomicity gap in the Draft API.
- Profile 0 reparses its borrowed capsule before semantic validation so a
  mutation that invalidates framing, padding, or CRC does not publish output.
- ADR 0020 defines executable capsule, profile, authentication, deployment, and
  freeze stages; Profile 0 remains Draft pending profile identity, critical
  entries, registries, Device Tree semantics, and compatibility policy.
- RFCs now state exact borrowed-view, aliasing, current Profile 0 field, and
  cooperating-writer lock behavior without broadening any v1.1 claim.

## BearBoot SDK 1.4.0 (BBP wire 1.1) - 2026-08-25

Published from signed tag
[`sdk-v1.4.0`](https://github.com/FermiHart/BearBoot/releases/tag/sdk-v1.4.0)
after reproducing the packages, passing the complete release gate, verifying
Sigstore bundles, and reconciling the exact 15 remote assets.

### Added / proven (Waves 16-24)
- Higher-half request-array symbols are stamped as physical addresses through
  their containing ELF64 `PT_LOAD`; malformed or non-loadable symbols fail
  without modifying the image.
- `make qemu-uefi-loader` exercises the constrained x86_64 loader end to end
  under OVMF/TCG: bounded ELF64 loading, stamped HEADER requests, final memory
  map and `ExitBootServices`, four-level paging/HHDM, three required v1.1 tags,
  and RDI transfer into the kernel parser. This is a complete proof of that
  constrained contract, not a general-purpose or production firmware loader.
- `make qemu-uefi-tcg2` discovers UEFI TCG2 in OVMF, extends SHA-256 evidence
  into PCR 16 of `swtpm`, publishes and consumes a CRC-sealed v1.1 SECURITY
  measurement log, and independently verifies the persistent PCR value. It is
  not Secure Boot, firmware identity, production provisioning, or physical TPM
  evidence.
- RFC 0004 and `make auth2-test` provide an offline host proof for exact-extent
  ECDSA P-256/SHA-256 envelopes, root-signed key manifests, key lifecycle and
  recovery policy. This is not a firmware verifier or Secure Boot implementation.
- `make rollback-test` proves a persistent alternating A/B journal, torn-write
  recovery, writer serialization, sequence CAS, release/recovery roles, and a
  caller-injected monotonic floor. The included floor provider is a hosted test
  double, not physical TPM NV or a firmware counter.
- All four OSIF ports expose and run a common hosted gate against the current
  checkout. Historical external emulator/OS records remain separately labeled;
  Linux 0.01's reported in-kernel run remains unarchived.
- A closed execution-evidence v1 schema separates hosted, emulator, and physical
  identity, raw serial, command status, and artifact digests. Unauthenticated
  physical claims are rejected as proof by default; no physical PASS proof is
  shipped.
- C, host, and dependency-free `no_std` Rust packages carry explicit experimental
  v2 capsule/Profile 0/HMAC framing and byte-identical vectors. v2/auth remain
  Draft, offline, non-publishable where applicable, and outside frozen wire 1.1.

### Release policy (Wave 25)
- Publication is a hardened draft-first transaction with an exact 15-asset
  allowlist, checksum and Sigstore re-verification, run/commit/tag ownership,
  resumable `--clobber` uploads, remote digest reconciliation, and publication
  only after every check passes. It refuses foreign, unexpected, or already
  published drafts and does not delete release objects.

## BearBoot SDK 1.3.0 (BBP wire 1.1) - 2026-08-24

### Added
- Reproducible AArch64 QEMU `virt` machine proof of the v1.1 X0 handoff,
  bounded identity-mapped parser, QEMU-generated Device Tree copy/CRC, and
  adversarial payload/tag rejection under `make qemu-aarch64`. This is a
  freestanding protocol proof, not an AArch64 OS port or production loader.
- Reproducible RV64 OpenSBI/QEMU `virt` machine proof of the v1.1 A0 handoff,
  bounded identity-mapped parser, QEMU-generated Device Tree copy/CRC, and
  adversarial payload/tag rejection under `make qemu-riscv64`. This is not a
  RISC-V OS port, SBI conformance test, or production loader.

### Experimental BBP v2 (offline only)
- Draft Profile 0 defines separate native semantics for boot identity, memory
  map, kernel address, and inline Device Tree. `make v2-profile-test` proves
  required-entry, duplicate, unknown-type, and malformed-stride policy.
- `make v2-vectors-test` feeds independently encoded Python capsules, including
  a physically relaid-out form, into the C parser and Profile 0 validator.
- `make v2-fuzz` runs bounded raw-framing and valid-framing/hostile-payload
  campaigns through the capsule parser and Profile 0 under libFuzzer+ASan.
- `make tpm2-measure-test` extends the SHA-256 canonical v2 measurement into
  PCR 16 of a real `swtpm` process and verifies the resulting PCR equation.
  This is a reproducible machine proof, not authentication or a firmware port.
- A host-only authenticated envelope binds a v2 capsule to an HMAC-SHA256 key
  identity and rollback index. Its single-writer state rejects replay and
  rollback under `make auth-envelope-test`; key provisioning is out of scope.
- Freestanding v2 core portability gate cross-compiles the same byte-oriented
  parser/builder for x86_64, AArch64, and RV64 under `make v2-portability`.
- Experimental contiguous v2 capsule with mandatory extent, relative payload
  offsets, bounded directory parsing, zero-padding rules, and CRC-64/XZ.
- Deterministic freestanding builder and layout-independent canonical digest
  stream with a caller-supplied hash callback.
- Explicit, bounded v1.1 bridge with opt-in policy for preserved external
  physical references. This does not alter or negotiate the frozen v1.1 ABI.
- `make v2-test` adversarial host proof; the draft also compiles freestanding.

## BearBoot SDK 1.2.0 (BBP wire 1.1) - 2026-08-22

### Added
- `bbp_evidence()` canonical, domain-separated byte stream for hashing a
  validated handoff without coupling the core to a hash implementation.
- `bbp_init_bounded()` fail-closed initializer for a known mapped tag arena;
  all four in-tree adapters and the bare-metal/fuzz proofs use it.
- `make qemu` now executes the Multiboot round-trip under QEMU/TCG with a hard
  timeout, captured serial verdict, and distinct guest success/failure exits;
  CI runs the same proof.
- `make qemu-uefi` builds a dependency-free x86_64 EFI application with
  Clang/LLD and OVMF-executes the real builder and bounded parser. The harness
  is explicitly scoped as firmware-context proof, not a complete EFI loader.
- `tools/bbpctl.py` and the separate BBPC v1 host capture format provide bounded
  inspect/verify/evidence workflows plus deterministic corruption fixtures;
  BBPC is explicitly not boot wire ABI or the future v2 capsule.
- Dependency-free, failure-atomic importers translate normalized Limine and
  final UEFI snapshots plus bounded raw Multiboot2 bytes into BBP tags. Their
  hosted gate covers successful parser roundtrips and adversarial framing.
- Versioned, reproducible C SDK and host-tools archives use explicit allowlists,
  SHA-256 manifests, safe paths, fixed metadata, and a release mode that rejects
  dirty/development sources. The extracted C SDK onboards with one `make` target
  and emits a deterministic JSON conformance report.
- The dependency-free `bbp-wire` Rust crate is always `no_std`, uses no allocator
  or unsafe code, and validates frozen BBP envelope framing and CRCs only over
  caller-provided slices without dereferencing physical addresses.

### Fixed / hardened
- Evidence hashes the fixed INFO object and every accepted tag exactly once;
  it no longer trusts informational `info_size` as a contiguous read length.
- HEADER and INFO validation compare all 16 magic bytes, including zero padding.
- Walk-window containment no longer underflows when the candidate object is
  larger than the remaining window.
- An HHDM body is read only when `tag_size` covers the concrete structure, and
  a producer-controlled HHDM tag cannot replace an explicit consumer hint.
- Tag walk bounds no longer incorrectly constrain separately allocated
  out-of-line blobs.
- Threat-model documentation now states mapped-window, immutability/TOCTOU, and
  semantic-validation preconditions instead of making an unconditional
  hostile-producer no-fault claim.
- Builder allocation rejects tag/count/physical-address/info-size overflow and
  provides a bounded string-copy entry point for untrusted source spans.

## v1.1

### Added
- Per-reference CRC-64/XZ for all out-of-line data (ADR-0006): `*_crc` fields
  on SECURITY (measurements/public_keys/entropy), CMDLINE (string), FRAMEBUFFER
  per-display (EDID), DEVICETREE (dtb/overlays). Closes the integrity gap where
  the measurement log — the most security-sensitive payload — had no checksum.
- `bbp_verify_blob()` — HHDM-aware, overflow-safe verification of out-of-line
  blobs against their sibling CRC.
- `bbp_verify_header()` — producer-side validation of a kernel's Bear Header
  before trusting `entry_point`/`requests`.
- `bbp_init_ex()` with an HHDM hint to resolve the higher-half chicken-and-egg
  (ADR-0005); normative HHDM reachability contract in SPEC §10.1.
- `bbp_tag_array()` — clamps a tag's claimed element count to what physically
  fits in `tag_size`, preventing OOB reads from a forged count.
- `bbp_init_win()` / `bbp_set_walk_window()` — optional walk window (ADR-0009):
  a consumer that knows the mapped tag region declares it, and the parser
  rejects any tag pointer outside it. Closes a gap a fuzzer found (a pointer
  in-range but past real RAM passed the architectural bound yet would fault on
  dereference). Disabled by default → backward compatible; no ABI change.
- `tools/bbp_stamp.py` — post-link header stamper (entry/requests/checksum),
  cross-verified against the C runtime CRC.
- Reference higher-half `examples/linker.ld` (KEEP/AT/NOLOAD, 0 linter warnings).
- Bare-metal QEMU round-trip test; structure-aware libFuzzer+ASan parser fuzzer
  (survives 380k+ executions, zero crashes); hang watchdog (SIGALRM + `timeout`
  wrapper) on the hosted gates so an infinite-loop regression fails visibly
  instead of spinning at 100% CPU; ADRs 0001–0009, CI, SECURITY.md.

### Fixed / hardened
- Integer underflow in `bbp_crc_skip` (`tag_size < 32` → ~16 EiB scan): gated.
- `bbp_for_each_tag` infinite loop on a cyclic chain of CRC-failing tags: the
  loop is now bounded by a step counter, not the delivered-tag counter.
- Overflow-safe region checks (`bbp_region_ok`): a hostile physical pointer
  near the top of the address space + a length that would wrap, or a region
  past `BBP_MAX_PHYS`, is now refused before any dereference (parser + blobs).
- Per-tag region validation moved BEFORE reading `tag_size`/`tag_id`.
- `bbp_strstatus` magic message generalized (was "BEAR_INFO"-only).

### ABI (re-asserted at compile time)
- `bbp_tag_security` 104 → 128, `bbp_tag_cmdline` 48 → 56,
  `bbp_display_info` 40 → 48, `bbp_tag_devicetree` 64 → 80.
- Backward compatible: new fields appended; v1.0 readers parse the prefix.

## v1.0

- Initial protocol: tag-based, UUID-versioned, CRC-64/XZ on every structure,
  16-byte magics, defensive parser threat model (ADR-0004), x86_64 + UEFI,
  essential tags (memory map, HHDM, framebuffer, SMP, security/TPM, ACPI,
  modules, metrics, devicetree, PCIe, EFI, hypervisor, SMBIOS), reference UEFI
  bootloader skeleton, freestanding kernel-side parser, hosted self-test.
