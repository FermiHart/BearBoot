# ADR-0012 - Versioned SDK and conformance surfaces

Status: Accepted

## Context

The BBP v1.1 wire contract, C producer/consumer code, and host capture tool are
usable from the source tree, but source-tree paths are not a stable integration
surface. Consumers also need a short way to prove that their compiler can build
the SDK and that the real builder and bounded parser agree. Rust consumers need
wire framing without an unsafe physical-address abstraction.

The SDK release version must not be mistaken for the frozen wire version. Host
BBPC captures must likewise remain separate from the boot wire ABI.

## Decision

Maintain the development SDK version in `sdk/VERSION`; wire compatibility stays
at BBP v1.1 in `include/bbp/bbp.h`. Wave 8 starts at `1.2.0-dev`; promotion to a
release version is a separate release decision.

`tools/package_sdk.py` produces two allowlisted, reproducible archives. The C SDK
contains the wire headers, OSIF, builder, bounded importers, parser, security and
protocol documents, and one hosted round-trip example. The host-tools package
contains `bbpctl` and the BBPC v1 document. Archive paths cannot be absolute or
contain traversal components; metadata and gzip timestamps derive from
`SOURCE_DATE_EPOCH`; a manifest records SHA-256 and size for every payload file.
Development packaging records a dirty source tree honestly. `--release` rejects
a dirty tree and a development version.

The C example emits `bbp-conformance-report-v1`, a deterministic JSON report for
one named host round-trip profile. It exercises wire layout, CRC, builder
finalization, bounded parsing, trailing-count clamping, out-of-line blob policy,
tamper detection, and fail-closed allocation. This proves SDK interoperability
on the host; it does not prove firmware collection or a machine boot.

The `bbp-wire` Rust crate is dependency-free, always `no_std`, allocator-free,
and forbids unsafe code. It validates caller-provided byte slices and exposes
physical addresses only as opaque numeric values. It does not map memory, walk
physical linked lists, create pointer references, or claim semantic safety.

## Consequences

+ A C consumer can extract an archive and run `make onboarding` without copying
  files or installing project-specific dependencies.
+ Package contents and conformance output are reproducible and machine-readable.
+ C and Rust tests cross-check the same frozen envelope sizes, magic padding,
  CRC vector, defensive size limits, trailing-count behavior, and blob policy.
+ SDK release version, wire ABI version, and BBPC container version remain
  visibly separate.
- The Rust crate currently provides generic envelope validation, not typed
  layouts for every tag and not a physical-memory walker.
- The host conformance profile is not a substitute for QEMU, OVMF, or live
  downstream OS boot evidence.
