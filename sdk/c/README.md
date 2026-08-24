# BearBoot C SDK

This package contains the frozen BBP v1.1 wire ABI, the freestanding producer
builder, bounded Limine/Multiboot2/UEFI importers, and the defensive consumer
parser. The SDK release version and wire version are deliberately independent.
The C wire structs require a little-endian target, as mandated by BBP v1.1; the
host conformance report fails rather than claiming support on big-endian hosts.

## Five-minute onboarding

Requirements: a C11 compiler and `make`.

```sh
make onboarding
```

The target compiles every importer, builds a producer-to-consumer round trip,
checks CRC and tamper behavior, and writes `build/conformance.json`. To emit the
same deterministic report on stdout:

```sh
make -s conformance
```

The report schema is `docs/bbp-conformance-report-v1.schema.json`.

Start with `examples/sdk_roundtrip.c`. A real kernel should call
`bbp_init_bounded()` with a mapped, immutable physical span for the tag arena.
Every trailing count must pass through `bbp_tag_array()`, and every out-of-line
payload must pass through `bbp_verify_blob()` before use.

## Security boundary

CRC-64/XZ detects accidental corruption; it is not authentication. The parser
validates framing and integrity, not the platform semantics of addresses or
memory-map entries. The caller remains responsible for mapping physical ranges,
preventing handoff mutation during validation, and applying platform policy.

See `SECURITY.md` and `SPEC.md` for the complete contract.
