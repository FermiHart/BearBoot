# RFC 0001: BBP v2 Contiguous Capsule

- Status: **Draft**
- Deployment: **Offline only**
- Wire version: 2.0
- Updated: 2026-08-22

This RFC defines an experimental, contiguous Bear Boot Protocol capsule. It
does not alter, extend, or negotiate the frozen BBP v1.1 ABI. A v2 producer and
consumer must be selected out of band. Draft capsules must not be treated as a
stable firmware/kernel handoff format or accepted from an online transport.

## Goals

BBP v2 provides one bounded byte extent containing a fixed header, a directory,
zero padding, and entry payloads. It removes physical linked-list pointers from
capsule framing, makes truncation detectable before traversal, accepts unknown
entry types, and supplies deterministic construction and hash-agnostic evidence.

The core implementation is C11 freestanding. It allocates no memory and calls
no libc function. Hosted code is used only by the adversarial self-test.

The 64-byte header is deliberately smaller than earlier design sketches. This
draft keeps only capsule-wide framing in the fixed header; extensible semantics
belong in directory entries instead of reserved fixed-header space. The layout
remains experimental and is not frozen by this RFC.

## Byte Order and Extent

Every multi-byte wire integer is unsigned little-endian. Packed C declarations
describe byte layout only; portable consumers decode fields bytewise.

`total_size` is mandatory and must exactly equal the readable extent supplied
to the parser. Neither truncation nor unaccounted trailing bytes are accepted.
The complete capsule is:

1. one 64-byte header;
2. one directory span, when `entry_count` is nonzero;
3. one nonempty payload span per directory entry; and
4. zero-filled bytes everywhere not occupied by those spans.

Header, directory, and payload spans may be physically re-laid out subject to
their alignment and non-overlap rules. All references to objects inside the
capsule are offsets from byte zero. Absolute addresses are never capsule
references.

## Header Layout

The header is exactly 64 bytes.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | `42 42 50 32 43 41 50 00` (`BBP2CAP\0`) |
| 8 | 2 | `version_major` | 2 |
| 10 | 2 | `version_minor` | 0 |
| 12 | 2 | `header_size` | 64 |
| 14 | 2 | `directory_entry_size` | 48 |
| 16 | 4 | `flags` | zero in this draft |
| 20 | 4 | `entry_count` | at most 1024 |
| 24 | 8 | `total_size` | exact supplied extent |
| 32 | 8 | `directory_offset` | capsule-relative, 8-byte aligned |
| 40 | 8 | `checksum` | CRC-64/XZ of the complete capsule with this field zero |
| 48 | 8 | `reserved0` | zero |
| 56 | 8 | `reserved1` | zero |

An empty capsule has `entry_count == 0`, `directory_offset == 64`, and
`total_size == 64`.

## Directory Layout

Each directory entry is exactly 48 bytes.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `type` | opaque entry identifier |
| 8 | 4 | `flags` | entry semantics; included in canonical evidence |
| 12 | 2 | `version` | type-specific payload version |
| 14 | 2 | `reserved0` | zero |
| 16 | 8 | `offset` | capsule-relative payload offset |
| 24 | 8 | `size` | nonzero payload byte count |
| 32 | 8 | `checksum` | CRC-64/XZ of payload bytes |
| 40 | 4 | `alignment` | power of two from 1 through 4096 |
| 44 | 4 | `reserved1` | zero |

Unknown `type` values and their payloads are valid. The core parser performs no
registry lookup and does not reinterpret unknown data. Consumers decide which
types are required after structural and integrity validation.

Directory order is semantic order. Payload offsets, alignment choices,
directory placement, checksums, and zero padding are layout metadata.

## Integrity Validation

CRC means CRC-64/XZ with reflected polynomial `0xC96C5795D7870F42`, all-one
initial value, and all-one final XOR. CRC is corruption detection, not a MAC or
signature.

The parser validates in this order:

1. fixed bytes, version, exact total extent, sizes, reserved fields, and caps;
2. directory multiplication and span bounds with subtraction-based overflow
   checks;
3. payload alignment and non-overlap with header, directory, and other payloads;
4. zero padding and cumulative work bounds; and only then
5. whole-capsule CRC followed by each payload CRC.

No checksum-controlled span is scanned before every span is proven to fit in
the supplied extent. Parsing publishes the output view only after all checks
pass.

## Deterministic Builder

`bbp_v2_build` is a one-shot builder. It first validates and sizes every input,
including source/destination non-aliasing, without writing the destination. It
then emits the directory at offset 64, places payloads in caller order at the
lowest offset satisfying each requested alignment, zeroes every gap, computes
payload CRCs, and computes the capsule CRC last. Identical calls produce
byte-identical extents. Any error leaves destination bytes unchanged.

## Canonical Digest Stream

`bbp_v2_digest` has no cryptographic dependency. A caller supplies an
incremental update callback for BLAKE3, SHA-256, or another chosen digest. The
following bytes are fed in order:

1. the 16-byte domain `BBP-V2-DIGEST\0\0\x01`;
2. a 16-byte little-endian envelope containing major, minor, header flags,
   entry count, and zero reserved bytes;
3. for each directory entry in semantic directory order, a 32-byte
   little-endian frame containing type, flags, version, payload size, and zero
   reserved bytes; and
4. that entry's payload bytes.

Offsets, alignments, CRC values, and padding are omitted. Consequently a
physical re-layout with unchanged semantic order and payloads yields the same
digest stream. Reordering entries changes the stream.

## v1.1 Bridge

The bridge is an explicit adapter, not an ABI update. It validates v1 INFO and
tag CRCs, bounds the physical chain through a caller-supplied map callback,
rejects spans at or across the 2^48 ceiling, overlapping tags, cycles, and count
mismatches, and stores one normalized v1 INFO entry plus normalized v1 wire-tag
entries. The adapter accepts exactly v1.1; it does not silently reinterpret a
future v1 minor. A normalized tag has `next_tag == 0` and
`checksum == 0`; therefore no v1 chain address becomes an internal v2
reference. The reverse bridge reconstructs contiguous physical links and v1.1
CRCs for the caller-provided output physical base.

Some v1 payloads contain addresses of data or hardware outside the tag, such as
command lines, modules, framebuffer/EDID data, firmware tables, device trees,
EFI maps, security blobs, SMP wake vectors, PCI resources, and unknown opaque
tags. The bridge does not pretend these become self-contained offsets and does
not dereference or copy them implicitly:

- default conversion fails with `BBP_V2_ERR_POLICY`;
- callers must set `BBP_V2_BRIDGE_ALLOW_EXTERNAL_PHYS` to preserve them;
- preserved entries carry `BBP_V2_EF_EXTERNAL_PHYS`; and
- reverse conversion requires the same explicit opt-in.

The caller is responsible for the lifetime, mapping, authorization, and CRC
policy of preserved external objects. Both bridge directions finish all
fallible validation and capacity planning before modifying destination bytes.
The source INFO and every byte span returned by the map callback must remain
immutable for the complete conversion; the bridge cannot make a mutable
physical producer atomic.

## Wire and Security Limits

| Limit | Value |
|---|---:|
| Total capsule extent | 64 MiB |
| Directory entries | 1024 |
| Payload alignment | 4096 bytes |
| Cumulative CRC bytes | 96 MiB |
| Bridge v1 tag size | 16 MiB |
| Bridge v1 INFO extent | 64 MiB |
| Bridge physical ceiling | 2^48 bytes |

Overlap comparison work is bounded by the square of the directory cap. Padding
selection uses the same bounded span set. Bridge cycle detection and temporary
entry storage are caller-owned and statically bounded; there is no recursion.

CRC-64/XZ does not provide authenticity, rollback resistance, freshness, or
confidentiality. Before a capsule crosses a trust boundary, an enclosing signed
and replay-resistant transport must authenticate the exact `total_size` bytes
and bind the expected BBP version and boot policy. This Draft specifies no such
transport, which is why deployment is offline only.

Native experimental semantics are defined separately by Profile 0 in
`docs/rfc/0002-bbp-v2-profile-0.md`; the generic capsule parser remains
registry-independent.
