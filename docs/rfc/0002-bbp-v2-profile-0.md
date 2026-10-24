# RFC 0002: BBP v2 Profile 0

- Status: **Draft**
- Deployment: **Offline only**
- Entry payload version: 1

Profile 0 adds exactly one native entry for boot identity, memory map, kernel
address, and inline Device Tree bytes. Unknown types remain valid. The generic
parser stays registry-independent; this profile is an explicit second
validation step and reparses the complete capsule before publishing a view.

This profile is not frozen, encoded in the generic capsule, negotiated from
v1.1, or authenticated. A producer and consumer currently select Profile 0 out
of band. Type IDs and field acceptance below describe the implemented Draft;
they are not a stable registry allocation.

## Common entry rules

The four recognized type IDs are:

| Type | ID |
|---|---:|
| Boot identity | `0x4242503200000001` |
| Memory map | `0x4242503200000002` |
| Kernel address | `0x4242503200000003` |
| Device Tree | `0x4242503200000004` |

Every recognized entry has directory `version == 1` and `flags == 0`.
Duplicates, missing recognized entries, and malformed recognized payloads fail
the complete profile. Unknown entries are ignored by Profile 0 after generic
capsule validation.

## Boot identity

The payload is exactly 16 bytes:

| Offset | Size | Field | Current Draft rule |
|---:|---:|---|---|
| 0 | 2 | `architecture` | 1 x86_64, 2 AArch64, 3 RV64, 4 LoongArch |
| 2 | 2 | `reserved0` | zero |
| 4 | 4 | `cpu_count` | nonzero |
| 8 | 4 | `flags` | zero |
| 12 | 4 | `reserved1` | zero |

Architecture values currently mirror v1.1, but this mapping is not frozen by
the Draft. CPU count is descriptive and does not authorize array access.

## Memory map

The payload begins with an 8-byte header:

| Offset | Size | Field | Current Draft rule |
|---:|---:|---|---|
| 0 | 4 | `entry_count` | 1 through 4096 |
| 4 | 4 | `entry_size` | exactly 32 |

Exactly `entry_count` records follow, with no trailing bytes:

| Offset | Size | Field | Current Draft rule |
|---:|---:|---|---|
| 0 | 8 | `base` | any unsigned value forming a valid range |
| 8 | 8 | `length` | nonzero; `base + length` must not wrap |
| 16 | 4 | `type` | nonzero; registry remains Draft |
| 20 | 4 | `attributes` | opaque in this Draft |
| 24 | 4 | `numa_node` | opaque in this Draft |
| 28 | 4 | `reserved` | zero |

The current validator does not require sorting, page alignment, disjoint ranges,
known types or attributes, or a relationship with the kernel-address entry.
Consumers must not treat structural acceptance as a usable platform memory map
without a separate policy.

## Kernel address

The payload is exactly 16 bytes:

| Offset | Size | Field | Current Draft rule |
|---:|---:|---|---|
| 0 | 8 | `physical_base` | nonzero |
| 8 | 8 | `virtual_base` | any unsigned value |

Alignment, canonical-address, image-size, and memory-map containment checks are
not part of the current Profile 0 validator.

## Device Tree bytes

The payload begins with an 8-byte header followed by at least one byte:

| Offset | Size | Field | Current Draft rule |
|---:|---:|---|---|
| 0 | 4 | `flags` | zero |
| 4 | 4 | `dtb_size` | exact number of following bytes |

Despite the entry name, the current profile treats the following extent as
opaque nonempty bytes. It does not validate FDT magic, header fields, totalsize,
blocks, or semantics. Freeze requires an explicit decision to retain opaque
bytes or require bounded FDT validation.

## Borrowed-view lifetime

The returned Device Tree pointer borrows the capsule extent. The complete
capsule must remain readable and immutable while the Profile 0 view is used.
This native inline Device Tree payload is distinct from a bridged v1 Device Tree
tag: the latter contains physical reference values, is marked
`BBP_V2_EF_EXTERNAL_PHYS`, and receives no Profile 0 validation or ownership.
`bbp_v2_p0_validate` reparses the capsule, so a mutation after an earlier generic
parse that invalidates framing, padding, or CRC is rejected before output is
published. Reparse is not a lock or TOCTOU defense: a writer can construct a new
valid capsule, and the caller remains responsible for immutability.

## Freeze blockers

Profile 0 cannot be promoted until the project defines:

1. encoded or cryptographically bound profile identity and profile version;
2. critical unknown-entry behavior;
3. type, memory-type, attribute, NUMA, and flag registries;
4. memory ordering, overlap, alignment, and kernel-containment policy;
5. Device Tree opacity versus bounded FDT validation; and
6. minor-version compatibility and downgrade behavior.

## Validation gates

- `make v2-profile-test` covers required, duplicate, unknown, malformed, and
  stale-view behavior.
- `make v2-vectors-test` consumes the generated 46-case corpus in C and an
  independent Python validator, including every current field-rule family,
  output atomicity, canonical digests, and physically relocated layouts. The
  same repository corpus is consumed directly by Rust under `make sdk-check`.
- `make v2-fuzz` combines arbitrary framing with checksum-valid capsules whose
  Profile 0 payloads are mutated, so the semantic validator is reached.
- `make v2-portability` cross-compiles the freestanding implementation for
  x86_64, AArch64, and RV64.
