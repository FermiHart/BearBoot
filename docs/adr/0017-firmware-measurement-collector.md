# ADR 0017: Firmware-independent v1.1 SECURITY measurement collector

- Status: Accepted

## Context

BBP v1.1 already freezes `bbp_tag_security` at 128 bytes and
`bbp_measurement` at 144 bytes. The SECURITY tag references an out-of-line
measurement array whose `measurements_crc` must be checked before a consumer
trusts it. Changing either structure would break the frozen wire ABI.

Firmware APIs are not portable test dependencies. UEFI TCG2, a direct TPM
transport, and a hosted fake expose different calling conventions, while the
collector needs the same validation, ordering, and publication guarantees in
all environments. A TPM PCR extend is irreversible. Discovering insufficient
local arena capacity after extending a PCR would leave evidence in the TPM
without a corresponding BBP record.

## Decision

Provide a freestanding C11 collector in
`experimental/firmware/uefi/bbp_security_collector.{h,c}`. It consumes bounded
component descriptors and platform metadata without including UEFI or TCG2
headers. Firmware glue supplies two interfaces:

- `hash_extend` hashes the supplied component with SHA-256, extends the digest
  into the requested PCR, and returns the exact 32-byte digest.
- `arena_allocate` publishes either the completed measurement array or the
  SECURITY tag through the supplied `bbp_builder`. The provided
  `bbp_security_builder_allocate` adapter uses `bbp_arena_blob` and
  `bbp_alloc_tag`.

The v1.1 collector supports one through 32 records. Every descriptor must use
`BBP_HASH_SHA256`, declare a 32-byte hash, select PCR 0 through 23, provide one
through 64 MiB of readable component bytes, and provide a nonempty component
name of at most 63 bytes. The explicit name length excludes the terminating
NUL; embedded NUL bytes are rejected and the collector writes the terminator.
Reserved fields, unsupported TPM metadata, malformed pointer spans, and
invalid builder state are rejected.

Collection has three ordered phases:

1. Validate every descriptor and platform field, validate the current builder,
   and reproduce both 8-byte-aligned allocations exactly. Complete log and tag
   capacity is proven before any external TPM callback.
2. Call `hash_extend` for each descriptor and construct canonical
   `bbp_measurement` records in local storage. A first-call TPM failure returns
   without invoking the arena allocator or changing output.
3. Copy the complete record array into the builder arena, allocate and populate
   `bbp_tag_security`, compute CRC-64/XZ over exactly
   `measurement_count * sizeof(struct bbp_measurement)`, seal the tag, and only
   then publish `out_tag`. A zero CRC, which v1.1 reserves to mean unchecked,
   takes the abort path rather than publishing unverifiable evidence.
   Public-key and entropy fields remain zero.

All recoverable failures preserve the builder, arena, and output pointer. The
collector retains the exact destination bytes needed to roll back an allocator
contract failure. If one or more PCR extensions have succeeded but a later TPM
operation or local publication cannot complete, it restores local state and
calls the required `abort` hook. Firmware integrations must make that hook
non-returning; a returning hosted test hook receives
`BBP_SECURITY_ERR_ABORT_RETURNED`.

## Consequences

- Existing v1.1 byte layout and frozen ABI declarations are unchanged.
- Capacity errors are deterministic and occur before any TPM side effect.
- A consumer can validate the SECURITY tag through the bounded parser and the
  measurement array independently through `bbp_verify_blob`.
- Tests use a real `bbp_builder` arena and mock callbacks, so they prove the
  collector state machine and wire output without firmware dependencies.
- This is not evidence of a live OVMF TCG2 invocation, firmware protocol
  discovery, TPM provisioning, Secure Boot policy, authentication, freshness,
  or rollback protection. Platform glue remains responsible for those tasks.
