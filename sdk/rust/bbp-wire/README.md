# bbp-wire

`bbp-wire` is a dependency-free Rust 2021 crate for the frozen Bear Boot
Protocol v1.1 envelope. The library is unconditionally `#![no_std]`, uses no
allocator, contains no unsafe code, and has no build script.

The crate follows the BearBoot SDK release version (`1.4.0` here). That
package version is independent from the compatible BBP wire version (`1.1`).
The manifest sets `publish = false`; this source package makes no registry
availability claim.

## Scope

- Exact alignment-one little-endian wire types for `Header` (160 bytes),
  `Info` (144 bytes), and `TagHeader` (32 bytes).
- Canonical v1.1 version, magic, category, tag-ID, architecture, size, and
  defensive-bound constants.
- One-shot and incremental CRC-64/XZ.
- Slice-only `HeaderRef`, `InfoRef`, and generic `TagRef` validation.
- Bounds-first tag validation: the fixed header and declared extent are checked
  before CRC reads the complete tag.
- A helper that clamps claimed trailing-record counts to complete records in a
  validated tag extent.
- Out-of-line blob CRC checking with an explicit `BlobPolicy`. Allowing a zero
  checksum returns `BlobVerification::Unchecked`, never `Verified`.
- Experimental, offline-only BBP v2 capsule and Profile 0 validation over
  caller-owned slices.
- Experimental v2 HMAC-envelope framing that exposes exact MAC input parts but
  deliberately does not implement or claim authentication.

Unknown tag IDs are valid framing and remain available through `TagRef`; tag
semantics belong to higher-level code. Minor versions are accepted as the BBP
compatibility model requires, while a mismatched major version is rejected.
`Info::info_size` is checked for plausibility but is not treated as a contiguous
slice length or a security boundary.

## Example

```rust
use bbp_wire::{InfoRef, TagRef};

fn inspect(info_bytes: &[u8], tag_bytes: &[u8]) {
    if let (Ok(info), Ok(tag)) = (
        InfoRef::validate(info_bytes),
        TagRef::validate(tag_bytes),
    ) {
        let first_tag_bits = info.first_tag().get();
        let tag_id = tag.tag_id();
        let _ = (first_tag_bits, tag_id);
    }
}
```

The caller must first obtain slices through platform-specific mapping code. This
crate intentionally does not provide that code.

The packaged examples consume the shared canonical v2 vector:

```text
cargo run --example v2_profile
cargo run --example auth_envelope
```

The v2 APIs remain experimental draft surfaces governed by RFCs 0001 through
0003; SDK 1.4.0 does not freeze or deploy them. A parsed
authentication envelope has validated framing and capsule CRCs only; callers
must verify HMAC-SHA256 and enforce rollback/profile policy before acceptance.

## Threat Model And Limits

All input bytes are untrusted. Validators prevent short-slice reads, reject
implausible declared sizes, and cap CRC work. They do not allocate and do not
follow `first_tag`, `next_tag`, `next_context`, or any other physical value.
Physical addresses are returned as `PhysicalAddress`, an opaque numeric wire
value with no pointer conversion or dereference operation.

CRC-64/XZ detects corruption; it is not authentication. A malicious producer
can recompute it. A valid CRC does not prove:

- that a physical address is mapped, aligned, or owned by the consumer;
- that producer-owned memory cannot change after validation;
- that a linked list is acyclic or contains no more than `MAX_TAGS`;
- that a memory map, entry point, timestamp, device description, or other field
  is semantically correct or safe to act on;
- that out-of-line bytes correspond to a physical address in a tag.

The consumer must map and bound memory before constructing a slice, keep the
validated bytes immutable or copy them into owned memory, enforce a bounded
walk such as `MAX_TAGS`, and perform tag-specific semantic validation. Blob
verification accepts caller-supplied bytes only; it never maps the associated
physical address. `BlobPolicy::AllowUnchecked` is an explicit integrity opt-out
and reports an `Unchecked` result.

## Validation

```text
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```
