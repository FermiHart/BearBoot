# ADR 0019: Experimental v2 SDK surfaces

- Status: Accepted
- Date: 2026-08-25

## Context

The BBP v2 capsule, Profile 0, and HMAC authentication envelope are draft,
offline-only interoperability surfaces. Keeping them only in the repository
makes downstream compilation and canonical-vector testing depend on an entire
BearBoot checkout. Moving them into SDK packages must not imply that v2 is
frozen, negotiated from v1.1, suitable for online boot handoff, or part of a new
SDK release.

## Decision

The C SDK archive explicitly allowlists the three v2 headers, their freestanding
C implementations, RFCs 0001 through 0003, a fixed-buffer Profile 0 roundtrip,
and the canonical authenticated Profile 0 vector. The host archive explicitly
allowlists the dependency-free HMAC envelope module, a package-local example,
the same RFCs, and the byte-identical vector.

The `bbp-wire` Rust crate exposes experimental slice-only v2 capsule, Profile 0,
and authentication-envelope framing. The library remains `no_std`, allocator
free, dependency free, and free of unsafe code. Authentication framing exposes
the exact MAC input and tag but does not implement or claim HMAC verification.
The crate is source-distributed with `publish = false`; packaging is validation,
not crates.io publication.

Every package boundary is an explicit file allowlist. Package tests compare the
complete archive and Cargo file sets, run examples after extraction, and require
all consumers to use the same canonical vector bytes.

## Consequences

Downstream users can build and evaluate v2 without repository-relative source
paths. The v1.1 stability contract and SDK version remain unchanged. Any v2 wire
or semantic change may still be breaking while the RFCs remain Draft, and RFC
0004 public-key host proofs remain outside these SDK surfaces.
