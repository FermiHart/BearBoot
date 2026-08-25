# ADR 0020: BBP v2 freeze requires executable gates

- Status: Accepted

## Context

The generic v2 capsule has a bounded parser, deterministic builder, canonical
digest, independent vectors, fuzzing, and multi-ISA compile coverage. Profile 0,
authentication, rollback, and deployment remain separate Draft proofs. Package
availability in SDK 1.4.0 does not freeze those surfaces.

An implementation version number is insufficient evidence for a wire freeze.
The current Draft also has no encoded profile identity, critical-entry rule, or
minor-version compatibility policy, and Profile 0 does not yet freeze its type
and attribute registries or Device Tree semantics.

## Decision

Promotion is split into explicit stages:

1. **Capsule candidate:** reconcile the C API contract, enforce output
   atomicity and immutable-view rules, and pass one shared positive/negative
   corpus in C, Rust, and Python.
2. **Profile candidate:** define profile identity and version binding, critical
   unknown-entry behavior, complete normative payload tables, registries, and
   semantic validation.
3. **Authenticated online candidate:** select one public-key composition and one
   generation policy, provide a freestanding verifier and monotonic provider,
   and reject downgrade without fallback.
4. **Deployment candidate:** execute producer-to-consumer handoff, recovery, and
   hostile-input campaigns under OVMF with persistent state.
5. **Freeze:** protect the exact normative RFCs, headers, shared vectors, and
   compatibility policy in CI and publish them in a new major SDK release.

Every stage must preserve frozen v1.1 and state its non-claims. Generic capsule
2.0 may become a candidate before Profile 0; no stage inherits maturity from
another merely because their bytes can be composed.

## Consequences

Profile 0 remains Draft after Wave 26. Online boot use remains prohibited until
authentication, anti-rollback authority, selection, and machine gates exist.
Changes to experimental v2 files remain possible, but must update their RFCs and
cross-language vectors. A later freeze decision will create a distinct CI guard;
it will not silently broaden the existing v1.1 frozen-core rules.
