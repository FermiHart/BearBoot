# ADR 0014: Separate measurement proof from authentication

- Status: Accepted

## Context

Extending a digest into a TPM PCR proves that a measurement operation occurred,
but does not identify who produced the capsule or authorize it for boot.

## Decision

The experimental v2 proof hashes the canonical digest stream with SHA-256,
extends it into debug PCR 16 of a fresh TPM2 emulator, records the event as
JSON, and verifies `PCR_after = SHA256(PCR_before || measurement)`. It is named
a measurement machine proof, never an authentication or secure-boot proof.

## Consequences

The gate is deterministic, requires only `swtpm`, and does not alter BBP v1.1.
Signer identity, key policy, freshness, replay protection, and anti-rollback
remain separate requirements for an authenticated envelope.
