# ADR 0015: Host-only authenticated envelope and rollback state

- Status: Accepted

## Context

CRC and TPM measurement do not authorize a capsule. A small experimental gate
is needed before selecting a firmware signing format or key hierarchy.

## Decision

Use a host-only envelope with exact payload extent, HMAC-SHA256, a 128-bit key
identity derived from SHA-256, and a 64-bit rollback index. Acceptance commits
the global highest index atomically to a single-writer JSON state file, so key
rotation cannot reset the rollback floor. Equal indices
are replays; lower indices are rollbacks.

## Consequences

The proof detects wrong keys, tampering, truncation, replay, and rollback. Its
host implementation serializes cooperating writers with an advisory lock, but
does not provide sequence CAS, hostile-writer exclusion, recovery, or a hardware
monotonic counter. It is not a public-key signature format and does not define
firmware key provisioning. The envelope is experimental and does not alter BBP
v1.1 or the v2 capsule framing.
