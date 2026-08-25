# ADR 0018: Durable generation and recovery policy

- Status: Accepted

## Context

ADR 0015 proves authentication and a single-writer rollback index, but its JSON
state is not a recovery protocol. A durable boot policy must distinguish the
monotonic authority from reconstructable operational state, survive an
interrupted write, and serialize concurrent writers without changing the BBP
wire formats.

## Decision

Wave 20 defines a host-testable policy model in
`experimental/rollback/bbp_boot_state.*`. For an established unsigned 64-bit
floor, a generation below the floor is rejected, the equal generation is an
idempotent retry, exactly `floor + 1` is an update, and larger gaps are rejected.
Arithmetic never wraps at `UINT64_MAX`: the maximum generation remains
retryable, but no successor can be authorized. Release artifacts may retry or
advance by one. Recovery artifacts may only retry at the current floor and
therefore cannot raise it. Unknown roles fail closed.

The Python model stores operational state in alternating `<path>.a` and
`<path>.b` records. Each record is canonical ASCII JSON with exactly these
members:

```text
schema, version, sequence, generation, active_slot, pending_slot, sha256
```

`schema` is `bbp-durable-boot-state` and `version` is 1. Sequence and generation
are unsigned 64-bit integers. Active and pending boot slots are `A` or `B`, the
pending slot may be null, and two non-null slots must differ. `sha256` covers
the canonical record without the digest member. Readers require the complete
canonical encoding, reject duplicate or additional members, and read at most
1024 bytes. Thus trailing data, truncation, non-ASCII data, malformed values,
and non-canonical rewrites are rejected rather than partially interpreted.

Writers hold an advisory exclusive lock at `<path>.lock` and require the
caller's expected sequence. A stale sequence is a compare-and-swap conflict.
The next sequence selects one journal path by parity, preserving the previous
record in the other path. Publication writes and fsyncs a same-directory
temporary file, atomically replaces the selected path, and fsyncs the parent
directory before success is returned.

The monotonic floor is supplied through the abstract `FloorProvider` interface.
An advancing transaction performs provider compare-and-advance before journal
publication. This order is intentional:

1. A crash before floor advancement leaves the old generation authoritative.
2. A crash after floor advancement but before journal publication leaves an old
   or absent journal, but cannot lower the floor.
3. An equal-generation recovery commit can reconstruct the active and pending
   slots and publish a new record after the second case.

On read, the valid record with the highest sequence wins. If its generation is
below the provider floor, its stale slot selections are cleared and it becomes
uninitialized operational state at the provider's generation while retaining
the sequence needed for compare-and-swap reconstruction. One corrupt record is
ignored when the other is valid. If any journal records exist but neither
validates, or if a record claims a generation above the provider, loading fails
closed. Two missing records represent uninitialized operational state at the
injected floor, which permits reconstruction without authorizing a lower
generation.

## Consequences

Deleting, replaying, or rewriting journal files cannot lower a correctly
implemented injected floor. Concurrent cooperating writers are serialized and
stale writers receive a conflict rather than overwriting newer state. The A/B
journal tolerates one torn or corrupt slot and intentionally refuses service
when both slots are unusable.

SHA-256 here detects accidental corruption and inconsistent writes; it is not
authentication because the digest is unkeyed. Advisory locking does not stop a
hostile process that ignores it. `MemoryFloorProvider` is only a hosted test
double and is neither persistent nor a security boundary. Wave 20 abstracts the
monotonic provider and makes no claim that a physical TPM, firmware counter, or
production key/provisioning policy has been implemented or tested.
