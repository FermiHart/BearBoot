# ADR 0021: Host TPM2 NV rollback authority

- Status: Accepted

## Context

ADR 0018 separates reconstructable A/B journal state from an injected monotonic
`FloorProvider`, but its only implementation is an in-memory test double. ADR
0020 requires a monotonic provider before authenticated online boot can become a
candidate. A host proof needs to exercise TPM2 wire framing and counter protocol
semantics without silently claiming persistence, provisioning, firmware
integration, or physical-hardware evidence.

A TPM daemon is also a security boundary. Password authorization crosses its
UNIX socket, a TPM counter can be undefined by a separately authorized hierarchy,
daemon state can be restored, and a read/increment/read compare-and-advance is
linearizable only when every writer cooperates. These limits must be part of the
contract rather than hidden behind a `FloorProvider` implementation.

## Decision

Wave 30 adds the repository-only `tools/tpm2_nv.py`. It consumes one externally
provisioned and already-written eight-byte TPM2 NV counter. The public area must
use SHA-256, an empty policy, and exactly
`AUTHREAD|AUTHWRITE|COUNTER|NO_DA`, with only the dynamic `WRITTEN` bit also
accepted. The default handle is `0x01804242`; every configured handle must have
the TPM NV-index handle type. The returned Name must exactly equal SHA-256 over
the validated public area.

Read and increment commands authorize with the NV index itself, not the owner
hierarchy. Callers must provide a canonical non-empty 1-to-32-byte SHA-256 index
authorization. A trailing zero is rejected because TPM password authorization
removes trailing zeros and could otherwise turn a non-empty input into an empty
or shorter effective secret.
This limits the provider credential to counter use and avoids embedding an
undefine-capable owner credential. Provisioning, first increment, undefine
policy, owner-hierarchy protection, secret storage, and rotation remain external.

`SocketTransport` accepts only an absolute UNIX socket path. Before every
exchange it requires a socket in a directory not writable by group or others,
pins the path owner, and after connect verifies the live Linux `SO_PEERCRED` UID.
Each connection carries one command, has a finite timeout, reads a bounded exact
response under one monotonic end-to-end deadline, and closes on every outcome.
Password-session responses require the reference TPM's `continueSession` bit,
empty nonce, and empty response HMAC. A canonical TPM error is exactly a
10-byte `TPM_ST_NO_SESSIONS` response; malformed error framing is a transport or
codec failure, not a trusted TPM result.

`Tpm2NvFloorProvider` requires an absolute cooperating-writer lock path. Its
directory cannot be writable by group or others. The lock must be a single-link
regular `0600` file owned by the caller, and its device/inode identity must still
match the pathname after acquisition. Lock acquisition has a finite timeout.
All writers holding the index authorization must use this same lock domain. The
daemon must also cancel a disconnected command before servicing a reconciliation
read or globally serialize commands across connections; UID pinning alone does
not establish that ordering.

Reads validate the public area before every counter read and reject an unwritten
counter. A provider instance remembers its highest observation and rejects a
lower later value. Advancement performs read, increment, and read under the
lock. Transport or malformed-response failures after the increment are
reconciled against a fresh authoritative read. An unverifiable outcome raises
`TpmNvAmbiguousError`; an observed regression raises `TpmNvRollbackError` and is
never downgraded to an ordinary conflict. TPM errors share the
`RollbackStateError` hierarchy.

The A/B journal requires an exact boolean compare-and-advance result and
revalidates both advancing and equal-generation operations before publishing. A
provider cannot claim success while the authority remains below the requested
generation; a later concurrent generation becomes a journal conflict rather
than a false accusation that the provider lied. Tests compose the TPM provider
with journal floor-first recovery and force two provider instances in separate
threads to contend through independently opened descriptors for one lock.
`make tpm2-nv-response-test` is part of `make check`.

## Consequences

The host proof now covers exact TPM2 codecs, strict metadata, dedicated index
authorization, local endpoint identity, a total transport deadline, bounded
provider locking, forced two-thread contention, uncertain increment recovery,
and journal composition. It remains an experimental repository surface and is
not included in SDK package allowlists.

The socket UID is the trusted process principal. It does not identify a physical
TPM, attest the daemon binary, bind a daemon to one hardware TPM, or prove that
its persistent state was not restored. The in-instance high-water mark cannot
detect a snapshot restored before a new process starts. A process with owner
hierarchy authorization can still undefine and recreate the index, and a process
with the index secret that ignores the shared lock can race increments. These are
deployment/provisioning failures, not properties repaired by wire parsing.

The TPM provider lock is finite and validates ownership, mode, links, and inode
identity. The A/B journal retains ADR 0018's separate indefinitely blocking
advisory lock and its cooperating-writer threat model. The current tests do not
prove cross-process serialization. A floor can also advance immediately after a
journal confirmation; such a record is safely recognized as stale on the next
load, but journal publication is not one atomic transaction with the TPM.

The checked-in tests use a fake TPM authority and a real local UNIX socket for
peer-credential behavior. They do not launch `swtpm`, persist state across daemon
restart, or exercise physical hardware. Therefore Wave 30 does not satisfy ADR
0020's monotonic-provider or deployment candidate gates. A future decision must
define protected provisioning/deletion policy, secret custody, TPM identity and
state-freshness evidence, and live emulator plus physical recovery campaigns.
