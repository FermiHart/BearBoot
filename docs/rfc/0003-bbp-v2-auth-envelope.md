# RFC 0003: Experimental BBP v2 authenticated envelope

- Status: **Draft**
- Deployment: **Host only**

This RFC defines a host-side authenticated transport for one complete BBP v2
capsule. It does not modify the v2 capsule format or the frozen BBP v1.1 ABI.
The construction is an interoperability and anti-rollback proof, not a firmware
key-provisioning design or a public-key signature format.

## Wire format

The header is exactly 80 bytes. All integers are unsigned little-endian.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | `BBP2AUTH` |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `algorithm` | 1, HMAC-SHA256 |
| 12 | 4 | `flags` | zero; unknown bits are rejected |
| 16 | 8 | `rollback_index` | global unsigned monotonic index |
| 24 | 8 | `capsule_size` | exact bytes following the header |
| 32 | 16 | `key_identity` | first 16 bytes of SHA-256(key) |
| 48 | 32 | `tag` | HMAC-SHA256 authentication tag |

The MAC input is the complete 80-byte header with bytes 48 through 79 replaced
by zero, followed by exactly `capsule_size` bytes. No trailing bytes are
accepted. `capsule_size` is at most 64 MiB, matching the generic v2 parser cap.
Version 1 defines no flags and no algorithm negotiation: unknown versions,
algorithms, or flag bits fail closed.

## Acceptance

Acceptance proceeds in this order:

1. Validate the fixed framing, unsigned ranges, 64 MiB cap, and exact extent.
2. Resolve `key_identity` and verify the MAC over the canonical input.
3. Parse the payload as a complete, CRC-valid BBP v2 capsule.
4. Apply caller policy, including profile semantics and rollback policy.
5. Publish the accepted view or commit rollback state.

`bbp_v2_auth_parse` is allocation-free and takes an injected MAC verifier so a
consumer can use its own key store and cryptographic implementation. Its policy
callback is mandatory and runs only after MAC and generic v2 validation. The
output view remains byte-for-byte unchanged on every error.

`tools/bbp_v2_envelope.py` provides the HMAC-SHA256 host implementation.
`verify_and_commit` validates the generic capsule and then invokes optional
application/profile policy before replacing state. A rejected capsule never
advances state. The JSON state schema is versioned as:

```json
{"accepted_key":"<32 lowercase hex digits>","highest_rollback":42,"version":1}
```

The rollback floor is global across all trusted keys, so key rotation cannot
reset it. Equal indices are replays, lower indices are rollbacks, and an
accepted `UINT64_MAX` exhausts the state. State replacement fsyncs both the new
file and its parent directory.

## Interoperability vector

`tests/vectors/bbp-v2-profile0-auth-v1.json` is the single canonical vector. It
contains one valid Profile 0 capsule, key, key identity, rollback index, and
complete envelope. Both the Python verifier and C parser self-test consume the
same file. The C self-test injects a deterministic vector oracle as its MAC
verifier; cryptographic HMAC correctness is pinned by Python's standard library.

## Limitations

Rollback state is deliberately **single-writer only**. There is no file lock,
compare-and-swap, concurrent-writer recovery, hardware monotonic counter, or
transaction spanning capsule use and state replacement. Callers must serialize
all acceptance attempts for a state path. This draft also does not specify
public-key signatures, confidentiality, firmware key provisioning, key
revocation, or rollback-state recovery.
