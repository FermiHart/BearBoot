# RFC 0004: Experimental BBP v2 public-key authentication

- Status: **Draft host and freestanding C proof**
- Deployment: **Offline verification only; no firmware caller**
- Wire version: 1
- Updated: 2026-08-25

## Scope

This RFC defines an isolated proof for authenticating an exact bounded payload
with ECDSA P-256 and SHA-256. It does not modify the BBP v1.1 ABI, the
BBP v2 capsule, or the HMAC envelope in RFC 0003. It is not a firmware verifier,
a Secure Boot implementation, a provisioning system, or a claim about hardware
root-of-trust behavior.

All multi-byte integers are unsigned little-endian. All unused fields must be
zero. P-256 signatures are fixed-width `r || s`, with each scalar encoded as 32
unsigned big-endian bytes. Signers normalize `s` to the lower half of the P-256
group order. Verifiers reject zero, out-of-range, or high-S signatures before
calling the crypto provider.

The only algorithm value in this version is 1, ECDSA P-256 with SHA-256.
Algorithm agility is explicit rather than inferred: every key ID is the
two-byte little-endian algorithm value followed by the first 30 bytes of
`SHA-256(SubjectPublicKeyInfo DER)`. Unknown algorithm values are rejected.

## Root-Signed Manifest

A deployment supplies the root public key and minimum acceptable security
generation out of band. The root key signs one exact manifest extent. The
manifest header is 136 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | `BBP2KEY\0` |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `header_size` | 136 |
| 12 | 2 | `algorithm` | 1 |
| 14 | 2 | `entry_size` | 128 |
| 16 | 4 | `flags` | zero |
| 20 | 4 | `key_count` | 1 through 32 |
| 24 | 8 | `security_generation` | nonzero |
| 32 | 8 | `total_size` | exactly `136 + key_count * 128` |
| 40 | 32 | `root_key_id` | algorithm-tagged root identity |
| 72 | 64 | `signature` | root ECDSA signature |

The root signs the complete `total_size` bytes with the signature field replaced
by 64 zero bytes. Truncation and trailing bytes are rejected before signature
verification.

Each 128-byte manifest entry is:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 32 | `key_id` | algorithm tag plus SPKI digest |
| 32 | 2 | `algorithm` | 1 |
| 34 | 2 | `role` | 1 release, 2 recovery |
| 36 | 4 | `flags` | bit 0 revoked; all other bits zero |
| 40 | 8 | `activation_generation` | first accepted generation |
| 48 | 8 | `retirement_generation` | last accepted generation, inclusive |
| 56 | 65 | `public_key` | uncompressed SEC1 P-256 point |
| 121 | 7 | `reserved` | zero |

The manifest builder sorts entries by key ID for canonical output. A builder or
verifier rejects duplicate IDs, malformed points, mismatched IDs, invalid
windows, unknown roles or algorithms, and unsupported bits. A revoked entry is
valid policy data but can never authenticate an envelope.

## Signed Envelope

The envelope is one 136-byte header followed immediately by exactly
`payload_size` bytes. Payloads are bounded at 64 MiB.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | `BBP2SIG\0` |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `header_size` | 136 |
| 12 | 2 | `algorithm` | 1 |
| 14 | 2 | `role` | 1 release, 2 recovery |
| 16 | 4 | `flags` | zero |
| 20 | 4 | `reserved` | zero |
| 24 | 8 | `security_generation` | nonzero |
| 32 | 8 | `payload_size` | at most 64 MiB; exact remaining extent |
| 40 | 32 | `signer_key_id` | algorithm-tagged identity |
| 72 | 64 | `signature` | signer ECDSA signature |

The signer signs the complete header, with the signature field replaced by 64
zero bytes, followed by the exact payload bytes. There is no detached or
implicit payload extent and trailing bytes are forbidden.

## Verification Policy

Verification performs these checks:

1. Validate the envelope fixed fields, bounds, exact extent, and low-S scalar.
2. Authenticate the exact manifest against the out-of-band root public key.
3. Enforce the caller's minimum security generation.
4. Require envelope and manifest security generations to be equal.
5. Locate one non-duplicate manifest key matching the algorithm-tagged signer
   ID and declared role.
6. Reject revoked, not-yet-active, and retired keys.
7. Reject recovery envelopes unless the caller explicitly enables recovery.
8. Verify ECDSA P-256/SHA-256 over the exact zero-signature envelope extent.
9. Release payload bytes only after every check succeeds.

The freestanding API is zero-copy and returns borrowed views. The caller must
hold the complete root-key, manifest, and envelope extents in readable,
caller-owned storage that cannot change from the start of verification until
all returned views have been discarded. DMA-visible or otherwise shared input
must first be snapshotted into protected storage, or concurrent mutation must
be excluded by an equivalent platform mechanism. The verifier does not claim
to establish memory ownership or DMA isolation itself.

The generation floor is caller-owned monotonic state; this offline proof does not
persist or provision such state. Recovery authorization is also an explicit
caller policy and is never inferred from possession of a recovery key.

## Host Tool

`tools/bbp_auth2.py` provides `manifest-sign`, `manifest-verify`,
`envelope-sign`, and `verify`. Manifest signing consumes a JSON list whose
records name a public key, `release` or `recovery` role, activation and
retirement generations, and optional `revoked` boolean. Private keys are read
only by signing commands. Verification uses an externally supplied root public
key and writes payload output only after successful policy and signature
verification.

Python implements wire and policy handling with the standard library. The
installed `openssl` CLI is the actual ECDSA/SHA-256 provider. Checked-in test
vectors use conspicuously labeled test-only private scalars and do not contain
production keys.

## Freestanding C Proof

`include/bbp/bbp_auth2.h` and `v2/bbp_auth2.c` implement the same wire and policy
checks without allocation or libc. A private wrapper uses an exact unmodified
subset of BearSSL pinned to commit
`7bea48e5e850ab4cafbe68d3765cdaba13a86d6f`; provenance and update policy are
recorded in `third_party/bearssl/README.bearboot`.

`make auth2-freestanding-test` runs checked-in release and recovery vectors plus
hostile framing, scalar, point, policy, alias, and truncation cases.
`make auth2-portability` produces closed relocatable objects for x86_64,
AArch64, and RV64, rejects unresolved or unexpected exported symbols, verifies
the ELF machine, rejects x86 SIMD instructions, and warns on any individual
stack frame larger than 2048 bytes. `make auth2-sanitize-test` exercises the C
backend under ASan and UBSan. These are offline implementation proofs, not a
producer-to-consumer firmware execution path.
