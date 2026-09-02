# Security Policy — Bear Boot Protocol

## Threat model

BBP is designed under an explicit assumption that most boot protocols do not
make: **the producer (bootloader/firmware) may be hostile or buggy.** The
bootloader is the largest attack surface of an OS (Secure Boot bypass,
evil-maid, DMA, supply-chain of the loader). See `docs/adr/0004-defensive-parser.md`.

Consequently the kernel-side parser (`kernel/bbp_kernel.c`) treats the handoff
structure and the entire tag list as UNTRUSTED INPUT. It validates framing
before reading tag bodies, bounds every length, checks CRC on every access path,
clamps trailing-array counts, and rejects overflowing / wrapping pointers.

That protection has explicit preconditions. The consumer MUST make INFO and the
declared walk window readable for the duration of parsing, SHOULD use
`bbp_init_bounded` when the mapped tag extent is known, and MUST treat a nonzero HHDM
hint as part of its trusted entry contract. Without a correct walk window, an
architecturally plausible but unmapped pointer can still fault. The parser also
returns pointers into producer-owned memory: the consumer MUST ensure those
bytes cannot change concurrently, or copy validated data into kernel-owned
memory before use. CRC detects changes; it does not make a check-and-use atomic.

Structural validity is not semantic validity. Consumers still validate memory
map overlap/reservations, address ownership, enum ranges, and platform-specific
relationships before acting on a tag. Under those preconditions, malformed
framing safely becomes an absent/rejected tag rather than an unbounded read or
walk.

### What BBP's CRC does and does NOT provide

CRC-64/XZ provides **integrity** (detects accidental corruption and casual
tampering of structures) — NOT **authenticity**. A producer that controls the
bytes can recompute any CRC. Authenticity is the job of Secure Boot and the
measured-boot chain (the SECURITY tag), never of the framing checksum. Do not
treat a valid CRC as proof of a trusted producer.

Host-side `.bbpc` captures are untrusted files. `bbpctl` bounds their directory
and payload ranges before reconstructing links, but the whole-file CRC still
provides no authenticity. BBPC v1 omits out-of-line blobs and must not be
treated as a complete image of boot state or as BBP wire input.

## Experimental trust proofs

SDK 1.4.0 keeps BBP wire 1.1 frozen. Its v2 capsule, Profile 0, HMAC envelope,
and public-key policy are experimental offline surfaces, not a deployed boot
protocol. The C, Rust, and host packages expose only the v2/Profile 0/HMAC
surfaces described by RFCs 0001 through 0003. RFC 0004 now has an unpackaged
freestanding C verification proof, but no firmware caller, key provisioning,
monotonic provider, downgrade selection, or hardware root of trust. Its
zero-copy inputs must remain in immutable caller-owned storage through use of
the returned view; DMA-visible or shared input requires a protected snapshot or
equivalent exclusion. It is not a Secure Boot implementation.

The UEFI/TCG2 machine gate proves that OVMF can extend an exact digest into PCR
16 of `swtpm` and publish a CRC-sealed v1.1 SECURITY measurement log. It does not
authenticate the firmware, report Secure Boot state, provision keys, establish
freshness, or prove a physical TPM. PCR 16 is deliberately a debug PCR in these
proofs.

The durable rollback model stores operational state in an alternating A/B
journal and refuses to lower a caller-injected monotonic floor.
`MemoryFloorProvider` is a hosted test double. The experimental, unpackaged
`Tpm2NvFloorProvider` requires a pre-provisioned, written TPM2 counter with
`AUTHREAD|AUTHWRITE|COUNTER|NO_DA`, a canonical non-empty SHA-256 index
authorization of at most 32 bytes with no trailing zero, one absolute private
lock domain, and a private UNIX socket whose path owner and live peer UID match
the pinned principal. It does not hold owner-hierarchy authorization.
Every process with the index authorization must use the same lock, and the owner
hierarchy must separately prevent undefine/redefine. UID pinning authenticates a
local process principal, not a physical TPM or the freshness of daemon-backed
state. The daemon must either cancel a disconnected command before processing a
reconciliation read or globally order commands across connections; otherwise a
timed-out increment may execute late. Restored `swtpm` state after process
restart remains outside this proof. The finite timeout covers the TPM provider
lock and one socket exchange, not ADR 0018's independently blocking journal
lock.
Journal SHA-256 is corruption detection, not authentication, and no physical
TPM NV or firmware monotonic counter is claimed.

Execution-evidence bundles provide integrity, not operator identity or truthful
provenance. The format cannot prevent hosted or emulator output from being
deliberately relabeled. Physical claims are therefore rejected as proof by
default; an explicit unauthenticated override only checks their internal
integrity. This repository ships no physical PASS proof.

## Reporting a vulnerability

Email **contact@fermihart.com** with:
- a description of the issue and its impact,
- a minimal reproducer (a crafted `bbp_info`/tag blob is ideal — the fuzzer
  in `tests/fuzz_parser.c` accepts corpus files on argv),
- the affected version (`BBP_VERSION_MAJOR.MINOR`) and commit.

Please allow a reasonable disclosure window before publishing. Security fixes
are released as a new minor (compatible) or major (ABI-breaking) version with
an entry in `CHANGELOG.md` and, where relevant, a new ADR.

## Hardening checklist for integrators

- Build the parser with `-fstack-protector`-equivalents disabled only because
  it is freestanding; do enable `-Wall -Wextra -Werror` (the repo does).
- Run `make check` and the `make fuzz` sanitizer smoke campaign in your CI.
- When consuming out-of-line data (measurement log, cmdline, EDID, dtb), call
  `bbp_verify_blob` and refuse data whose `*_crc` fails (ADR-0006).
- Honor the HHDM reachability contract (SPEC §10.1) or you risk a page fault
  inside `bbp_init` on a higher-half handoff.
- Prefer `bbp_init_bounded` with the smallest mapped tag arena and preserve an
  explicit nonzero HHDM hint as trusted consumer state.
- Quiesce the producer/DMA writer or copy validated tags before using returned
  pointers; otherwise a post-validation mutation creates a TOCTOU race.
- Treat every v2/auth API as experimental and keep it outside a stable online
  boot path until its RFC and deployment policy are explicitly frozen.
- Back rollback policy with a real monotonic provider before deployment; an A/B
  journal or unkeyed digest cannot replace hardware or firmware authority.
