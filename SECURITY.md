# Security Policy — Bear Boot Protocol

## Threat model

BBP is designed under an explicit assumption that most boot protocols do not
make: **the producer (bootloader/firmware) may be hostile or buggy.** The
bootloader is the largest attack surface of an OS (Secure Boot bypass,
evil-maid, DMA, supply-chain of the loader). See `docs/adr/0004-defensive-parser.md`.

Consequently the kernel-side parser (`kernel/bbp_kernel.c`) treats the handoff
structure and the entire tag list as UNTRUSTED INPUT. It validates structure
before dereferencing, bounds every length, checks CRC on every access path,
clamps trailing-array counts, and rejects overflowing / wrapping pointers. A
hostile producer can make the kernel REFUSE to boot, but must not be able to
make it fault, hang, or consume forged data.

### What BBP's CRC does and does NOT provide

CRC-64/XZ provides **integrity** (detects accidental corruption and casual
tampering of structures) — NOT **authenticity**. A producer that controls the
bytes can recompute any CRC. Authenticity is the job of Secure Boot and the
measured-boot chain (the SECURITY tag), never of the framing checksum. Do not
treat a valid CRC as proof of a trusted producer.

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
- Run `make test` (ASan/UBSan clean) and the fuzzer in your CI.
- When consuming out-of-line data (measurement log, cmdline, EDID, dtb), call
  `bbp_verify_blob` and refuse data whose `*_crc` fails (ADR-0006).
- Honor the HHDM reachability contract (SPEC §10.1) or you risk a page fault
  inside `bbp_init` on a higher-half handoff.
