# BBP — Maturity & Honesty Matrix

This file states plainly what is **exercised**, what is **structure-only**, and
what is **roadmap**. No claim here is made that a `make` target does not back up.
Trust is the product — read this before you rely on anything.

Legend:
- 🟢 **LIVE** — exercised end-to-end with a reproducible proof in this repo.
- 🟡 **SKELETON / STRUCTURE** — the ABI/code path exists and compiles, but it is
  a reference base or a definition, not a finished, exercised implementation.
- 🔴 **ROADMAP** — designed for in the ABI, not yet built.

---

## Core protocol

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Frozen ABI (`bbp.h`) with `_Static_assert` on every struct | 🟢 LIVE | `make abi` — layout drift fails the build |
| CRC-64/XZ on info + every tag | 🟢 LIVE | `make test` self-test incl. tamper detection |
| Defensive kernel-side parser (untrusted-input safe) | 🟢 LIVE | `make test` adversarial suite; `make fuzz` over malformed corpus (no crash/hang) |
| `bbp_verify_blob()` out-of-line integrity | 🟢 LIVE | exercised by the TinaLinux hosted test (cmdline CRC) |
| `bbp_tag_array()` forged-count clamping | 🟢 LIVE | self-test + used in port consumers |
| Producer-side tag builder (`bbp_build.c`) | 🟢 LIVE | round-trip: builder → parser agree on CRCs |
| Bare-metal round-trip (real producer → real parser) | 🟢 LIVE | `make qemu` → `BBP-QEMU: PASS` |

## OS integrations (the OSIF seam)

| Integration | State | Proof / note |
|-------------|:-----:|--------------|
| `ports/tinalinux/` — native Linux OSIF | 🟢 LIVE | boots under QEMU+KVM; `bbp: tinalinux adapter ok, 5 tags, hhdm=0x…` in `ports/tinalinux/test/serial.log`; 5 CRC-sealed tags from real e820+ACPI+cmdline at `late_initcall` |
| `ports/minix/` — Limine adapter OSIF | 🟡 SKELETON+ | compiles+links against the frozen core; standalone Limine harness exists; full in-tree MINIX boot evidence is the open item in its CONFORMANCE.md |
| OSIF contract (`bbp_osif.h`) + weak/strong hook seam | 🟢 LIVE | both ports build on it; TinaLinux proves the strong-override path in a real kernel |

## Producers / bootloader side

| Capability | State | Proof / note |
|------------|:-----:|--------------|
| Tag builder API (firmware-agnostic) | 🟢 LIVE | used by both ports + the QEMU rig |
| `bootloader/efi_main.c` UEFI producer | 🟡 SKELETON | **explicitly a reference skeleton**: shows the correct seal-before-ExitBootServices ORDER and the RDI handoff. The `collect_*` / ELF-load / page-alloc functions are `extern` stubs to be implemented against real firmware. It is a base to port, not a shippable loader. |
| `tools/bbp_stamp.py` post-link header stamp | 🟢 LIVE | cross-verified against the C runtime CRC |

## Architectures

| Arch | State | Note |
|------|:-----:|------|
| x86_64 | 🟢 LIVE | every proof above is x86_64 |
| AArch64 | 🟡 ABI-only | defined in the ABI (handoff register X0, little-endian); **no AArch64 boot exercised** |
| RISC-V 64 | 🟡 ABI-only | defined (A0 handoff); not exercised |
| LoongArch | 🔴 ROADMAP | enum reserved only |

## Security tags

| Capability | State | Note |
|------------|:-----:|------|
| SECURITY / measurement / Secure-Boot tag **definitions** | 🟡 STRUCTURE | the on-the-wire structs + `*_crc` fields exist and parse |
| A producer that actually **measures** (extends PCRs, fills the log) | 🔴 ROADMAP | no measuring producer ships here; the tags are framing for one |
| CRC-64/XZ = integrity, **not** authenticity | 🟢 LIVE (documented) | `SECURITY.md` is explicit: detects corruption/casual tampering, not a signing layer |

---

## One-line summary

**The protocol, the defensive parser, the builder, and the native TinaLinux
integration are real and reproducible on x86_64.** The UEFI producer is a
reference skeleton, non-x86 is ABI-only, and the security tags are definitions
awaiting a measuring producer. Everything above is gated by a `make` target or a
checked-in log; if you find a gap between a claim and its proof, that is a bug —
please open an issue.
