# Bear Boot Protocol (BBP) — Specification v1.1

    Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
    SPDX-License-Identifier: BSD-3-Clause

This document is normative. Keywords MUST / SHOULD / MAY follow RFC 2119.
The authoritative machine-readable definition is `include/bbp/bbp.h`; where
this prose and the header disagree, the header wins. Design rationale for each
major decision lives in `docs/adr/`.


## 1. Scope and model

BBP defines the handoff between a *producer* and a *consumer* (kernel). It is a
**complementary layer**: the producer is typically NOT a from-scratch bootloader
but a thin component that runs alongside an existing boot mechanism — a Limine
adapter, a UEFI-stub producer, or an in-kernel adapter on the native Linux boot
path — and re-expresses the platform data that mechanism already discovered as a
CRC-sealed tag list. BBP does not own the disk, the ELF loader, SMP bring-up, or
`ExitBootServices`; it rides on top of whatever did.

The producer collects platform information into a set of TAGS, assembles them
into a singly-linked list, prepends a fixed INFO structure, and transfers
control to the kernel's entry point with a pointer to the INFO structure in a
register.

The kernel publishes a fixed HEADER structure describing itself and the tags
it requests. The producer reads the HEADER before loading.

All structures are little-endian. All pointers stored in any structure are
**physical addresses**.


## 2. Versioning

- `BBP_VERSION_MAJOR` (1) — bumped on any breaking ABI change. A consumer
  MUST reject an INFO whose `version_major` differs from the one it was built
  against.
- `BBP_VERSION_MINOR` (0) — bumped on backward-compatible additions (new
  tags, new appended fields guarded by a tag's `tag_version`).


## 3. Magics

- HEADER magic: the 16 bytes `"BEAR_BOOT"` followed by NUL padding.
- INFO magic:   the 16 bytes `"BEAR_INFO"` followed by NUL padding.

A 16-byte magic is used (rather than 8) so a producer scanning a kernel image
for `.bbp_hdr` content has negligible false-match probability.


## 4. Integrity — CRC-64/XZ

Every INFO structure and every TAG carries an 8-byte `checksum` field holding
a CRC-64/XZ (ECMA-182, poly 0x42F0E1EBA9EA3693, reflected, init/xorout all-
ones) computed over the entire structure **with the `checksum` field itself
treated as 8 zero bytes**. For a variable-length tag the CRC covers the full
`tag_size` bytes (fixed struct + trailing array).

Canonical check value: `CRC64("123456789") == 0x995DC9BBDF1939FA`.

A consumer:
- MUST verify the INFO checksum in `bbp_init` and refuse to boot on mismatch.
- SHOULD verify each tag's checksum on access; a tag failing CRC MUST be
  treated as absent (never handed to a subsystem).


## 5. The HEADER (`struct bbp_header`, 160 bytes)

Emitted by the kernel into ELF section `.bbp_hdr`. The producer locates it by
section name (or by scanning for the magic). Notable fields:

| Field                 | Meaning                                          |
|-----------------------|--------------------------------------------------|
| magic[16]             | `"BEAR_BOOT"` + NUL padding                      |
| version_major/minor   | protocol version the kernel targets              |
| header_size           | `== 160`                                         |
| flags                 | `BBP_HF_*` (KASLR, 5-level, NX, SMP, FB, ...)     |
| entry_point           | kernel entry (phys or virt per build)            |
| paging_mode           | `BBP_PAGING_{NONE,4LEVEL,5LEVEL}`                |
| kernel_virtual_base   | desired higher-half base                          |
| request_count         | number of `bbp_tag_request` entries              |
| requests              | physical pointer to the request array            |
| kernel_uuid[2]        | 128-bit kernel identity                          |
| kernel_name[64]       | NUL-terminated                                   |
| checksum              | CRC-64/XZ of the header (this field = 0)         |

The `entry_point`, `requests`, and `checksum` fields generally cannot be
known at compile time; a post-link stamping pass computes them. The layout is
fixed-offset to make stamping a simple patch.

`KEEP(*(.bbp_hdr))` is REQUIRED in the kernel linker script — otherwise the
linker garbage-collects the header and the producer finds nothing.


## 6. Request tags (`struct bbp_tag_request`, 24 bytes)

An array the kernel publishes. Each entry: `tag_id`, `flags`, `reserved(0)`.
`BBP_REQ_OPTIONAL` marks a tag whose absence is not fatal; `BBP_REQ_EXTENDED`
requests an extended variant. The producer SHOULD honor requests but MAY
provide additional tags the kernel did not request (the kernel ignores
unknown tags).


## 7. The INFO (`struct bbp_info`, 144 bytes)

Built by the producer; pointer passed to the kernel. Carries producer
identity, boot timestamps (ns), architecture, cpu_count, `tag_count`,
`first_tag` (physical pointer to the first tag), `next_context` (physical
pointer to a chained INFO for multistage boot, 0 if none), `info_size` (total
bytes spanning the INFO plus all tags), and `checksum`.

Register on entry: RDI (x86_64 System V), X0 (AArch64), A0 (RISC-V).


## 8. Tag framing (`struct bbp_tag_header`, 32 bytes)

Every tag begins with: `tag_id` (UUID), `tag_size` (total incl. header and
trailing array), `tag_version`, `flags`, `next_tag` (physical, 0 = end), and
`checksum`. Tags are 8-byte aligned. Consumers MUST tolerate unknown
`tag_id`s and walk past them via `next_tag`.

### Tag UUID encoding

`tag_id = (category << 48) | id`. Categories: CORE 0x0001, MEMORY 0x0002,
DEVICE 0x0003, SECURITY 0x0004, PLATFORM 0x0005, DEBUG 0x0006, VENDOR 0xFFFF.


## 9. Defined tags

| UUID name              | Cat/ID        | Size  | Trailing array              |
|------------------------|---------------|-------|-----------------------------|
| BBP_TAG_SMP            | CORE/1        | 48    | bbp_cpu_info[cpu_count]     |
| BBP_TAG_MODULES        | CORE/2        | 40    | bbp_module_entry[]          |
| BBP_TAG_CMDLINE        | CORE/3        | 48    | (string via phys ptr)       |
| BBP_TAG_MEMORY_MAP     | MEMORY/1      | 40    | bbp_memory_entry[]          |
| BBP_TAG_HHDM           | MEMORY/2      | 40    | —                           |
| BBP_TAG_KERNEL_ADDRESS | MEMORY/3      | 48    | —                           |
| BBP_TAG_FRAMEBUFFER    | DEVICE/1      | 72    | bbp_display_info[]          |
| BBP_TAG_PCIE           | DEVICE/2      | 48    | bbp_pcie_device[]           |
| BBP_TAG_SECURITY       | SECURITY/1    | 104   | (measurements via phys ptr) |
| BBP_TAG_ACPI           | PLATFORM/1    | 56    | —                           |
| BBP_TAG_DEVICETREE     | PLATFORM/2    | 64    | —                           |
| BBP_TAG_EFI            | PLATFORM/3    | 64    | —                           |
| BBP_TAG_HYPERVISOR     | PLATFORM/4    | 64    | —                           |
| BBP_TAG_SMBIOS         | PLATFORM/5    | 48    | —                           |
| BBP_TAG_METRICS        | DEBUG/1       | 72    | bbp_boot_phase[]            |

### 9.1 HHDM — Higher-Half Direct Map (REQUIRED for higher-half kernels)

`offset` such that `virt = phys + offset` maps all physical RAM. The single
most important tag for a higher-half kernel: without it the kernel cannot
dereference the (physically-linked) tag list after switching to its own page
tables. `bbp_init` reads it automatically.

### 9.2 KERNEL_ADDRESS

`physical_base` / `virtual_base` where the producer actually loaded/relocated
the kernel. Needed to undo a KASLR slide and to build kernel page tables.

### 9.3 MEMORY_MAP

`bbp_memory_entry[]` with `{base, length, type, attributes, numa_node}`.
Types extend the usual set with PERSISTENT (NVDIMM), DEVICE_IO, PCI_ECAM,
USABLE_WITH_GUARD, HOTPLUGGABLE, SOFT_RESERVED. Attributes are R/W/X, cache
policy, and ENCRYPTED (SME/TME).

### 9.4 SECURITY

TPM presence/interface/base, Secure Boot state, a measurement log
(`bbp_measurement[]` referenced by physical pointer), optional public keys,
and a boot-entropy seed for the kernel CSPRNG.

(Remaining tags are documented inline in `include/bbp/bbp.h`.)


## 10. Boot flow (normative order)

```
FIRMWARE (UEFI/BIOS)
  POST -> Secure Boot validation -> hand off to the BBP producer
PRODUCER (bootloader)
  read .bbp_hdr from kernel ELF
  process request tags
  load kernel into memory
  collect hardware -> append tags (CRC sealed at finalize)
  extend TPM PCRs, record measurement log  (if TPM present)
  configure paging (if requested); apply KASLR (if requested)
  start APs (if SMP_BOOT_ALL)
  ExitBootServices (UEFI)
  finalize INFO (seal all tag CRCs + info CRC)
  jump to entry_point with INFO phys ptr in RDI/X0/A0
KERNEL
  bbp_init(): validate magic/version/size/CRC, pick up HHDM offset
  bbp_find_tag()/bbp_for_each_tag() to consume tags
  initialize subsystems; start scheduling
```

The producer MUST seal every tag's CRC and the INFO CRC AFTER the `next_tag`
chain is fully wired (the reference `bbp_builder_finalize` does this). Sealing
a tag before its `next_tag` is written produces a stale CRC the consumer will
reject.

### 10.1 HHDM reachability (REQUIRED — ADR-0005)

All tag pointers are physical, but a higher-half kernel can only dereference
them via the HHDM offset, which itself arrives inside BBP_TAG_HHDM. To break
this chicken-and-egg, at handoff the producer MUST satisfy at least one of:

  (a) leave the INFO structure and the entire tag list reachable in the
      IDENTITY map (physical == virtual at entry); the kernel then calls
      `bbp_init` (HHDM hint 0), reads BBP_TAG_HHDM, and switches to its own
      map afterward; OR
  (b) pass the INFO pointer as an HHDM VIRTUAL address AND populate
      BBP_TAG_HHDM with the matching offset; the kernel calls `bbp_init_ex`
      with that offset as the hint.

A conforming producer MUST document which of (a)/(b) it provides. A producer
that does neither is non-conforming; a kernel that dereferences `first_tag`
with offset 0 against a higher-half-only map will fault. The reference loader
uses HHDM base 0xFFFF800000000000 and provides (a).

### 10.2 Out-of-line integrity (v1.1 — ADR-0006)

For any tag carrying a physical pointer to data outside the tag (SECURITY
measurement log / public keys / entropy, CMDLINE string, FRAMEBUFFER EDID,
DEVICETREE dtb/overlays), the producer SHOULD populate the sibling `*_crc`
field with the CRC-64/XZ of the referenced bytes. A consumer MUST call
`bbp_verify_blob` before trusting such data and MUST NOT extend/replay a
measurement log whose `measurements_crc` fails. A zero `*_crc` means
"unchecked"; a consumer accepts it only if it explicitly opts in.

### 10.3 Walk window (OPTIONAL, hardening — ADR-0009)

The parser bounds every tag pointer to the architectural maximum
(`BBP_MAX_PHYS`) before dereference. That prevents an out-of-bounds read but
NOT a dereference of an address that is in-range yet UNMAPPED — on a real
higher-half kernel the HHDM maps only actual RAM, so a forged pointer past the
top of RAM passes the arithmetic check and page-faults. (Found by the parser
fuzzer.) A consumer that knows the physical region holding the tag list is
mapped MAY declare it as a walk window via `bbp_init_win(out, info, hint,
walk_lo, walk_hi)` or `bbp_set_walk_window`; the parser then rejects any tag
pointer outside `[walk_lo, walk_hi)` as corruption instead of faulting. The
window is OPTIONAL and disabled by default (`bbp_init`/`bbp_init_ex` leave it
unset, preserving v1.0/v1.1 behavior); it changes no on-the-wire structure.


## 11. Conformance

A conforming consumer passes `tests/abi_selftest.c` (including the adversarial
suite) and rejects: bad magic, mismatched major version, implausible
`info_size`, bad INFO CRC, per-tag CRC failures, undersized/oversized
`tag_size`, misaligned tag pointers, and cyclic tag chains (bounded by
BBP_MAX_TAGS). It clamps trailing-array counts to `tag_size` via
`bbp_tag_array`. A conforming producer emits structures whose `_Static_assert`
sizes match `include/bbp/bbp.h` and seals CRCs per §10.

### 11.1 Notes on non-safety fields (ADR-0008)

- `entry_point` holds the address control transfers to, IN THE KERNEL'S OWN
  address space: physical for a lower-half kernel, virtual for a higher-half
  kernel. The header `flags`/`paging_mode` indicate the regime. The field is a
  64-bit address either way; it is NOT double-translated.
- `info_size` is an INFORMATIONAL span (INFO struct + arena) and is correct
  only when `info` is contiguous with and immediately precedes the tag arena
  (the reference builder guarantees this). Consumers MUST NOT use `info_size`
  as a security bound on individual tag pointers — each tag is bounded by its
  own validated `tag_size`, never by `info_size`.


## 12. Roadmap

BBP stays a **complementary handoff + integrity layer** — the roadmap is about
deepening that layer and proving it on more targets, NOT about growing BBP into a
standalone bootloader (PXE/disk/ELF-loading remain the job of Limine/UEFI/the
Linux path that BBP rides on).

| Version | Milestone        | Scope                                                  |
|---------|------------------|--------------------------------------------------------|
| v1.1    | **current**      | x86_64 proven end-to-end; native TinaLinux OSIF boots; frozen ABI; defensive parser; out-of-line CRC |
| v1.5    | Exercise non-x86 | bring an AArch64 (Device Tree) and a RISC-V consumer up from ABI-only to a booted proof |
| v2.0    | Measuring producer | a producer that actually extends TPM PCRs + fills the measurement log (today the SECURITY tags are definitions only) |
| v2.x    | Authenticity     | optional signature layer over the CRC integrity layer (CRC ≠ authenticity, by design — see SECURITY.md) |

See `STATUS.md` for the current live/skeleton/roadmap matrix.
