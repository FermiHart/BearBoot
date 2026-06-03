# Changelog — Bear Boot Protocol

All notable changes. Versioning: `MAJOR.MINOR`. MAJOR bumps on an ABI break;
MINOR on backward-compatible additions. Rationale for major decisions is in
`docs/adr/`.

## v1.1

### Added
- Per-reference CRC-64/XZ for all out-of-line data (ADR-0006): `*_crc` fields
  on SECURITY (measurements/public_keys/entropy), CMDLINE (string), FRAMEBUFFER
  per-display (EDID), DEVICETREE (dtb/overlays). Closes the integrity gap where
  the measurement log — the most security-sensitive payload — had no checksum.
- `bbp_verify_blob()` — HHDM-aware, overflow-safe verification of out-of-line
  blobs against their sibling CRC.
- `bbp_verify_header()` — producer-side validation of a kernel's Bear Header
  before trusting `entry_point`/`requests`.
- `bbp_init_ex()` with an HHDM hint to resolve the higher-half chicken-and-egg
  (ADR-0005); normative HHDM reachability contract in SPEC §10.1.
- `bbp_tag_array()` — clamps a tag's claimed element count to what physically
  fits in `tag_size`, preventing OOB reads from a forged count.
- `bbp_init_win()` / `bbp_set_walk_window()` — optional walk window (ADR-0009):
  a consumer that knows the mapped tag region declares it, and the parser
  rejects any tag pointer outside it. Closes a gap a fuzzer found (a pointer
  in-range but past real RAM passed the architectural bound yet would fault on
  dereference). Disabled by default → backward compatible; no ABI change.
- `tools/bbp_stamp.py` — post-link header stamper (entry/requests/checksum),
  cross-verified against the C runtime CRC.
- Reference higher-half `examples/linker.ld` (KEEP/AT/NOLOAD, 0 linter warnings).
- Bare-metal QEMU round-trip test; structure-aware libFuzzer+ASan parser fuzzer
  (survives 380k+ executions, zero crashes); hang watchdog (SIGALRM + `timeout`
  wrapper) on the hosted gates so an infinite-loop regression fails visibly
  instead of spinning at 100% CPU; ADRs 0001–0009, CI, SECURITY.md.

### Fixed / hardened
- Integer underflow in `bbp_crc_skip` (`tag_size < 32` → ~16 EiB scan): gated.
- `bbp_for_each_tag` infinite loop on a cyclic chain of CRC-failing tags: the
  loop is now bounded by a step counter, not the delivered-tag counter.
- Overflow-safe region checks (`bbp_region_ok`): a hostile physical pointer
  near the top of the address space + a length that would wrap, or a region
  past `BBP_MAX_PHYS`, is now refused before any dereference (parser + blobs).
- Per-tag region validation moved BEFORE reading `tag_size`/`tag_id`.
- `bbp_strstatus` magic message generalized (was "BEAR_INFO"-only).

### ABI (re-asserted at compile time)
- `bbp_tag_security` 104 → 128, `bbp_tag_cmdline` 48 → 56,
  `bbp_display_info` 40 → 48, `bbp_tag_devicetree` 64 → 80.
- Backward compatible: new fields appended; v1.0 readers parse the prefix.

## v1.0

- Initial protocol: tag-based, UUID-versioned, CRC-64/XZ on every structure,
  16-byte magics, defensive parser threat model (ADR-0004), x86_64 + UEFI,
  essential tags (memory map, HHDM, framebuffer, SMP, security/TPM, ACPI,
  modules, metrics, devicetree, PCIe, EFI, hypervisor, SMBIOS), reference UEFI
  bootloader skeleton, freestanding kernel-side parser, hosted self-test.
