# ADR-0006 — Per-reference CRC for out-of-line data (v1.1)

Status: Accepted (introduced in protocol v1.1)

## Context
ADR-0002 puts a CRC on every fixed structure. But several tags reference data
that lives OUTSIDE the structure via a physical pointer: the SECURITY tag's
measurement log and entropy seed and public keys, the CMDLINE string, the
FRAMEBUFFER EDID blob, the DEVICETREE overlays, and (implicitly) module
contents. The tag's CRC covers only its own `tag_size` bytes — NOT the target
of those pointers. So the single most integrity-sensitive payload in the whole
protocol, the Secure Boot measurement log, shipped with ZERO checksum
coverage. The "CRC64 on all structures" promise was, for out-of-line data, a
lie. This was the most serious design hole found in audit.

## Decision
Every out-of-line reference gains a sibling CRC-64/XZ field in the referencing
tag's body, covering the pointed-to bytes. Added in v1.1 (version_minor = 1),
backward compatible (new fields appended at the END of each tag's fixed
struct; old readers parsing the v1.0 prefix still work, and the tag_version is
bumped):

- SECURITY:   measurements_crc, public_keys_crc, entropy_crc
- CMDLINE:    string_crc
- FRAMEBUFFER (per display): edid_crc
- DEVICETREE: overlays_crc

A helper `bbp_verify_blob(k, phys, len, expected_crc)` translates the physical
pointer (HHDM-aware), bounds-checks the length, computes the CRC and compares.
A consumer MUST call it before trusting any out-of-line payload it cares about;
it MUST refuse to extend/trust a measurement log whose CRC fails.

## Consequences
+ Closes the integrity gap; the measured-boot story is now coherent end to end.
+ Backward compatible: a v1.0 consumer ignores the new fields; a v1.1 consumer
  detects them via tag_version and validates.
- ABI grew (SECURITY 104->128, CMDLINE 48->56, display_info 40->48,
  DEVICETREE 64->72). All sizes re-asserted at compile time.
- Still not authentication: a malicious producer can recompute these CRCs.
  Authenticity remains the job of measured boot / signatures over the blob.
