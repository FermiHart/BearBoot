# RFC 0002: BBP v2 Profile 0

- Status: **Draft**
- Deployment: **Offline only**

Profile 0 adds exactly one native entry for boot identity, memory map, kernel
address, and inline Device Tree. Unknown types remain valid. The generic parser
stays registry-independent; this profile is an explicit second validation step.
Layouts and experimental type IDs are in `include/bbp/bbp_v2_profile.h`.

Every memory entry has the fixed 32-byte stride, a nonzero non-wrapping range,
a nonzero type, and a zero reserved field. Type and attribute registries remain
draft policy; the validator does not assign meaning to unknown nonzero values.

This profile is not frozen, negotiated from v1.1, or authenticated.

## Validation gates

- `make v2-profile-test` covers required, duplicate, unknown, and malformed
  semantic entries.
- `make v2-vectors-test` uses an independent Python encoder and the C parser
  across canonical and physically relocated capsule layouts.
- `make v2-fuzz` combines arbitrary framing with checksum-valid capsules whose
  Profile 0 payloads are mutated, so the semantic validator is always reached.
- `make v2-portability` cross-compiles the freestanding implementation for
  x86_64, AArch64, and RV64.
