# ADR-0007 — Post-link header stamping (bbp_stamp)

Status: Accepted

## Context
The kernel publishes a `struct bbp_header` as a compile-time constant in
section `.bbp_hdr`. But three of its fields cannot be known at compile time:
- `entry_point` — the kernel's real entry address (a link-time symbol).
- `requests` — the PHYSICAL address of the request array (link/load-time).
- `checksum` — the CRC-64/XZ over the header, which depends on the two above.

Leaving them zero (as v1.0 did) means the producer reads a header with a null
entry point and a null request pointer and a checksum that will never match.
The kernel literally cannot be booted by a conforming producer.

## Decision
A post-link tool, `tools/bbp_stamp`, patches the linked ELF in place:
1. Locate `.bbp_hdr` (by section, fallback to magic scan).
2. Validate magic + version + header_size.
3. Write `entry_point` from the ELF entry (e_entry) unless already non-zero.
4. Resolve the `bbp_kernel_header`/request symbol addresses and write
   `requests` (caller may pass --requests-phys for an explicit physical base
   when VMA != LMA).
5. Zero the checksum field, compute CRC-64/XZ over the 160-byte header, write
   it back.
The header layout is fixed-offset precisely so this is a deterministic patch,
not a relink. It runs in the kernel Makefile after the final link.

## Consequences
+ The kernel becomes bootable: producer reads a valid, self-consistent header.
+ Pure post-processing — no change to kernel source or linker script beyond
  KEEP(.bbp_hdr).
+ The same CRC routine (CRC-64/XZ) is shared with the runtime, so a stamp the
  tool writes is exactly what `bbp_verify_header` expects.
- The tool must understand the kernel's VMA/LMA relationship for `requests`
  when the kernel is higher-half; exposed via --requests-phys. Defaults to the
  symbol's VMA when not given (correct for identity/lower-half).
- Adds a build step; documented in README integration section.
