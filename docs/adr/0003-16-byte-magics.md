# ADR-0003 — 16-byte structure magics

Status: Accepted

## Context
The producer must locate the kernel's Bear Header. The cleanest path is the
ELF section `.bbp_hdr`, but a robust producer also scans for the magic as a
fallback (stripped sections, flat binaries). An 8-byte magic ("BEARBOOT") has
a 1-in-2^64 false-match probability per offset — already small, but the magic
also doubles as a human-facing identity and we wanted the names "BEAR_BOOT" /
"BEAR_INFO", which are 9 characters and do not fit in 8 bytes.

## Decision
Magics are 16 bytes: the ASCII string ("BEAR_BOOT" / "BEAR_INFO") followed by
NUL padding to 16. Comparison is over all 16 bytes.

## Consequences
+ The desired names fit, with room to spare.
+ False-match probability on a content scan drops to 1-in-2^128.
+ Trailing NULs are deterministic (zero-filled by the C initializer), so the
  comparison is exact and reproducible.
- +8 bytes each in HEADER and INFO. Irrelevant (header is 160 B total).
- All size/offset _Static_asserts were recomputed (header 152->160,
  info 136->144) and are enforced at compile time.
