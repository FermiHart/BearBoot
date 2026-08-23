# ADR-0004 — Defensive parser / hostile-bootloader threat model

Status: Accepted

## Context
Every mainstream boot protocol (Multiboot, stivale2, Limine) implicitly trusts
the handoff structure: the kernel reads tag_size, entry counts and next-tag
pointers as if they were correct. But the bootloader/firmware is the LARGEST
attack surface of an OS — Secure Boot bypass, evil-maid, DMA, supply-chain of
the loader itself. A single corrupted `tag_size` becomes an out-of-bounds read
inside the kernel. The integrity checksum (ADR-0002) cannot save you here,
because the code that VALIDATES the checksum must first read the very fields
(tag_size, next_tag) it has not yet validated in order to compute it. That is
self-defeating, and it is the blind spot of the entire field.

## Decision
The kernel-side parser treats `bbp_info` and the tag list as UNTRUSTED INPUT
and validates structure BEFORE touching bytes:

1. Length gate before CRC. `bbp_crc_skip` refuses `len < off + 8` (returns a
   sentinel that cannot match a real CRC), and `bbp_tag_len_ok` requires
   `tag_size` in [sizeof(tag_header) .. 16 MiB] before any byte past the
   header is read. Kills the integer-underflow OOB (tag_size - 32 wrapping to
   ~16 EiB) and the multi-GiB CRC scan.
2. Pointer gate. `bbp_tag_ptr_ok` requires every physical tag pointer to be
   non-zero and 8-byte aligned; a misaligned/garbage chain stops the walk.
3. Absolute loop ceiling. `BBP_MAX_TAGS` (1024) bounds the walk regardless of
   the untrusted `tag_count`. The step counter advances on EVERY iteration,
   including CRC-skipped tags, so a cyclic next_tag of CRC-failing tags cannot
   spin forever (this exact hole was found and fixed in for_each).
4. CRC on every access path. Both `bbp_find_tag` and `bbp_for_each_tag` verify
   each tag's CRC; a failing tag is treated as absent and never handed to a
   subsystem.
5. Clamped trailing arrays. `bbp_tag_array()` clamps a tag's claimed element
   count to what physically fits in `tag_size`; callers iterate the clamped
   count, never the raw field.
6. Header validation. The producer validates the kernel's Bear Header
   (`bbp_verify_header`) before trusting `entry_point`/`requests`; HEADER and
   INFO magic comparisons cover all 16 bytes.
7. Typed-body gate. A recognized tag is not cast to its concrete structure
   until `tag_size` covers that structure. In particular, an undersized HHDM
   tag cannot expose adjacent bytes as its offset.
8. Consumer authority. A nonzero HHDM hint supplied by the consumer is not
   replaced by the producer-controlled HHDM tag.

## Consequences
+ BBP framing can be checked without trusting producer-provided lengths or tag
  counts. With a correct mapped walk window and immutable handoff memory,
  malformed framing is rejected without an unbounded read or walk.
+ Every rule has an adversarial regression test (undersized, oversized, cycle,
  misaligned, corrupt-skip, full-magic, window-extent, HHDM-hint,
  header-tamper, array-overclaim).
- Defense is structural, not cryptographic: a malicious producer can still
  hand semantically wrong-but-well-formed data (e.g. a bogus memory map). That
  is the domain of measured boot, not the parser.
- Without a caller-supplied walk window, the parser cannot prove that an
  architecturally plausible physical pointer is mapped. It also cannot prevent
  producer/DMA mutation after validation or establish semantic truth. Those are
  explicit consumer preconditions, not properties supplied by CRC framing.
