# ADR-0008 — Field typing and info_size coupling

Status: Accepted

## Context
Two smaller correctness/clarity issues surfaced in audit:

1. `entry_point` is typed `bbp_phys_t` but, for a higher-half kernel, the value
   the producer jumps to is a VIRTUAL address (the high-half entry). The type
   misleads readers into treating it as physical and double-translating it.

2. `bbp_builder_finalize` computes `info_size = sizeof(info) + builder.used`.
   This is only correct when the `info` struct sits immediately before the
   builder arena and they are contiguous. If a caller allocates `info`
   separately, `info_size` is silently wrong, and a consumer that trusts it to
   bound the handoff region reads the wrong span.

## Decision
1. Keep the field width (both are 64-bit addresses, ABI-identical) but rename
   the SEMANTICS in documentation: `entry_point` holds the address control is
   transferred to, in the kernel's own address space — physical for a
   lower-half kernel, virtual for higher-half. The header `flags`/`paging_mode`
   tell the producer which regime applies. A doc comment in bbp.h states this;
   no ABI change.

2. Document the contiguity precondition of `bbp_builder_finalize` explicitly in
   both the header and bbp.h, and have the reference `efi_main.c` follow it
   (info at arena front, builder immediately after). Consumers MUST NOT use
   `info_size` as a security bound on individual tag pointers — each tag is
   bounded by its own validated `tag_size` (ADR-0004), and `info_size` is an
   informational span only. The parser already relies on tag_size, not
   info_size, for safety.

## Consequences
+ No ABI churn; both are documentation/contract fixes.
+ Removes the "is entry_point physical or virtual?" footgun.
+ Makes explicit that `info_size` is informational, not a safety boundary, so
  nobody builds a bounds check on a fragile value.
- A future v2 could split entry_point into entry_phys/entry_virt if the
  ambiguity ever causes real bugs; deferred until evidence justifies the ABI
  break.
