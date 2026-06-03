# ADR-0009 — Optional walk window for tag-pointer dereference

Status: Accepted (introduced in protocol v1.1, backward compatible)

## Context
The kernel-side parser treats the whole handoff as untrusted input (ADR-0004).
Before dereferencing any physical tag pointer it runs `bbp_region_ok`, which
bounds the pointer to the architectural maximum (`BBP_MAX_PHYS`, 256 TiB) and
rejects zero/overflow/wrap. That is sufficient to prevent an out-of-bounds READ
of the harness's address space — but it does NOT guarantee the pointer lands on
mapped memory.

A libFuzzer + AddressSanitizer campaign over the parser found the gap: a forged
`next_tag` (or `first_tag`) whose value sits in `(top_of_RAM, BBP_MAX_PHYS)`
passes every arithmetic check, yet on a real kernel the HHDM maps only actual
RAM (a few GiB), so dereferencing it **page-faults**. The architectural bound is
not the same as "this address is mapped". This breaks the protocol's central
promise — *a hostile or buggy producer can make the kernel refuse to boot, but
must not be able to make it fault* — for the specific case of a pointer that is
in-range but unmapped.

## Decision
Add an OPTIONAL "walk window" to the parser context: a physical range
`[walk_lo, walk_hi)` that, when set (`walk_hi > walk_lo`), every tag-pointer
dereference must fall fully inside. A consumer that knows the region holding the
tag list is mapped — e.g. a bootloader-reserved area, or, in the TinaLinux port,
the `__get_free_pages` arena the adapter built the tags in — declares that
region, and the parser then rejects any pointer outside it as corruption instead
of trusting the architectural bound.

API (kernel/bbp_kernel.h):
- `bbp_init_win(out, info, hhdm_hint, walk_lo, walk_hi)` — seeds the window
  BEFORE init's own internal HHDM-tag lookup, so even that first walk is bounded
  (the fuzzer showed init itself walks the list, so a window set only afterwards
  is too late).
- `bbp_set_walk_window(k, lo, hi)` — set/adjust the window after init.
- The window is enforced inside `bbp_region_ok`, the single chokepoint every
  dereference already passes through.

Default behavior is UNCHANGED: `bbp_init`/`bbp_init_ex` leave the window at
`{0,0}` (disabled), so existing consumers and the architectural-bound path are
fully preserved. The window is a hardening opt-in, not an ABI change — no struct
layout moved.

## Consequences
+ Closes the fuzzer-found gap: with the window set, an in-range-but-unmapped
  pointer is rejected, not dereferenced. The "no fault from a hostile producer"
  promise holds for this case.
+ Backward compatible: no on-the-wire struct changed; the new fields live only
  in the in-memory `struct bbp_kctx`. Disabled by default.
+ The parser fuzzer now drives the window (bounds = its arena) and survives
  380k+ executions with zero crashes; a regression that weakened the check would
  resurface as an ASan abort.
- It is the CONSUMER's responsibility to pass a correct window. A wrong window
  (too narrow) makes valid tags appear absent (safe-fail); too wide reopens the
  gap. The honest default is "disabled" so a consumer opts in only when it can
  state the mapped region truthfully.
- Still not authenticity (ADR-0002/0006): the window bounds where the parser
  will read, not who produced the data.
