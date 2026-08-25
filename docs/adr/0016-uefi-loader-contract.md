# ADR 0016: UEFI loader physical request-pointer contract

- Status: Accepted

## Context

`bbp_header.requests` is a physical pointer. In a higher-half ELF, however, a
request-array symbol's `st_value` is its virtual memory address (VMA). Stamping
that value directly produces a valid checksum around a pointer that a UEFI ELF
loader cannot use as a physical address.

ELF `PT_LOAD` entries already define the required relationship: `p_vaddr` is
the segment VMA and `p_paddr` is its physical load address. The symbol's offset
within the segment is invariant between those address spaces.

## Decision

When `bbp_stamp.py --requests-symbol NAME` resolves a symbol, the tool MUST find
the `PT_LOAD` whose memory range contains the symbol and stamp:

```text
p_paddr + (st_value - p_vaddr)
```

Containment uses the half-open memory range `[p_vaddr, p_vaddr + p_memsz)`, so
request arrays in zero-initialized loadable memory are covered. A symbol outside
all loadable segments is rejected and the ELF is not modified. The explicit
`--requests ADDRESS` option remains an escape hatch and writes the caller's
already-physical address unchanged.

A UEFI loader consuming the stamped header loads each `PT_LOAD` according to
its physical load address and treats `bbp_header.requests` as physical. It does
not reinterpret that field as a higher-half VMA. `entry_point` retains its
separate ADR-0008 semantics and may be virtual for a higher-half kernel.

## Consequences

Higher-half kernels can publish request arrays without a second hand-maintained
physical-address constant. Malformed or non-loadable symbol locations fail at
stamp time instead of becoming checksum-valid bad handoffs. Existing explicit
address integrations and the BBP wire layout are unchanged.
