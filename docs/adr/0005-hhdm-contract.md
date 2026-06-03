# ADR-0005 — HHDM handoff contract (the chicken-and-egg)

Status: Accepted

## Context
All tag pointers (`first_tag`, `next_tag`, out-of-line data) are PHYSICAL.
A higher-half kernel runs with only its high virtual range mapped, so it must
add a direct-map offset (HHDM) to dereference a physical pointer. But the HHDM
offset itself is delivered INSIDE a tag (BBP_TAG_HHDM) — which lives in the
physically-linked tag list the kernel cannot reach until it knows the offset.

Reading `first_tag` with offset 0 only works if the producer left the tag list
identity-mapped at handoff. If the producer handed over a higher-half-only map,
the first dereference inside `bbp_init` is a page fault → triple fault. Limine
sidesteps this by guaranteeing BOTH an identity map and an HHDM at entry; BBP
v1.0 did not mandate either, which is a latent triple-fault on the MINIX port.

## Decision
Two-part contract:

1. API: `bbp_init_ex(out, info, hhdm_hint)` lets the kernel seed the offset
   when it already knows where the producer direct-mapped RAM (from its own
   linker layout / boot agreement). `bbp_init` == `bbp_init_ex(...,0)` for the
   identity-mapped case. Once the HHDM tag is read, its authoritative value
   overrides the hint.

2. Normative requirement on the producer (SPEC §10): at handoff the producer
   MUST satisfy at least one of:
   (a) leave the tag list (and `info`) reachable in the identity map, OR
   (b) pass `info` as an HHDM virtual address AND populate BBP_TAG_HHDM, so the
       kernel can call `bbp_init_ex` with the matching hint.
   A conforming producer documents which it provides.

## Consequences
+ The egg hatches: the kernel can always reach the HHDM tag, either via
  identity (a) or via the hint (b).
+ No silent triple fault: the failure mode becomes a documented contract, not
  a mystery page fault.
- The kernel and producer must agree on the HHDM base out-of-band when using
  (b). The reference loader uses 0xFFFF800000000000 and the example kernel
  expects it; both cite this ADR.
