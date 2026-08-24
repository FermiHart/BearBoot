# ADR-0010 - Host capture container for BBP v1

Status: Accepted

## Context
BBP handoff data consists of a fixed INFO structure and physically linked tags.
Host tools need to retain and inspect that data after boot, but a memory dump is
too broad and address-dependent, while rewriting pointers into file offsets
destroys the original evidence. Reusing the handoff ABI as a file format would
also blur a security boundary: kernel consumers walk mapped physical memory;
host tools walk bounded file ranges.

Evidence hashing needs a stable byte sequence that is independent of capture
file placement and container bookkeeping. It must preserve the core parser's
rule that a CRC-failed tag is ignored while traversal can continue through its
already-bounded next pointer.

## Decision
Define BBPC v1 as a separate, host-only capture container. It stores one raw
144-byte BBP v1 INFO, a fixed-size directory from original physical addresses
to absolute payload offsets, and each raw tag. Physical links remain unchanged.
Readers reconstruct the chain with an exact `source_phys` dictionary lookup,
never pointer arithmetic.

The container has its own versioned 96-byte header and whole-file CRC-64/XZ.
Strict fixed offsets, 8-byte alignment, zero padding, no trailing bytes, range
non-overlap, and conservative 64 MiB/16 MiB/1024 limits make parsing bounded.
INFO and tags retain and independently validate their BBP CRC-64/XZ fields.
This format captures BBP major 1 only; it is neither the wire ABI nor a design
placeholder for BBP or BBPC v2.

Canonical evidence is a domain separator, the exact INFO bytes, and each
structurally valid CRC-valid reachable tag once in chain order. Container
metadata is excluded. CRC-failed tags are excluded but their bounded next links
are followed. Invalid container or INFO integrity and all structural chain
errors refuse evidence generation.

`tools/bbpctl.py` is implemented with the Python standard library only. It
provides bounded inspection, strict verification, canonical evidence hashing
and streaming, and deterministic valid/corrupt fixtures. Writes are atomic and
do not overwrite or alias inputs without explicit fixture `--force` behavior.

## Consequences
+ Captures preserve the exact BBP bytes and original physical topology without
  requiring a sparse physical-memory image.
+ Canonical hashes are reproducible across hosts and container layouts, and do
  not accidentally attest directory offsets or padding.
+ Corrupt-tag exclusion matches the defensive BBP core traversal semantics.
+ Deterministic fixtures cover integrity, framing, alignment, dangling links,
  and cycles without checked-in binary artifacts.
- BBPC is an additional host format and must be documented and versioned
  independently from the BBP handoff ABI.
- The whole-file CRC detects accidental corruption but provides no
  authenticity, consistent with ADR-0002.
- Out-of-line blobs referenced by tag bodies are not captured by BBPC v1 and
  therefore are not part of its canonical evidence stream.
