# ADR-0001 — Tag identity: 64-bit UUID = (category << 48) | id

Status: Accepted

## Context
A boot protocol must let a bootloader and kernel that were built separately
negotiate exactly what they exchange, without tight coupling. Multiboot uses
small dense integer tag types; stivale2 uses random 64-bit IDs. Dense small
integers collide across vendors; fully-random IDs are unsearchable and carry
no structure.

## Decision
Every tag is identified by a 64-bit value where bits [63:48] are a CATEGORY
and bits [47:0] are an ID within that category:

    tag_id = ((uint64_t)category << 48) | id      // BBP_TAG_ID(cat, id)

Categories: CORE 0x0001, MEMORY 0x0002, DEVICE 0x0003, SECURITY 0x0004,
PLATFORM 0x0005, DEBUG 0x0006, VENDOR 0xFFFF. Vendor tags live entirely under
0xFFFF and never collide with standard tags.

## Consequences
+ Human-readable, greppable, self-describing (category visible in the hex).
+ Vendors get a permanent private namespace without a registry.
+ Consumers can route by category (e.g. "skip all DEBUG tags in production").
- 8 bytes per tag id (vs 4 for Multiboot). Negligible at boot-list scale.
- A central, lightweight registry is still wanted for the standard categories
  to prevent two upstream tags claiming the same id; tracked as future work.
