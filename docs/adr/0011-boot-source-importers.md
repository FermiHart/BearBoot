# ADR-0011 - Failure-atomic boot-source importers

Status: Accepted

## Context

Limine, Multiboot2, and UEFI expose similar boot facts through incompatible
structures and lifetime rules. Pulling vendor headers into the BBP core would
couple the handoff ABI to external projects, while translating partially
validated input directly into a `bbp_builder` can leave a corrupt tag chain
after a late framing or capacity error.

The current builder is a forward-only arena allocator. It has no public mark or
rollback operation, and rolling back its fields would still leave modified
arena bytes. Import therefore needs to be transactional without depending on a
future builder API.

## Decision

Provide dependency-free C11 importers in `bootloader/bbp_import*.c`. Their public
input types contain fixed-width values, explicit presence flags, bounded byte
spans, and normalized framebuffer and ACPI records. No Limine, GRUB, UEFI, or PI
header is required. The historical `bbp_import_uefi_hobs` name consumes a
normalized UEFI snapshot; it is not a parser for a PI HOB binary.

Each importer performs two phases. Preflight validates all source framing,
counts, strings, ranges, arithmetic, singleton rules, and source-specific
semantics. A shared planner then reproduces the builder's exact 8-byte aligned
bump allocation for every tag and out-of-line blob. It checks the existing
builder state, final tag count, 16 MiB per-tag ceiling, physical-address extent,
and complete required capacity. Builder calls begin only after the entire plan
succeeds, so every reported failure preserves both builder fields and all arena
bytes. Snapshot structures and their variable-size source spans are rejected
when they overlap the destination arena.

Limine responses are supplied as normalized arrays. Types 0 through 7 map to
the corresponding BBP memory classes; unknown types become RESERVED. SMP input
requires unique APIC IDs and a present BSP. Tags are emitted as HHDM,
MEMORY_MAP, KERNEL_ADDRESS, SMP, CMDLINE, FRAMEBUFFER, and ACPI.

Multiboot2 is parsed directly as bounded little-endian bytes. `total_size`, the
reserved word, tag sizes, 8-byte progression, and the terminal end tag are
mandatory. Supported data is CMDLINE, MODULES, MEMORY_MAP, RGB framebuffer, and
ACPI old/new, plus normalized HHDM and kernel-address sideband. Duplicate
supported singleton tags are rejected; ACPI new is preferred when one valid old
and one valid new tag coexist. Command lines and ACPI RSDP bytes are copied into
the builder arena. Module names are UTF-8-valid and truncated to the largest
complete prefix of 63 bytes. Unknown structurally valid tags are skipped.
Multiboot2 EFI tags are not translated or advertised as supported.

The UEFI importer accepts a normalized final snapshot. It parses the 40-byte
UEFI descriptor v1 prefix using byte offsets and permits larger strides. The
map size must be a stride multiple and every page extent must be nonempty and
overflow-free. A non-final map is rejected. The raw descriptor bytes are copied
into the arena before emission of the EFI tag. BBP v1.1's `bbp_tag_efi` has no
memory-map CRC field, so no such field is synthesized and the wire ABI remains
unchanged. Tags are emitted as HHDM, MEMORY_MAP, KERNEL_ADDRESS, CMDLINE,
FRAMEBUFFER, ACPI, EFI, and SMBIOS.

Physical addresses and ranges are restricted to BBP's existing 48-bit parser
ceiling. Bounded strings must contain exactly one trailing NUL and valid UTF-8.
Only directly representable packed RGB framebuffer layouts are accepted.

## Consequences

+ Translation is deterministic, freestanding, independent of external source
  headers, and failure-atomic with the current builder.
+ Hosted tests can prove parser roundtrips, tag and blob CRCs, source mapping,
  and unchanged state after adversarial failures.
+ The BBP wire ABI and all existing structures remain unchanged.
- Platform glue must collect and normalize live boot-service responses before
  invoking these functions; this work does not implement real firmware calls.
- Inputs must remain immutable for the duration of an import. Raw UEFI map bytes
  copied into the EFI tag are
  not covered by a BBP CRC because BBP v1.1 defines no EFI map CRC field.
