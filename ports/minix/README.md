# BBP port: MINIX x86_64 (limine-boot)

Target: MINIX kernel at /Users/admin/OS/minix/ (branch: limine-boot).

## Strategy — Limine→BBP adapter (NOT a bootloader replacement)

MINIX already boots via Limine. Do NOT replace the bootloader. Instead, very
early in the MINIX C entry (after Limine has handed off, before subsystem
init), an ADAPTER reads Limine's boot responses and SYNTHESIZES a BBP
`bbp_info` + tag list in scratch memory, then the BBP core parser validates
and exposes it. This gives MINIX the BBP tag API + defensive parser + CRC
integrity over real hardware data, with zero risk to the existing boot path.

Flow:

    Limine -> minix entry -> bbp_minix_adapter(limine responses)
                               builds bbp_info + tags via bbp_build.c
                          -> bbp_init() / bbp_init_ex() validates
                          -> MINIX consumes tags via bbp_find_tag()

## Deliverables (in THIS directory only)

1. osif.c / osif.h — implement `struct bbp_osif` for MINIX:
   - phys_to_virt: MINIX's phys->kvirt (use the kernel's existing macro/HHDM)
   - log: route to MINIX serial/kputc (console=tty00 path or direct COM1)
   - panic: call MINIX panic()
   - alloc_pages: hand back scratch (a static arena is fine for v1)
   - now_ns: TSC-based if available, else NULL

2. adapter.c — bbp_minix_adapter():
   - translate Limine memmap -> BBP_TAG_MEMORY_MAP (map Limine types to BBP_MEM_*)
   - Limine HHDM -> BBP_TAG_HHDM (CRITICAL: seeds parser translation)
   - Limine kernel-address -> BBP_TAG_KERNEL_ADDRESS
   - Limine RSDP -> BBP_TAG_ACPI
   - Limine framebuffer -> BBP_TAG_FRAMEBUFFER (optional)
   - cmdline -> BBP_TAG_CMDLINE (set string_crc!)
   - seal via bbp_builder_finalize, then bbp_init_ex(&k, info, hhdm)

3. integration.md — exact MINIX paths/flags: where to add -Iinclude, which
   .c files to add to which MINIX makefile, where bbp_minix_adapter() is
   called in the entry sequence, and the linker note (no .bbp_hdr needed for
   the adapter path — that's only for the native-BBP-boot path).

4. CONFORMANCE.md — fill the template (../CONFORMANCE.template.md).

5. test/ — capture a REAL MINIX serial log showing the adapter ran and the
   parser validated (e.g. "bbp: minix adapter ok, N tags, hhdm=0x...").

## Hard rules

- Touch ONLY files under ports/minix/. Never edit include/bbp/*, kernel/*,
  bootloader/* — the core is audited and ABI-frozen.
- Pin the core commit you built against in CONFORMANCE.md.
- Every out-of-line pointer you emit (cmdline, etc.) MUST carry its *_crc, and
  the MINIX consumer MUST call bbp_verify_blob before trusting it (ADR-0006).
- Honor SPEC §10.1: the adapter runs inside MINIX which is already mapped, so
  feed bbp_init_ex() the HHDM offset MINIX uses; do not assume identity.
- Report results in CONFORMANCE.md + test/ logs. Do not claim it works without
  a serial log proving the parser validated on real/QEMU MINIX.
