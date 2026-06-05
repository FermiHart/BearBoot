# BBP port: Josh-Bear x86_64 ("lisabeth", limine-boot)

Target: Josh-Bear monolithic kernel at $JOSH (the
"lisabeth" x86_64 kernel, booted by Limine).

## Strategy — Limine→BBP adapter (NOT a bootloader replacement)

Josh-Bear already boots via Limine. Do NOT replace the bootloader. Instead,
early in Josh's C entry — but AFTER vmm/pmm/heap are up — an ADAPTER reads
Josh's already-parsed Limine responses and SYNTHESIZES a BBP `bbp_info` + tag
list, then the BBP core parser validates and exposes it. This gives Josh the
BBP tag API + defensive parser + CRC integrity over real hardware data, with
zero risk to the existing boot path.

## Why this port is SIMPLER than ports/minix/

Josh-Bear is a MONOLITHIC x86_64 kernel: by the time the adapter runs, the
VMM, the PMM (a buddy allocator) and the heap are ALREADY up. That removes the
two awkward dances the MINIX microkernel port had to perform:

- **HHDM is a single direct map.** The OSIF's `phys_to_virt` is just
  `phys + g_hhdm_offset` using Josh's own HHDM global — the same one the rest of
  the kernel uses. No `set_hhdm()` plumbing, no per-call hint juggling.
- **alloc_pages gives TRUE physical contiguous pages.** It calls Josh's buddy
  allocator `pmm_alloc_pages(order)`, which returns a page-aligned, physically
  contiguous block. The arena's physical is therefore known directly, and its
  virtual is just `phys + g_hhdm_offset`. So there is NO kernel-slide /
  static-arena / kernel-image-vs-HHDM alias gymnastics — the one bring-up bug
  the MINIX port had to carefully avoid simply cannot occur here.

The net result: `osif.c` is direct (every hook real, no slide math) and
`adapter.c` builds the tag list straight into a single PMM-backed arena.

## Tags produced

| tag         | source                       | notes                                   |
|-------------|------------------------------|-----------------------------------------|
| HHDM        | Limine HHDM response         | mandatory — drives all later translation |
| MEMORY_MAP  | Limine memmap                | RAW Limine type → BBP_MEM_*, R/W attrs   |
| FRAMEBUFFER | Limine framebuffer[0]        | optional (omitted if Limine gave none)   |
| SMP         | Limine SMP response          | Josh is MULTICORE — the MINIX port never emitted this tag; it is the clearest Josh-specific addition |
| CMDLINE     | Limine kernel cmdline        | optional, out-of-line string + string_crc |

## Flow

    Limine -> josh entry -> bbp_josh_init()        (josh_glue.c: reads limine_get_*)
                              fills bbp_josh_bootinfo
                         -> bbp_josh_adapter()      (adapter.c: builds bbp_info + tags)
                         -> bbp_init_win()          (core parser validates + bounds the walk)
                         -> Josh consumes tags via bbp_find_tag() / bbp_for_each_tag()

On success `bbp_josh_init()` logs one proof line:

    [BBP] josh adapter ok, N tags, hhdm=0x... (CRC-sealed, parser-validated)

## Deliverables (in THIS directory only)

1. osif.c / osif.h — `struct bbp_osif` for Josh-Bear:
   - phys_to_virt: `phys + g_hhdm_offset` (Josh's single higher-half direct map)
   - log:          `kserial_puts` (Josh COM1 console, already initialized)
   - panic:        `kpanic` (Josh's noreturn panic)
   - alloc_pages:  `pmm_alloc_pages(order)` (buddy allocator → TRUE phys, contiguous)
   - now_ns:       rdtsc at a nominal 1 GHz (boot metrics only; TECH DEBT)

2. adapter.c — `bbp_josh_adapter()`: Limine snapshot → HHDM / MEMORY_MAP /
   FRAMEBUFFER / SMP / CMDLINE tags into one PMM arena, sealed via
   `bbp_builder_finalize`, validated via `bbp_init_win`.

3. josh_glue.c — the ONE file coupled to Josh's headers: reads the
   `limine_get_*()` accessors, fills `struct bbp_josh_bootinfo`, calls the
   adapter. Lives only in the Josh tree (needs `<kernel/boot/limine.h>`); the
   standalone harness uses synthetic data instead.

4. integration.md — exact Josh paths/flags: where to add `-Iinclude`, which .c
   files to add to Josh's build, and where to call `bbp_josh_init()` in
   `kernel/boot/lisabeth_kernel.c`.

5. CONFORMANCE.md — filled-in conformance report (see ../CONFORMANCE.template.md).

6. test/ — a standalone hosted harness (test/harness.c + test/run.sh) that feeds
   synthetic Limine data to the SHIPPED osif.c + adapter.c and proves the parser
   validates all 5 tags. The REAL Josh-boot serial proof is captured separately.

## Hard rules

- Touch ONLY files under ports/josh/. Never edit include/bbp/*, kernel/*,
  bootloader/* — the core is audited and ABI-frozen.
- Pin the core commit you built against in CONFORMANCE.md. **Pinned: ae5d3e2.**
- Every out-of-line pointer you emit (cmdline, etc.) MUST carry its *_crc, and
  the Josh consumer MUST call `bbp_verify_blob` before trusting it (ADR-0006).
- Honor SPEC §10.1(b): the adapter runs inside Josh which is already on its own
  higher-half page tables, so tag pointers are TRUE physicals (the PMM arena)
  and the parser is seeded with the HHDM offset via `bbp_init_win`. Do not
  assume identity.
- Report results in CONFORMANCE.md + test/ logs. Do not claim it works on real
  Josh without a serial log proving the parser validated on real/QEMU Josh.
