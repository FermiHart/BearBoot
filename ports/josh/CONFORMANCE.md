# BBP Port Conformance Report — Josh-Bear x86_64 ("lisabeth", limine-boot)

## Identity
- OS / branch:            Josh-Bear "lisabeth" x86_64, Limine boot ($JOSH)
- Port version:           1.0.0
- Historical external-OS core revision: ae5d3e2 ("docs: add ADR-0009 (walk
                          window), SPEC §10.3, changelog for v1.1 hardening").
                          This identifies `test/serial.log`, not the current core.
- Current hosted/scaffold revision: the BearBoot checkout at gate execution;
                          release metadata records that exact source revision.
- BBP protocol version:   1.1
- Toolchain:              hosted harness: Apple clang 17.0.0 (cc).
                          scaffold-check: x86_64-elf-gcc 16.1.0.
- Date / author:          2026-06-05 · F E R M I ∞ H A R T <contact@fermihart.com>

## OSIF hooks implemented
| hook          | status (done/NULL) | notes |
|---------------|--------------------|-------|
| phys_to_virt  | done               | `phys + g_hhdm_offset` — Josh's single higher-half direct map (same global the rest of the kernel uses). NULL for phys 0. No alias dance. |
| log           | done               | `kserial_puts` — Josh COM1 console, already initialized when the adapter runs. |
| panic         | done               | `kpanic` — Josh's noreturn panic; cli;hlt loop after to satisfy noreturn. |
| alloc_pages   | done               | `pmm_alloc_pages(order)` — Josh buddy allocator. TRUE physical, page-aligned, CONTIGUOUS; *out_phys is that physical directly, returned virtual is phys+hhdm. No kernel-slide math. |
| now_ns        | done               | rdtsc at a nominal 1 GHz (1 tick==1 ns). Honest boot-metric approximation only. TECH DEBT: calibrate against Josh's TSC freq. |

## Adapter / boot path
- Mode: [x] Limine->BBP adapter   [ ] native BBP boot (.bbp_hdr + stamp)
- HHDM offset source:             Limine HHDM response via `limine_get_hhdm_offset()`
                                  (== Josh's `g_hhdm_offset`). Mandatory; the adapter
                                  refuses to build if it is 0.
- parser initializer used:        `bbp_init_bounded(out, info, hhdm_offset,
                                  tagbase_phys, tag_arena_bytes)` — SPEC §10.1(b): the
                                  adapter runs on Josh's own higher-half page tables,
                                  so tag pointers are TRUE physicals (PMM arena) and
                                  the parser is seeded with the HHDM offset; the walk
                                  is bounded to the arena window (ADR-0009).

### Correctness note (why no MINIX-style alias bug is possible here)
The MINIX port had to reconcile two virtual aliases (kernel-image slide vs HHDM)
because it had no allocator that early and used a static arena addressed through
the kernel image. Josh allocates the arena from the PMM buddy allocator AFTER the
VMM is up, so `alloc_pages` returns the TRUE physical AND the HHDM-virtual base of
the same contiguous block. The adapter writes tags via the HHDM alias and stamps
those same physicals into the tags; the parser reads them back through the SAME
`phys + g_hhdm_offset` map. One map, no slide, so the classic faulting-tag-walk
bring-up bug cannot occur.

## Tags produced (adapter mode) / consumed
| tag              | produced | consumed | out-of-line *_crc set? |
|------------------|----------|----------|------------------------|
| MEMORY_MAP       | yes      | yes (harness) | n/a (RAW Limine type -> BBP_MEM_*, R/W attrs) |
| HHDM             | yes      | yes      | n/a |
| KERNEL_ADDRESS   | no       | n/a      | n/a (not needed — single direct map, no slide) |
| ACPI             | no       | n/a      | n/a (out of scope for v1) |
| FRAMEBUFFER      | optional | yes (if present) | EDID not forwarded (edid_crc=0); w/h/pitch/format set |
| SMP              | yes      | yes (harness) | n/a — **Josh-specific: the MINIX port never emitted this tag** |
| CMDLINE          | optional | yes (if present) | string_crc — SET via bbp_crc64 over the arena copy |
| SECURITY         | optional | **yes (real boot)** | entropy_crc — SET; carries 48 B boot entropy (root-of-trust seed). Josh bbp_verify_blob()s it, then seeds its CSPRNG. TPM/measured-boot fields zeroed in v1. |

## Validation evidence (REQUIRED — no green claims without these)
- [x] `make scaffold-check` passes (compiles+links against the core in the
      current checkout)
      => "Josh-Bear port scaffold compiles + links against frozen BBP core."
      (x86_64-elf-gcc 16.1.0, -ffreestanding -Wall -Wextra -Werror, zero warnings;
      osif.c + adapter.c + bbp_kernel.c + bbp_build.c link into one relocatable
      object — every symbol the port uses exists in the current core while the
      wire ABI remains frozen.)
- [x] `make` / `make test` passes the hosted harness (synthetic Limine data fed to
      the shipped osif.c + adapter.c, validated through the public parser API).
      The checked output is `test/run.log`:
        bbp_josh_adapter -> ok
          tag HHDM         : present
          tag MEMORY_MAP   : present
          tag FRAMEBUFFER  : present
          tag SMP          : present
          tag CMDLINE      : present
          tag SECURITY     : present
          memmap entries: 5 (type[0]=1 expect USABLE=1)   (memmap decoded)
          smp cpu_count=4 bsp_id=0                          (SMP: 4 CPUs decoded)
          cmdline verify_blob -> ok                         (CMDLINE CRC verified)
        total tags walked: 6
        RESULT: PASS
- [x] bbp_init_bounded returned BBP_OK on the hosted harness snapshot (the
      "bbp_josh_adapter -> ok" line is bbp_strstatus(st) with st==BBP_OK; the 6
      tags are CRC-validated by the parser, walked via bbp_for_each_tag).
- [x] bbp_verify_blob called on the out-of-line CMDLINE before reading it
      (harness "cmdline verify_blob -> ok"), per ADR-0006.
- [x] Historical external Josh/QEMU serial record showing the parser validated.
      `bbp_josh_init()` is wired into `kernel/boot/lisabeth_kernel.c` right after
      `heap_init` per ../integration.md §4. Captured proof (test/serial.log):
        [BBP] josh adapter ok, 0x5 tags, hhdm=0xffff800000000000 (CRC-sealed, parser-validated)
        [BBP] boot entropy: 0x30 bytes via rdrand, CRC ok (root-of-trust seed)
        [NET] crypto: CSPRNG seeded from BBP root-of-trust entropy
      5 tags = HHDM + MEMORY_MAP + FRAMEBUFFER + SMP + SECURITY (count is hex via
      Josh's kserial_puthex; no CMDLINE in the external OS record — see gap 4). Josh VERIFIES
      the SECURITY entropy blob (bbp_verify_blob) and seeds its CSPRNG from it —
      BBP in the read path. hhdm is Limine's canonical higher-half base.

### Evidence scope / substrate / replay
| artifact / command | proof scope | substrate | replay | core revision |
|--------------------|-------------|-----------|--------|---------------|
| `make test` | hosted adapter (6 tags) | host process, synthetic Limine data | reproducible from current checkout | current checkout |
| `test/run.log` | archived hosted adapter output (6 tags) | host process, synthetic Limine data | recorded hosted output; current command is separately replayable | ae5d3e2 report provenance |
| `test/serial.log` | full Josh OS boot (5 tags) | QEMU + Limine + external Josh tree | recorded only; external tree not archived here | ae5d3e2 |

The hosted six-tag output and external five-tag record are different proofs and
must not be cited interchangeably. The archived OS record does not prove a Josh
boot at the current BearBoot source revision.

## Deviations / known gaps (honest accounting)
1. Historical Josh-boot serial record: `test/serial.log`. The hosted
   harness proves osif.c + adapter.c against the current checkout on synthetic Limine
   data (6 tags incl. CMDLINE and SECURITY); the live Josh boot shows the adapter validating
   5 real Limine-derived tags (no CMDLINE — Josh has no Limine command line).
2. now_ns uses a nominal 1 GHz TSC assumption (relative boot metrics only).
3. No KERNEL_ADDRESS / ACPI tags in v1 — out of scope. KERNEL_ADDRESS is
   unnecessary because the single direct map needs no slide reconciliation.
   SECURITY is now produced (entropy only; TPM/measured-boot still out of scope).
4. No CMDLINE in the external OS record (Josh boots with no Limine kernel command line in v1);
   the tag + string_crc path is exercised by the harness and ready for when a
   cmdline is added.
5. Framebuffer EDID not forwarded (edid_crc=0); width/height/pitch/format are.
6. The arena is a single 64 KiB PMM block (BBP_JOSH_ARENA_BYTES), never freed.
