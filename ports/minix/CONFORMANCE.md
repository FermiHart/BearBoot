# BBP Port Conformance Report — MINIX x86_64 (limine-boot)

## Identity
- OS / branch:            MINIX x86_64, branch `limine-boot` (/Users/admin/OS/minix)
- Port version:           0.1.0
- Historical evidence core revision: b2ea55e ("BBP v1.1 — hardened, audited,
                          publishable"), recorded from a working tree then at
                          742906a. This describes the archived machine/OS logs,
                          not the current BearBoot core implementation.
- Current hosted/scaffold revision: the BearBoot checkout at gate execution;
                          release metadata records that exact source revision.
                          The wire ABI remains v1.1.
- BBP protocol version:   1.1
- Toolchain:              x86_64-elf-gcc 16.1.0, x86_64-elf-ld; xorriso 1.5.8;
                          limine (deploy); qemu-system-x86_64 11.0.0
- Date / author:          2026-06-02 · F E R M I ∞ H A R T <contact@fermihart.com>

## OSIF hooks implemented
| hook          | status   | notes |
|---------------|----------|-------|
| phys_to_virt  | done     | phys + HHDM offset (the offset MINIX gets from Limine, set via bbp_minix_set_hhdm). NULL for phys 0. |
| log           | done     | raw COM1 0x3F8 polled, same register sequence as limine_kinfo.c serial. |
| panic         | done     | logs + optional MINIX panic() hook (bbp_minix_set_panic_hook), else halt. noreturn. |
| alloc_pages   | done     | 8B-aligned bump over a 64 KiB static arena; *out_phys via the kernel slide. |
| now_ns        | done     | rdtsc at a nominal 1 GHz (1 tick==1 ns). Honest approx; TECH DEBT: calibrate. |

## Adapter / boot path
- Mode: [x] Limine->BBP adapter   [ ] native BBP boot
- HHDM offset source:  Limine HHDM response (`hhdm_request.response->offset`,
  == `limine_hhdm_offset` in limine_kinfo.c). Verified at runtime in the harness.
- parser initializer used:  `bbp_init_bounded(out, info_hhdm, hhdm_offset,
  tagbase_phys, tag_arena_size)` —
  SPEC §10.1(b): adapter runs inside the already-higher-half kernel, so tag
  pointers are TRUE physicals and the parser is seeded with the HHDM offset.
  The INFO is passed as its HHDM-virtual alias.

### Critical correctness note (the classic BBP bring-up bug, avoided)
Two virtual aliases exist for the scratch arena's physical pages:
  1. KERNEL-IMAGE alias (where the arena symbol resolves): phys = virt - kvirt_base + kphys_base.
  2. HHDM alias (phys + hhdm_offset): how the parser dereferences tag pointers.
`alloc_pages`/the builder use alias 1 (kernel slide, from BBP_TAG_KERNEL_ADDRESS)
to stamp TRUE physicals into tags; `phys_to_virt`/`bbp_init_bounded` use alias 2 to
read them back. Conflating the two is the standard cause of a faulting tag walk;
the port keeps them distinct (see osif.c alias note + adapter.c).

## Tags produced (adapter mode) / consumed
| tag              | produced | consumed | out-of-line *_crc set? |
|------------------|----------|----------|------------------------|
| MEMORY_MAP       | yes      | yes (harness) | n/a (RAW Limine type -> BBP_MEM_*, R/W attrs) |
| HHDM             | yes      | yes      | n/a |
| KERNEL_ADDRESS   | yes      | yes      | n/a |
| ACPI             | yes (if RSDP) | yes  | n/a (rsdp_address only; xsdt/version left 0) |
| FRAMEBUFFER      | optional | yes (if present) | EDID not provided (edid_crc=0) |
| CMDLINE          | yes (if cmdline) | yes | string_crc — SET via bbp_crc64 over arena copy |

## Validation evidence
- [x] `make scaffold-check` passes (compiles+links against the core in the
      current checkout)
      => "MINIX port scaffold compiles + links against frozen BBP core."
- [x] `make test-hosted` is the current reproducible host-process gate. It uses a
      synthetic nonzero-HHDM snapshot, validates seven tags and cmdline tamper
      rejection, and explicitly makes no MINIX boot claim.
- [x] Historical core self-test was green at the recorded revision (`make test`)
      => "PASSED (0 failures)"
- [x] Adapter machine harness built into a bootable higher-half Limine ISO with the
      shipped osif.c + adapter.c objects:
        - x86_64-elf cross-compile of boot.S/harness.c/osif.c/adapter.c +
          core bbp_kernel.c/bbp_build.c: all OK, zero warnings (-Wall -Wextra).
        - higher-half link: Entry 0xffffffff80001000, .limine_requests section
          present, ZERO undefined symbols; bbp_minix_adapter / bbp_minix_osif /
          bbp_init_ex / bbp_verify_blob all linked.
        - Limine BIOS-CD ISO built + `limine bios-install` OK (3.8M harness.iso).
- [x] Historical full MINIX OS record in `test/serial-all6-consumers.log`
      showing the parser validated on Limine boot data in the external MINIX
      kernel under QEMU. Captured lines:
        [limine] BBP adapter: ok
        |   B E A R   B O O T   P R O T O C O L   v1.1           |
        [*] Limine -> BBP adapter ......... ACTIVE
        [*] handoff integrity ............. CRC-64/XZ verified
        [*] HHDM reachability (SPEC 10.1b)  ok, offset=0xffff800000000000
        [*] tags validated ................ 6
        MINIX x86_64 now sees hardware through BBP.
      The kernel then continues to the interactive JASH shell.
- [x] bbp_init_ex returned BBP_OK on the historical external OS boot data (the "BBP adapter: ok" line
      is bbp_strstatus(st) with st==BBP_OK; 6 tags CRC-validated by the parser:
      HHDM, MEMORY_MAP, KERNEL_ADDRESS, SMP, ACPI, CMDLINE. The SMP tag carries
      the Limine MP topology (cpu_count/bsp/LAPIC ids); a uniprocessor boot still
      emits a valid 1-CPU tag, so the count is 6 with or without -smp).
- [x] bbp_verify_blob called on every out-of-line payload consumed — the
      harness calls it on the CMDLINE before reading the string (the
      standalone test/harness.c path; the MINIX glue passes cmdline through and
      a consumer verifies it per ../integration.md §4).

### Evidence scope / substrate / replay
| artifact / command | proof scope | substrate | replay | core revision |
|--------------------|-------------|-----------|--------|---------------|
| `make test-hosted` | hosted adapter | host process, synthetic snapshot | reproducible from current checkout | current checkout |
| `test/serial.log` | adapter machine harness (7 tags; loads `harness.elf`) | QEMU + Limine machine harness | recorded only; not replayed by hosted gate | b2ea55e report provenance |
| `test/serial-all6-consumers.log` | full MINIX OS boot (6 tags; loads `kernel.elf` and MINIX modules) | QEMU + Limine + external MINIX tree | recorded only; external tree not archived here | b2ea55e report provenance |

Neither checked machine log proves an external MINIX boot at the current
BearBoot source revision. `test/serial.log` must not be cited as the full OS log.

### Integration path (how the recorded QEMU boot evidence was produced)
The adapter is wired into the MINIX boot via a thin glue TU that keeps all
bbp/* includes out of the -nostdinc MINIX translation units:
  - BearBoot/ports/minix/minix_glue.c — owns the BBP includes, exposes
    bbp_minix_boot_glue() with a plain scalar+void* signature, prints the BBP
    banner on success.
  - minix/kernel/arch/x86_64/limine_kinfo.c — 1 extern + 1 call before kmain().
  - minix/kernel/scripts/build_limine_full.sh — -I<BearBoot>/include + the 5
    BBP objects added to LIBSRCS.
Verified: kernel.elf links bbp_minix_boot_glue / bbp_minix_adapter /
bbp_init_ex / bbp_minix_osif; all BBP sources compiled under the external kernel
CFLAGS (-Werror -nostdinc + -idirafter destdir).

## Deviations / known gaps (honest accounting)
1. Historical full-OS evidence is `test/serial-all6-consumers.log`, with six
   CRC-validated tags and the BBP banner. `test/serial.log` is a distinct
   seven-tag adapter machine harness. Neither external run is currently replayed.
2. now_ns uses a nominal 1 GHz TSC assumption (relative metrics only).
3. ACPI tag carries rsdp_address only (no RSDP/RSDT parse).
4. Framebuffer EDID not forwarded (edid_crc=0); width/height/pitch/format are.
5. Scratch arena is a 64 KiB static buffer (v1); swap to the kernel PMM later.
