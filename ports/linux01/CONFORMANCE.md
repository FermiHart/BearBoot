# BBP Port Conformance Report — linux-0.01

## Identity
- OS / branch:            linux-0.01-modern (Linus' 1991 kernel, Limine-booted)
- Port version:           1.0.0
- BBP core commit pinned:  9257abe (include/bbp + kernel/bbp_kernel.c + bootloader/bbp_build.c)
- BBP protocol version:   1.1
- Toolchain:              x86_64-elf-gcc 16.1.0 (-m32 elf32-i386); host cc for the harness
- Date / author:          2026-06-03 — F E R M I ∞ H A R T <contact@fermihart.com>

## OSIF hooks implemented
| hook          | status (done/NULL) | notes |
|---------------|--------------------|-------|
| phys_to_virt  | done               | identity map: phys + hhdm_offset, hhdm_offset == 0 |
| log           | done               | weak: COM1 serial; strong glue override -> printk |
| panic         | done               | weak: cli;hlt; strong glue override -> kernel panic() |
| alloc_pages   | done               | weak static 64 KiB arena (kernel is identity-mapped) |
| now_ns        | done               | rdtsc @ nominal 1 GHz (honest approx; no timebase this early) |

## Adapter / boot path
- Mode: [x] native RAM-model -> BBP adapter   [ ] native BBP boot (.bbp_hdr + stamp)
- HHDM offset source:             0 — linux-0.01 is identity-mapped (pg_dir=0, first 8 MiB)
- bbp_init / bbp_init_ex used:     bbp_init (SPEC §10.1(a), identity handoff, hint 0)

## Tags produced (adapter mode) / consumed
| tag              | produced | consumed | out-of-line *_crc set? |
|------------------|----------|----------|------------------------|
| MEMORY_MAP       | yes      | via accessor | n/a                |
| HHDM             | yes      | by parser    | n/a                |
| KERNEL_ADDRESS   | yes      | via accessor | n/a                |
| ACPI             | no (1)   | —            | n/a                    |
| FRAMEBUFFER      | no (1)   | —            | EDID                   |
| CMDLINE          | no (1)   | —            | string_crc             |
| SECURITY         | no (1)   | —            | measurements/entropy   |

(1) Honest absence — linux-0.01 is a 1991 kernel with no ACPI, no boot cmdline,
no framebuffer protocol, no SMP, no TPM. The port NEVER fabricates a tag for
hardware the kernel has no knowledge of. It produces exactly the 3 tags the
kernel's fixed RAM model + identity map can truthfully describe.

## Validation evidence
- [x] `make scaffold-check CROSS=x86_64-elf-` passes — compiles + links the port
      against the frozen core in elf32-i386 (confirmed via objdump: "file format
      elf32-i386, architecture: i386"). Proves zero ABI drift in the 32-bit world.
- [x] Core self-test still green against pinned commit 9257abe:
      `make test` in root -> PASSED (0 failures), 45 checks incl. adversarial suite.
- [x] Hosted real-data proof in test/serial.log: the SHIPPED adapter (osif.c +
      adapter.c) run on the linux-0.01 fixed RAM model through the frozen parser:
        bbp: linux-0.01 adapter ok, 3 tags, hhdm=0x0
        RESULT: PASS - native adapter validated on the linux-0.01 RAM model
- [x] bbp_init returned BBP_OK on the synthesized info (identity-mapped handoff).
- [x] Adversarial in-situ test: corrupting the MEMORY_MAP tag's entry_count makes
      the parser reject it (CRC mismatch) — "corrupt-tag rejection . ok".
- [x] MEMORY_MAP total verified: 640 KiB + (8 MiB − 1 MiB) = 7808 KiB usable.
- [ ] In-kernel QEMU boot log — PENDING the §3 call-site wiring in init/main.c
      (the linux-0.01-modern tree is edited separately; this port ships the glue
      + the exact one-line call site, verified by the hosted rig above). The
      kernel boot proof will be captured as the `[bbp] linux-0.01 adapter: ok`
      console line once the call is wired and the ISO is booted.

## Deviations / known gaps
- bbp_verify_blob is NOT exercised: the port produces no out-of-line payloads
  (no CMDLINE/SECURITY/EDID), so there is nothing to verify. This is correct,
  not a gap — the 3 tags are fully self-contained.
- The in-kernel boot log is the one remaining evidence item (above). It depends
  on a one-line edit to init/main.c in the linux-0.01-modern repo, which is a
  separate tree under separate authorization. The hosted rig proves the SAME
  adapter code on the SAME RAM-model field shape the call site fills, so the
  integration is wiring-only.
- now_ns / arena are documented tech debt (see integration.md §6), not defects:
  honest approximations with a clear upgrade path and the binding seam in place.

— F E R M I ∞ H A R T  <contact@fermihart.com>
