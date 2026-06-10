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
- [x] In-kernel QEMU boot log — DONE. The call site `bbp_linux01_init()` is
      wired into init/main.c (after hd_init()) in the linux-0.01-modern tree, and
      the kernel boots headless under QEMU to the interactive shell with:
        [bbp] linux-0.01 adapter: ok, 3 tags, hhdm=0x0
        Partition table ok. / ... / linux 0.01 — interactive shell
      The adapter is additive and non-fatal: the kernel reaches userspace
      normally with BBP validation running inside it.

## Notes from the in-kernel bring-up
- A latent pre-existing bug surfaced during wiring (NOT a BBP defect): the 1991
  kernel/vsprintf.c is miscompiled by modern GCC at -O2 in the `%s` case — a
  non-empty %s renders garbage (the va_arg(char*) is fetched off by a slot),
  while %x/%c/%d are fine. The original boot path only ever passed empty strings
  to %s (hd.c "Partition table%s"), so it went unseen until the adapter printed
  a real status string. Same heisenbug class the project already documents for
  fs/buffer.c and fs/bitmap.c. Fixed in the kernel Makefile by compiling
  kernel/vsprintf.o at -O1 (root-caused via -O0/-O1 bisection + monitor pmemsave
  confirming the table/pointer were correct; the corruption was purely in the
  -O2 codegen). The BBP adapter itself always returned BBP_OK correctly.

## Deviations / known gaps
- bbp_verify_blob is NOT exercised: the port produces no out-of-line payloads
  (no CMDLINE/SECURITY/EDID), so there is nothing to verify. This is correct,
  not a gap — the 3 tags are fully self-contained.
- The in-kernel integration is COMPLETE and booted (see evidence above). The
  hosted rig and the real kernel boot agree: same adapter code, same RAM-model
  field shape, same `adapter ok` verdict.
- now_ns / arena are documented tech debt (see integration.md §6), not defects:
  honest approximations with a clear upgrade path and the binding seam in place.

— F E R M I ∞ H A R T  <contact@fermihart.com>
