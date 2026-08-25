# BBP Port Conformance Report — TEMPLATE

Copy to your port dir as CONFORMANCE.md and fill every field. Do not collapse a
hosted process, machine harness, emulator OS boot, and physical-machine boot into
one claim. A reported but unarchived run must be labeled as such, not "recorded."

## Identity
- OS / branch:            <e.g. MINIX x86_64, limine-boot>
- Port version:           <e.g. 0.1.0>
- Historical evidence core revision: <commit recorded by each archived run>
- Current hosted/scaffold revision:   <current checkout; record exact commit in release metadata>
- BBP protocol version:   1.1
- Toolchain:              <e.g. x86_64-elf-gcc 16.1.0>
- Date / author:

## OSIF hooks implemented
| hook          | status (done/NULL) | notes |
|---------------|--------------------|-------|
| phys_to_virt  |                    |       |
| log           |                    |       |
| panic         |                    |       |
| alloc_pages   |                    |       |
| now_ns        |                    |       |

## Adapter / boot path
- Mode: [ ] Limine->BBP adapter   [ ] native BBP boot (.bbp_hdr + stamp)
- HHDM offset source:             <e.g. Limine HHDM response = 0x...>
- parser initializer used:         <prefer bbp_init_bounded; include hint/span>

## Tags produced (adapter mode) / consumed
| tag              | produced | consumed | out-of-line *_crc set? |
|------------------|----------|----------|------------------------|
| MEMORY_MAP       |          |          | n/a                    |
| HHDM             |          |          | n/a                    |
| KERNEL_ADDRESS   |          |          | n/a                    |
| ACPI             |          |          | n/a                    |
| FRAMEBUFFER      |          |          | EDID                   |
| CMDLINE          |          |          | string_crc             |
| SECURITY         |          |          | measurements/entropy   |

## Validation evidence (REQUIRED — no green claims without these)
- [ ] `make scaffold-check` passes against the core in the current checkout
- [ ] Current hosted gate passes; state clearly that it is not a machine/OS boot
- [ ] Every archived record has scope, substrate, replay status, core revision,
      and repository-relative artifact path:

| artifact / command | proof scope | substrate | replay | core revision |
|--------------------|-------------|-----------|--------|---------------|
| `<path or command>` | `<hosted-adapter / adapter-machine-harness / full-os-boot / physical-os-boot>` | `<host process / QEMU / QEMU+KVM / physical model>` | `<reproducible / recorded-only / unarchived-not-replayable>` | `<commit>` |

- [ ] Machine/OS log shows `bbp_init` returned BBP_OK on that substrate
- [ ] bbp_verify_blob called on every out-of-line payload consumed
- [ ] Physical hardware is claimed only when the artifact identifies physical
      hardware; KVM acceleration is still emulator evidence

## Deviations / known gaps
<list anything not done, with why. Honesty here is the whole point.>
