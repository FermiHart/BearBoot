# BBP Port Conformance Report — TEMPLATE

Copy to your port dir as CONFORMANCE.md and fill every field. A port is not
"done" until this is complete and backed by a serial log in test/.

## Identity
- OS / branch:            <e.g. MINIX x86_64, limine-boot>
- Port version:           <e.g. 0.1.0>
- BBP core commit pinned: <git rev of include/bbp + kernel/ + bootloader/>
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
- bbp_init / bbp_init_ex used:     <which, and the hint value>

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
- [ ] `make scaffold-check` passes (compiles against frozen core)
- [ ] Core self-test still green against the pinned commit (`make test` in root)
- [ ] Real/QEMU MINIX serial log in test/ showing the parser validated:
      paste the line(s), e.g. "bbp: minix adapter ok, N tags, hhdm=0x..."
- [ ] bbp_init returned BBP_OK on real boot data
- [ ] bbp_verify_blob called on every out-of-line payload consumed

## Deviations / known gaps
<list anything not done, with why. Honesty here is the whole point.>
