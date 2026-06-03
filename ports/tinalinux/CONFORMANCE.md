# BBP Port Conformance Report — TinaLinux x86_64 (native Linux boot)

## Identity
- OS / branch:            TinaLinux (Linux 6.12 "Baby Opossum Posse" derivative),
                          tree /home/alf/OS/TinaLinux, kernel build #122.
- Port version:           1.0.0
- BBP core commit pinned: BBP v1.1 (hardened/audited). The vendored core files
                          arch/x86/bbp/{include/bbp/*, bbp_kernel.c, bbp_build.c}
                          are BYTE-IDENTICAL to the canonical BearBoot core
                          (ABI-frozen — verified by diff against
                          BearBoot/{include,kernel,bootloader}).
- BBP protocol version:   1.1
- Toolchain:              host gcc (kernel build, -nostdinc -ffreestanding for
                          the freestanding BBP TUs via compat shim);
                          qemu-system-x86_64 with -enable-kvm.
- Date / author:          2026-06-02 · F E R M I ∞ H A R T <contact@fermihart.com>

## What makes this a NATIVE port (NOT a Limine adapter)
The MINIX port is a Limine->BBP adapter: it translates Limine response structs.
TinaLinux is NOT booted by Limine — it is booted by the native Linux x86_64 path
(EFI stub / BIOS -> boot_params). So this port sources its boot data from the
REAL Linux globals, and was written from scratch as a genuine OSIF:

| OSIF concern  | Linux-native source                                  |
|---------------|------------------------------------------------------|
| HHDM offset   | `page_offset_base`  (the direct map; __va == phys+off)|
| memory map    | `e820_table`        (firmware E820 map)              |
| kernel slide  | `phys_base` / `_text`                                |
| ACPI RSDP     | `acpi_os_get_root_pointer()`                         |
| cmdline       | `saved_command_line`                                 |
| log           | `printk` (real)                                      |
| panic         | `panic()` (real)                                     |
| alloc         | `__get_free_pages()` (real, direct-map)              |
| now_ns        | `ktime_get_ns()` (real)                              |

## OSIF hooks implemented (binding seam: __weak fallback / strong kernel override)
osif.c declares each primitive as a __weak freestanding fallback; the kernel
glue (tina_bbp.c) and the hosted harness each install a STRONG override. Same
osif.o, two worlds, chosen at link time — zero #ifdef in the core or port.

| hook          | freestanding fallback | strong kernel override     |
|---------------|-----------------------|----------------------------|
| log           | COM1 0x3F8 polled      | printk(KERN_INFO "bbp: …") |
| panic         | cli;hlt               | panic("bbp: %s")           |
| alloc_pages   | 64 KiB static arena   | __get_free_pages(GFP_KERNEL\|__GFP_ZERO, order 4) |
| now_ns        | rdtsc (nominal 1 GHz) | ktime_get_ns()             |
| phys_to_virt  | phys + hhdm (arith)   | (same; == __va)            |

## Why the classic BBP dual-alias bug CANNOT occur here (port advantage)
The MINIX port must juggle two virtual aliases for its scratch arena (kernel-
image alias vs HHDM alias) because the arena is a kernel SYMBOL; conflating them
is the standard BBP bring-up fault. The TinaLinux glue allocates the arena with
__get_free_pages, so it lives in the Linux DIRECT MAP. There:

    arena_phys == __pa(arena) == arena_virt - page_offset_base
    phys_to_virt(p) == p + page_offset_base == __va(p)

are the SAME linear relation. There is exactly ONE alias; the kernel-image-vs-
HHDM hazard is structurally absent. (osif.c + adapter.c dual-alias notes.)

## Adapter / boot path
- Mode: [x] native Linux->BBP adapter   [ ] Limine adapter   [ ] native BBP boot
- HHDM offset source: `page_offset_base`. Verified at runtime — the boot log
  shows hhdm=0xffff91e140000000 (a real KASLR'd direct-map base, NOT identity).
- bbp_init / bbp_init_ex used: `bbp_init_ex(out, info_hhdm, page_offset_base)` —
  SPEC §10.1(b): the adapter runs inside the already-higher-half kernel, so tag
  pointers are TRUE physicals (__pa of the direct-map arena) and the parser is
  seeded with the HHDM offset. The INFO is passed as its __va alias.
- Call site: a `late_initcall(bbp_tina_init)` in tina_bbp.c. Registered in
  vmlinux as __initcall__kmod_bbp__..._bbp_tina_init7 (level 7) — proven present
  in System.map; it runs every boot.

## Tags produced (adapter mode) / consumed
| tag              | produced | consumed | out-of-line *_crc set? |
|------------------|----------|----------|------------------------|
| HHDM             | yes      | yes      | n/a |
| MEMORY_MAP       | yes      | yes      | n/a (RAW E820_TYPE_* -> BBP_MEM_*, R/W attrs) |
| KERNEL_ADDRESS   | yes      | yes      | n/a (phys_base / _text) |
| ACPI             | yes (if RSDP) | yes | n/a (rsdp_address only; xsdt/version left 0) |
| CMDLINE          | yes (if cmdline) | yes | string_crc — SET via bbp_crc64 over arena copy |

Boot log: "tinalinux adapter ok, 5 tags" => HHDM + MEMORY_MAP + KERNEL_ADDRESS +
ACPI + CMDLINE, each CRC-64/XZ validated by the frozen parser.

## Validation evidence
- [x] `make scaffold-check` passes — port compiles+links against the FROZEN core
      under -nostdinc -ffreestanding (kernel-like flags) via the compat shim:
      "TinaLinux port scaffold compiles + links against frozen BBP core."
- [x] `make test` (hosted rig) PASS — the SHIPPED osif.c + adapter.c, driven by
      representative native e820 data through the frozen parser:
      "bbp: tinalinux adapter ok, 5 tags … RESULT: PASS". Includes a
      bbp_verify_blob() of the out-of-line cmdline (ADR-0006).
- [x] Core self-test (root `make test`) still green: "PASSED (0 failures)" — the
      ABI-frozen core was NOT modified by this port.
- [x] In-tree kernel compile of all 5 BBP objects: zero warnings, zero errors
      (CC bbp_kernel/bbp_build/osif/adapter/tina_bbp, AR built-in.a).
- [x] vmlinux links with the BBP objects; System.map carries bbp_tina_adapter /
      bbp_init_ex / bbp_tina_osif / bbp_find_tag / bbp_tina_get_rsdp and the
      registered late_initcall.
- [x] REAL boot evidence in test/serial.log (headless QEMU+KVM, embedded
      initramfs, kernel #122). Captured lines:
        bbp: native Linux -> BBP adapter: ok
        |   B E A R   B O O T   P R O T O C O L   v1.1           |
        [*] native Linux -> BBP adapter .... ACTIVE
        [*] handoff integrity ............. CRC-64/XZ verified
        [*] source tables ................. e820 + ACPI + cmdline
        bbp: tinalinux adapter ok, 5 tags, hhdm=0xffff91e140000000
      The firmware tables that fed it are in the same log (BIOS-e820: …, ACPI:
      RSDP 0x...F5290). The kernel then continued to the interactive jash prompt
      (fermi@fermihart:/ $) — the adapter is ADDITIVE and NON-FATAL.
- [x] bbp_init_ex returned BBP_OK on real boot data (the "adapter: ok" line is
      bbp_strstatus(st) with st==BBP_OK; 5 tags CRC-validated by the parser).
- [x] hhdm in the live log is a real KASLR'd page_offset_base (0xffff91e1…),
      proving phys_to_virt is the kernel's actual direct map, not identity.

## Build wiring (how to reproduce)
- Vendored at kernel/arch/x86/bbp/ (flat layout): core + port + glue + Kbuild +
  Kconfig + port/compat/{stdint,stddef}.h.
- arch/x86/Kbuild:  `obj-$(CONFIG_BBP_TINALINUX) += bbp/`
- arch/x86/Kconfig: `source "arch/x86/bbp/Kconfig"`
- CONFIG_BBP_TINALINUX=y (default y; depends on X86_64 && ACPI).
- Pre-existing config gaps fixed to get a bootable vmlinux (UNRELATED to BBP, the
  build dir had never linked): fs/tinafs/Kconfig now `select BUFFER_HEAD` +
  `select LEGACY_DIRECT_IO` (TinaFS uses fs/buffer.c), and CONFIG_TINAFS=y (the
  permanent TinaLinux config the NYX entropy pool hard-requires for BLAKE3).

## Deviations / known gaps (honest accounting)
1. now_ns strong override is ktime_get_ns() (real). The __weak fallback assumes
   a nominal 1 GHz TSC — used ONLY in the freestanding harness, never in-kernel.
2. ACPI tag carries rsdp_address only (xsdt_address/acpi_version/oem_id left 0);
   the adapter does not parse the RSDP/RSDT. Populate if a consumer needs it.
3. The arena is 64 KiB (__get_free_pages order 4). For ~40 e820 entries the tag
   list is a few KiB; raise BBP_TINA_ARENA_ORDER if many large tags are added.
4. The port is ADDITIVE: it does not (yet) replace TinaLinux's native e820/ACPI
   consumers — it provides a parallel CRC-sealed view via bbp_find_tag(). A
   follow-up can route the ACPI subsystem through bbp_tina_get_rsdp() (a
   CRC-verified RSDP) — the accessor is shipped and ready.
