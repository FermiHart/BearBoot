# BBP MINIX integration — exact paths, flags, and call site

This file tells the MINIX maintainer precisely how to wire the Limine->BBP
adapter and scalar glue shipped in `ports/minix/` into the MINIX x86_64
`limine-boot` tree. Nothing here edits the BBP core.

Target tree: `/Users/admin/OS/minix`, branch `limine-boot`.

--------------------------------------------------------------------------
## 0. What the adapter gives MINIX

MINIX already translates Limine responses into a legacy `kinfo_t`
(`minix/kernel/arch/x86_64/limine_kinfo.c`). The BBP adapter is ADDITIVE: it
also synthesizes a CRC-protected BBP tag list from the same Limine responses
and validates it with the BBP defensive parser. MINIX can then consume
hardware data (memory map, HHDM, kernel address, ACPI RSDP, framebuffer,
cmdline) through `bbp_find_tag()` with per-tag CRC integrity and out-of-line
blob verification — without touching the existing boot path.

--------------------------------------------------------------------------
## 1. Files to add to the kernel build

Add these five source files to the kernel compile. `minix_glue.c` is the
`-nostdinc` boundary: the MINIX entry calls it through a plain scalar prototype
and does not include BBP headers.

    /Users/admin/OS/BearBoot/ports/minix/osif.c
    /Users/admin/OS/BearBoot/ports/minix/adapter.c
    /Users/admin/OS/BearBoot/ports/minix/minix_glue.c
    /Users/admin/OS/BearBoot/kernel/bbp_kernel.c
    /Users/admin/OS/BearBoot/bootloader/bbp_build.c

In `minix/kernel/scripts/build_limine_full.sh`, append them to the library
source list (PHASE 1.5, the `LIBSRCS=(...)` array around line 129):

    LIBSRCS=(
        ...
        "/Users/admin/OS/BearBoot/ports/minix/osif.c"
        "/Users/admin/OS/BearBoot/ports/minix/adapter.c"
        "/Users/admin/OS/BearBoot/ports/minix/minix_glue.c"
        "/Users/admin/OS/BearBoot/kernel/bbp_kernel.c"
        "/Users/admin/OS/BearBoot/bootloader/bbp_build.c"
    )

They compile under the existing kernel `CFLAGS` unchanged. The only addition
needed is the BBP include path (next section).

For an in-tree mirror instead of an absolute path, copy `osif.{c,h}`,
`adapter.{c,h}`, and `minix_glue.c` into e.g.
`minix/kernel/arch/x86_64/bbp/` and adjust the two
`#include "../../kernel/bbp_kernel.h"` / `"../../bootloader/bbp_build.h"` lines
in `adapter.c` to point at wherever you vendor the BBP core headers. Keep the
core headers themselves UNMODIFIED (ABI-frozen).

--------------------------------------------------------------------------
## 2. Compiler flags — add the BBP include path

The adapter/osif need `<bbp/bbp.h>`, `<bbp/bbp_crc64.h>`, `<bbp/bbp_osif.h>`
and the core helper headers `bbp_kernel.h` / `bbp_build.h`.

In `build_limine_full.sh`, add ONE include dir to `CFLAGS` (near line 38):

    -I/Users/admin/OS/BearBoot/include

`adapter.c` reaches the two non-`include/` core headers via relative paths
(`../../kernel/bbp_kernel.h`, `../../bootloader/bbp_build.h`) which resolve
from `ports/minix/`. If you vendor the port elsewhere, either preserve that
relative layout or change those two includes.

No linker-script change is required for the adapter path — `.bbp_hdr` /
`KEEP()` is only for the *native* BBP-boot path (a bootloader reading the
kernel's Bear Header), which is NOT what this port does. Limine remains the
bootloader untouched.

--------------------------------------------------------------------------
## 3. Where to call it — the entry sequence

Call site: `minix/kernel/arch/x86_64/limine_kinfo.c`, function
`limine_to_kinfo_and_boot()` (the kernel ELF ENTRY per
`kernel_limine_full.lds:15`). The adapter must run AFTER the HHDM and
kernel-address responses are read (so the slide/HHDM are known) and BEFORE
`kmain()` — the same window where `limine_kinfo.c` already reads everything.

The function already pulls the values the adapter needs into globals:
`limine_hhdm_offset`, `limine_kernel_phys_base`, `limine_kernel_virt_base`,
`limine_rsdp_phys`, the Limine `memmap_request.response`, and (if you add a
framebuffer request) the framebuffer. The integration is a field copy +
one call.

Declare the scalar boundary near the top of `limine_kinfo.c` without including
BBP headers:

```c
extern int bbp_minix_boot_glue(unsigned long long hhdm,
    unsigned long long kphys, unsigned long long kvirt, int have_kaddr,
    unsigned long long rsdp, void **entries, unsigned long long entry_count,
    const char *cmdline, unsigned cpu_count, unsigned bsp_lapic,
    void *lapic_ids, int x2apic);
```

Call it near the end of `limine_to_kinfo_and_boot()`, before `kmain()`, passing
the raw Limine entry-pointer array and the already flattened LAPIC IDs:

```c
(void)bbp_minix_boot_glue(limine_hhdm_offset,
    limine_kernel_phys_base, limine_kernel_virt_base, 1, limine_rsdp_phys,
    (void **)memmap_request.response->entries,
    memmap_request.response->entry_count, param_buf,
    limine_cpu_count, limine_bsp_lapic, limine_lapic_ids, limine_x2apic);
```

The glue bounds the memory map at 256 entries, constructs the neutral bootinfo,
retains the validated context, and keeps failure non-fatal to the legacy MINIX
boot path. Adapt the local SMP variable names to the target tree.

--------------------------------------------------------------------------
## 4. Consuming tags later in the kernel

Anywhere after the adapter ran, with the saved `struct bbp_kctx *k`:

```c
const struct bbp_tag_header *t = bbp_find_tag(k, BBP_TAG_MEMORY_MAP);
if (t) {
    const struct bbp_tag_memory_map *mm = (const void *)t;
    uint32_t n;
    const struct bbp_memory_entry *e =
        bbp_tag_array(t, sizeof(*mm), sizeof(struct bbp_memory_entry),
                      mm->entry_count, &n);   /* clamps n to tag_size */
    for (uint32_t i = 0; i < n; i++) { /* e[i].base, .length, .type ... */ }
}
```

For the ACPI RSDP: `bbp_find_tag(k, BBP_TAG_ACPI)` then read `rsdp_address`.
This can replace the legacy low-memory RSDP scan in `acpi.c` with a
CRC-verified pointer. The ACPI subsystem must still validate the pointed-to
RSDP signature, extent, and ACPI checksum before use.

For the cmdline (out-of-line) ALWAYS verify before trusting (ADR-0006):

```c
const struct bbp_tag_cmdline *cl = (const void *)bbp_find_tag(k, BBP_TAG_CMDLINE);
if (cl && bbp_verify_blob(k, cl->string, cl->length, cl->string_crc, 0) == BBP_OK) {
    const char *s = bbp_phys_to_virt(k, cl->string);   /* safe to read */
}
```

--------------------------------------------------------------------------
## 5. Build + verify

    # compile-check the port against the frozen core
    cd /Users/admin/OS/BearBoot/ports/minix && make scaffold-check CROSS=x86_64-elf-

    # core self-test still green
    cd /Users/admin/OS/BearBoot && make test

    # standalone real-boot proof of the adapter (Limine higher-half, QEMU)
    cd /Users/admin/OS/BearBoot/ports/minix/test && ./run.sh
    # -> writes test/serial.log; look for "bbp: minix adapter ok, N tags, hhdm=0x..."

After wiring into MINIX, the same evidence appears in the MINIX serial log as
the `[limine] BBP adapter: ok` line emitted at the call site above.

--------------------------------------------------------------------------
## 6. Tech debt / future work

- OSIF `now_ns` assumes a nominal 1 GHz TSC (1 tick == 1 ns). Honest
  approximation for relative boot metrics only; calibrate against PIT/HPET or
  feed MINIX's real `tsc_per_ms` once the timer subsystem is up.
- The scratch arena is a 64 KiB static buffer (v1). Switch to the kernel PMM
  via OSIF `alloc_pages` once a PMM exists this early, if larger tag sets are
  needed.
- ACPI tag fills only `rsdp_address`; `xsdt_address`/`acpi_version`/`oem_id`
  are left 0 because parsing the RSDP/RSDT is out of scope for the adapter.
  Populate them if a consumer needs them without re-parsing.
