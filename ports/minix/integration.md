# BBP MINIX integration — exact paths, flags, and call site

This file tells the MINIX maintainer precisely how to wire the Limine->BBP
adapter (shipped in `ports/minix/osif.c` + `ports/minix/adapter.c`) into the
MINIX x86_64 `limine-boot` tree. Nothing here edits the BBP core; the adapter
is consumed as two extra `.c` files plus one header include path.

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

Add these THREE source files to the kernel compile (they are freestanding,
`-nostdinc`-safe, and pull in no MINIX headers):

    /Users/admin/OS/BearBoot/ports/minix/osif.c
    /Users/admin/OS/BearBoot/ports/minix/adapter.c
    (osif.h / adapter.h are headers — include path only)

In `minix/kernel/scripts/build_limine_full.sh`, append them to the library
source list (PHASE 1.5, the `LIBSRCS=(...)` array around line 129):

    LIBSRCS=(
        ...
        "/Users/admin/OS/BearBoot/ports/minix/osif.c"
        "/Users/admin/OS/BearBoot/ports/minix/adapter.c"
    )

They compile under the existing kernel `CFLAGS` unchanged. The only addition
needed is the BBP include path (next section).

For an in-tree mirror instead of an absolute path, copy `osif.{c,h}`,
`adapter.{c,h}` into e.g. `minix/kernel/arch/x86_64/bbp/` and adjust the two
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

The BBP core parser/builder objects MUST also be linked in. Add to the same
`LIBSRCS`:

    "/Users/admin/OS/BearBoot/kernel/bbp_kernel.c"
    "/Users/admin/OS/BearBoot/bootloader/bbp_build.c"

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

Add near the end of `limine_to_kinfo_and_boot()`, just before
`kmain(&limine_cbi);`:

```c
/* ---- BBP adapter: synthesize + validate a Bear Boot tag list -------- */
#include <bbp/bbp.h>                 /* (put includes at file top) */
#include "../../../BearBoot/ports/minix/adapter.h"
#include "../../../BearBoot/ports/minix/osif.h"

static struct bbp_minix_mmap_entry bbp_mmap[MAXMEMMAP_OR_MORE]; /* size to Limine entry_count */
static struct bbp_kctx            bbp_ctx;

{
    struct bbp_minix_bootinfo bi;
    for (unsigned z = 0; z < sizeof(bi); z++) ((char*)&bi)[z] = 0;

    bi.hhdm_offset = limine_hhdm_offset;
    bi.kernel_phys_base    = limine_kernel_phys_base;
    bi.kernel_virt_base    = limine_kernel_virt_base;
    bi.have_kernel_address = 1;
    bi.rsdp_phys           = limine_rsdp_phys;

    /* full Limine memmap (ALL types — the BBP map is informational and keeps
     * RESERVED/ACPI/etc., unlike the kinfo map which is usable-RAM only) */
    unsigned m = 0;
    if (memmap_request.response) {
        struct lim_memmap_response *r = memmap_request.response;
        for (unsigned i = 0; i < r->entry_count
                          && m < (sizeof(bbp_mmap)/sizeof(bbp_mmap[0])); i++) {
            bbp_mmap[m].base   = r->entries[i]->base;
            bbp_mmap[m].length = r->entries[i]->length;
            bbp_mmap[m].type   = r->entries[i]->type;  /* RAW Limine type */
            m++;
        }
    }
    bi.mmap = bbp_mmap; bi.mmap_count = m;

    /* cmdline: reuse the same string MINIX builds for param_buf, or any
     * NUL-terminated boot cmdline you have here. NULL => CMDLINE tag omitted. */
    bi.cmdline = "console=tty00 arch=x86_64";

    /* (optional) install MINIX panic() so OSIF panics route to it:
     *   bbp_minix_set_panic_hook(bbp_minix_panic_wrapper);
     * where bbp_minix_panic_wrapper(const char*m){ panic("%s", m); }   */

    bbp_status_t bst = bbp_minix_adapter(&bbp_ctx, &bi);
    e_puts("[limine] BBP adapter: ");
    e_puts(bbp_strstatus(bst));
    e_puts("\n");
    /* bbp_ctx is now a validated handle; stash it in a global for the rest of
     * the kernel to query via bbp_find_tag()/bbp_for_each_tag(). Non-fatal on
     * error — MINIX still boots from the legacy kinfo_t. */
}
```

Notes:
- The adapter calls `bbp_minix_set_hhdm()` and `bbp_minix_set_kslide()` for you
  from the bootinfo, so OSIF `phys_to_virt`/`alloc_pages` are coherent
  immediately after. You do NOT need to call them separately.
- `struct lim_memmap_response` is already declared locally in
  `limine_kinfo.c`; reuse it for the copy above.
- Size `bbp_mmap[]` to at least the Limine `entry_count` (a Limine map is
  routinely 30-40 entries; 256 is a safe static bound, ~6 KiB).
- The adapter's scratch arena is a 64 KiB static buffer inside `osif.c`
  (`BBP_MINIX_ARENA_BYTES`); for ~40 memmap entries the tag list is a few KiB,
  well within budget. Bump it via `-DBBP_MINIX_ARENA_BYTES=...` if you add many
  large tags.

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
CRC-verified value.

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
