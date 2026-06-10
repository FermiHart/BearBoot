# BBP Josh-Bear integration — exact paths, flags, and call site

This file tells the Josh-Bear maintainer precisely how to vendor + wire the
Limine->BBP adapter (shipped in `ports/josh/osif.c` + `ports/josh/adapter.c` +
`ports/josh/josh_glue.c`) into the Josh-Bear ("lisabeth") x86_64 kernel tree.
Nothing here edits the BBP core; the adapter is consumed as a handful of extra
`.c` files plus one header include path. The BBP core stays ABI-frozen.

Target tree: `$JOSH` (the "lisabeth" Limine-booted kernel).

> Path placeholders below: `$JOSH` = your Josh-Bear checkout, `$BEARBOOT` = your
> BearBoot checkout. Substitute your own absolute paths.

--------------------------------------------------------------------------
## 0. What the adapter gives Josh-Bear

Josh-Bear already reads Limine responses through the `limine_get_*()` accessors
in `kernel/boot/limine_requests.c`. The BBP adapter is ADDITIVE: it synthesizes
a CRC-protected BBP tag list from the SAME Limine responses and validates it
with the BBP defensive parser. Josh can then consume hardware data (memory map,
HHDM, framebuffer, SMP topology, cmdline) through `bbp_find_tag()` with per-tag
CRC integrity and out-of-line blob verification — without touching the existing
boot path.

Because Josh is a monolithic kernel and the adapter runs AFTER vmm/pmm/heap are
up, this port needs no kernel-slide / static-arena gymnastics: the arena comes
straight from Josh's buddy allocator and the HHDM is Josh's own direct map.

--------------------------------------------------------------------------
## 1. Vendor the core + port, preserving the relative layout

Copy the following into the Josh tree, KEEPING the relative directory layout
(`adapter.c` includes `"../../kernel/bbp_kernel.h"` and
`"../../bootloader/bbp_build.h"`, so the port must sit two dirs below the core
headers). The cleanest mirror is to drop the whole `bearboot/` subtree under
e.g. `kernel/thirdparty/bearboot/`:

    bearboot/include/bbp/*                  (bbp.h, bbp_osif.h, bbp_crc64.h, ...)
    bearboot/kernel/bbp_kernel.{c,h}
    bearboot/bootloader/bbp_build.{c,h}
    bearboot/ports/josh/osif.{c,h}
    bearboot/ports/josh/adapter.{c,h}
    bearboot/ports/josh/josh_glue.c         (Josh-coupled; only lives here)

Keep `include/bbp/*`, `kernel/bbp_kernel.*`, `bootloader/bbp_build.*`
UNMODIFIED — they are ABI-frozen (pinned core commit ae5d3e2). If you vendor
the port somewhere that breaks the `../../` relative includes, adjust ONLY the
two `#include` lines in `adapter.c`; do not touch the core headers.

--------------------------------------------------------------------------
## 2. Compiler flags — add the BBP include path

Add ONE include dir to Josh's kernel CFLAGS (in `Makefile.bear` /
`Makefile.legacy`, wherever the kernel CFLAGS are assembled):

    -I<vendor>/bearboot/include            # e.g. -Ikernel/thirdparty/bearboot/include

That resolves `<bbp/bbp.h>`, `<bbp/bbp_osif.h>`, `<bbp/bbp_crc64.h>`.
`adapter.c` reaches the two non-`include/` core headers
(`bbp_kernel.h`, `bbp_build.h`) via the `../../` relative paths from
`ports/josh/`, so no extra `-I` is needed for those as long as the layout in §1
is preserved.

--------------------------------------------------------------------------
## 3. Files to add to the kernel build

Add these FIVE source files to Josh's kernel compile/link:

    bearboot/kernel/bbp_kernel.c            (core parser)
    bearboot/bootloader/bbp_build.c         (core builder)
    bearboot/ports/josh/osif.c              (Josh OSIF vtable)
    bearboot/ports/josh/adapter.c           (Limine -> BBP adapter)
    bearboot/ports/josh/josh_glue.c         (Josh integration entry)

`bbp_kernel.c`, `bbp_build.c`, `osif.c`, `adapter.c` are freestanding and pull
in NO Josh headers — they compile under Josh's existing kernel CFLAGS unchanged.
`josh_glue.c` is the ONE file coupled to Josh: it includes
`<kernel/boot/limine.h>` for the Limine struct/accessor declarations.

No linker-script change is required for the adapter path. The native-BBP-boot
`.bbp_hdr`/`KEEP()` mechanism is for a bootloader reading the kernel's Bear
Header, which is NOT what this port does — Limine stays the bootloader, untouched.

--------------------------------------------------------------------------
## 4. Where to call it — the entry sequence

Call site: `kernel/boot/lisabeth_kernel.c`, the main boot path. Call
`bbp_josh_init()` ONCE, AFTER the VMM / PMM / heap are up (the OSIF arena comes
from `pmm_alloc_pages`, and the parser dereferences through `g_hhdm_offset`), and
BEFORE networking (so a later netstack consumer can already query BBP tags).

In the current tree that window is right after `heap_init(...)` (line ~412) and
before `bearnet_init()` (line ~491):

```c
/* ---- BBP adapter: synthesize + validate a Bear Boot tag list -------- */
extern int bbp_josh_init(void);    /* ports/josh/josh_glue.c */
bbp_josh_init();                   /* non-fatal: Josh still boots if it fails */
```

`bbp_josh_init()` reads the Limine responses itself (via `limine_get_*()`), fills
`struct bbp_josh_bootinfo`, calls `bbp_josh_adapter()`, and on success logs ONE
proof line over COM1:

    [BBP] josh adapter ok, N tags, hhdm=0x... (CRC-sealed, parser-validated)

On failure it logs `[BBP] josh adapter FAILED: <status>` and returns the status;
the call is non-fatal — Josh continues booting from its existing Limine path.

--------------------------------------------------------------------------
## 5. Symbols the port depends on (must exist / link in the Josh tree)

OSIF (osif.c) `extern`-declares these Josh kernel symbols — all present in the
tree today:

| symbol                                   | where it lives                         |
|------------------------------------------|----------------------------------------|
| `uint64_t g_hhdm_offset`                 | Josh HHDM global (kernel/core/kmalloc.c, vmm) |
| `void kserial_puts(const char *)`        | Josh COM1 console                      |
| `void kpanic(const char *)` (noreturn)   | Josh panic                             |
| `uint64_t pmm_alloc_pages(unsigned char order)` | Josh buddy allocator (kernel/core/pmm.c) |

The glue (josh_glue.c) additionally uses `kserial_puthex` and the Limine
accessors declared in `<kernel/boot/limine.h>`:

| accessor                               | returns                              |
|----------------------------------------|--------------------------------------|
| `limine_get_hhdm_offset()`             | `uint64_t` HHDM offset (mandatory)   |
| `limine_get_memmap()`                  | `struct limine_memmap_response*`     |
| `limine_get_framebuffer()`             | `struct limine_framebuffer_response*`|
| `limine_get_smp()`                     | `struct limine_smp_response*`         |

--------------------------------------------------------------------------
## 6. Consuming tags later in the kernel

Anywhere after `bbp_josh_init()` ran, query through the saved context
(`bbp_josh_context()` returns the validated `struct bbp_kctx *`, or NULL):

```c
const struct bbp_kctx *k = bbp_josh_context();
if (k) {
    const struct bbp_tag_header *t = bbp_find_tag(k, BBP_TAG_MEMORY_MAP);
    if (t) {
        const struct bbp_tag_memory_map *mm = (const void *)t;
        uint32_t n;
        const struct bbp_memory_entry *e =
            bbp_tag_array(t, sizeof(*mm), sizeof(struct bbp_memory_entry),
                          mm->entry_count, &n);   /* clamps n to tag_size */
        for (uint32_t i = 0; i < n; i++) { /* e[i].base, .length, .type ... */ }
    }
}
```

For SMP topology: `bbp_find_tag(k, BBP_TAG_SMP)` then read `cpu_count`/`bsp_id`
and the trailing `struct bbp_cpu_info[]`. (Josh is multicore — the MINIX port
never emitted this tag.)

For the cmdline (out-of-line) ALWAYS verify before trusting (ADR-0006):

```c
const struct bbp_tag_cmdline *cl = (const void *)bbp_find_tag(k, BBP_TAG_CMDLINE);
if (cl && bbp_verify_blob(k, cl->string, cl->length, cl->string_crc, 0) == BBP_OK) {
    const char *s = bbp_phys_to_virt(k, cl->string);   /* safe to read */
}
```

--------------------------------------------------------------------------
## 7. SPEC §10.1(b) note — page tables and pointer truth

The adapter runs on Josh's OWN higher-half page tables (the VMM is already up).
Per SPEC §10.1(b): the tag pointers it emits are TRUE physicals (the arena is a
contiguous block from Josh's PMM, so its physical is known directly), and the
parser is seeded with the HHDM offset via `bbp_init_win()`. The walk is bounded
to `[arena_phys, arena_phys + arena_bytes)` (ADR-0009), so a corrupt `next_tag`
is rejected as corruption rather than faulting on unmapped RAM. There is no
identity-map assumption and no kernel-slide alias to reconcile — the single
direct map (`phys + g_hhdm_offset`) is used for both writing and reading the tags.

--------------------------------------------------------------------------
## 8. Build + verify

    # compile-check the port against the frozen core (freestanding, no run)
    cd $BEARBOOT/ports/josh && make scaffold-check CROSS=x86_64-elf-

    # run the standalone hosted harness (synthetic Limine data, shipped objects)
    cd $BEARBOOT/ports/josh && make          # expects "RESULT: PASS"
    # or: ./test/run.sh

    # core self-test still green
    cd $BEARBOOT && make test

After wiring into Josh, the same evidence appears in the Josh serial log as the
`[BBP] josh adapter ok, N tags, hhdm=0x...` line at the call site in §4. Capture
that log into `test/` as the real-boot proof (see CONFORMANCE.md).

--------------------------------------------------------------------------
## 9. Tech debt / future work

- OSIF `now_ns` assumes a nominal 1 GHz TSC (1 tick == 1 ns) — honest
  approximation for relative boot metrics only. Feed Josh's calibrated TSC
  frequency once the timer subsystem exposes it.
- No CMDLINE tag in v1: Josh boots without a Limine kernel command line. When
  one is added, point `bi.cmdline` at it in `josh_glue.c`; the adapter seals its
  `string_crc` and any consumer must `bbp_verify_blob()` it.
- Framebuffer EDID is not forwarded (`edid_crc=0`); width/height/pitch/format
  are. Forward EDID if a consumer needs it.
- The arena is a single 64 KiB PMM block (`BBP_JOSH_ARENA_BYTES`), never freed.
  Bump it via `-DBBP_JOSH_ARENA_BYTES=...` if a very large tag set is added.
