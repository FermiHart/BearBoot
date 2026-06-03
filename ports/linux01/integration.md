# BBP linux-0.01 integration — exact paths, flags, and call site

This documents how the native linux-0.01 -> BBP OSIF (shipped in
`ports/linux01/`) is wired into the linux-0.01-modern kernel (Linus Torvalds'
first kernel, 1991, ported to boot under Limine on modern x86 + QEMU). Nothing
here edits the BBP core; the port is consumed as a vendored arch subdirectory.

Target tree: `/Users/admin/Documents/Code/linux-0.01-modern`.

--------------------------------------------------------------------------
## 0. What the port gives linux-0.01

linux-0.01 has no firmware memory map, no ACPI, no boot cmdline — it is a 1991
kernel with a FIXED, compile-time RAM model (`include/linux/config.h`
HIGH_MEMORY) and it runs IDENTITY-mapped (mm/memory.c hardcodes `pg_dir = 0`,
which maps the first 8 MiB with virt == phys). The BBP port is ADDITIVE: early
in `main()` it synthesizes a CRC-64/XZ-sealed BBP tag list from that same fixed
RAM model and validates it through the BBP defensive parser. The kernel can then
read its memory layout through `bbp_find_tag()` with per-tag CRC integrity —
without disturbing the existing boot path. It is NON-FATAL: linux-0.01 boots
normally whether or not validation succeeds.

Because the kernel is identity-mapped, the handoff is the SIMPLEST possible BBP
case (SPEC §10.1(a)): the HHDM offset is literally 0, every tag pointer is a
true physical that is also a valid virtual, and the parser is seeded with offset
0 via `bbp_init` (no `bbp_init_ex`, no higher-half translation).

--------------------------------------------------------------------------
## 1. Vendored layout (kernel/bbp/)

The canonical port lives in `BearBoot/ports/linux01/`. Vendor it FLAT into the
linux-0.01 tree at `bbp/` (a new top-level dir next to boot/ kernel/ mm/ fs/):

    bbp/include/bbp/{bbp.h,bbp_crc64.h,bbp_osif.h}   ABI-FROZEN core headers
    bbp/bbp_kernel.{c,h}                             ABI-FROZEN core parser
    bbp/bbp_build.{c,h}                              ABI-FROZEN core builder
    bbp/osif.{c,h}                                   linux-0.01 OSIF (freestanding)
    bbp/adapter.{c,h}                                native RAM-model -> BBP adapter
    bbp/linux01_bbp.{c,h}                            kernel glue + call site
    bbp/compat/{stdint.h,stddef.h}                   shims for the frozen core's
                                                     <stdint.h>/<stddef.h> under
                                                     the kernel -nostdinc build

The only edit vs the canonical port is the include layout: `adapter.{c,h}`,
`linux01_bbp.{c,h}` use `"bbp_kernel.h"` / `"bbp_build.h"` (flat) instead of the
canonical `"../../kernel/..."` / `"../../bootloader/..."` relative paths. The
core headers themselves are UNMODIFIED (byte-identical, ABI-frozen).

Re-vendor after a port change:

    cp BearBoot/include/bbp/*.h            linux-0.01-modern/bbp/include/bbp/
    cp BearBoot/kernel/bbp_kernel.{c,h}    linux-0.01-modern/bbp/
    cp BearBoot/bootloader/bbp_build.{c,h} linux-0.01-modern/bbp/
    cp BearBoot/ports/linux01/{osif,adapter,linux01_bbp}.{c,h} linux-0.01-modern/bbp/
    cp BearBoot/ports/linux01/compat/*.h   linux-0.01-modern/bbp/compat/
    # then fix the flat includes in adapter.{c,h} and linux01_bbp.{c,h}:
    sed -i '' 's#"\.\./\.\./bootloader/bbp_build.h"#"bbp_build.h"#; \
               s#"\.\./\.\./kernel/bbp_kernel.h"#"bbp_kernel.h"#' \
        linux-0.01-modern/bbp/adapter.c linux-0.01-modern/bbp/adapter.h \
        linux-0.01-modern/bbp/linux01_bbp.c linux-0.01-modern/bbp/linux01_bbp.h

--------------------------------------------------------------------------
## 2. Build wiring — the C-standard split (CRITICAL)

linux-0.01-modern compiles the 1991 kernel with `-std=gnu89` (K&R-era source:
positional stack args in fork.c, `extern inline` semantics, etc.). The BBP core
REQUIRES C99+ (it declares loop variables in `for` initializers, uses
designated initializers). **Do not force the core down to gnu89** — give the BBP
objects their own dialect. Add a `bbp/Makefile` (or rules in the top Makefile):

    BBP_DIR   := bbp
    BBP_SRCS  := $(BBP_DIR)/bbp_kernel.c $(BBP_DIR)/bbp_build.c \
                 $(BBP_DIR)/osif.c $(BBP_DIR)/adapter.c $(BBP_DIR)/linux01_bbp.c
    BBP_OBJS  := $(BBP_SRCS:.c=.o)

    # BBP objects: SAME -m32 freestanding flags as the kernel, but -std=gnu11
    # (the core needs C99+) and the compat-shim + BBP include paths. Pass the
    # kernel's HIGH_MEMORY so the glue's RAM model matches config.h exactly.
    BBP_CFLAGS := -m32 -march=i386 -ffreestanding -fno-pie -fno-pic \
                  -fno-stack-protector -nostdinc -mno-sse -mno-mmx \
                  -std=gnu11 -O2 -Wall \
                  -I$(BBP_DIR)/include -I$(BBP_DIR)/compat -Iinclude \
                  -DBBP_L01_HIGH_MEMORY=$(shell awk '/define HIGH_MEMORY/{print $$3}' \
                                          include/linux/config.h | head -1)

    $(BBP_DIR)/%.o: $(BBP_DIR)/%.c
    	$(CC) $(BBP_CFLAGS) -c $< -o $@

Then add `$(BBP_OBJS)` to the kernel link line (the same `ld -m elf_i386` that
links kernel.bin). No linker-script change is required: the BBP objects are
ordinary `.text`/`.data`/`.rodata`/`.bss`, relocated to physical 0 with the rest
of the kernel by the existing bootstub.

The compat shims satisfy the core's `<stdint.h>`/`<stddef.h>` under the kernel's
`-nostdinc`. linux-0.01 has no `<linux/types.h>` with fixed-width types (it
predates them), so the shims' compiler-builtin typedefs are always what the BBP
TUs see — no clash with the 1991 headers (which the BBP TUs never include).

--------------------------------------------------------------------------
## 3. The call site — one line in main()

`init/main.c`, function `main()`. The adapter touches no interrupts and needs
only the identity map (always present on linux-0.01), so it can run anywhere in
`main()`. Place it right after `tty_init()` so `printk` output is visible:

```c
#include "../bbp/linux01_bbp.h"   /* with the other includes at file top */

void main(void)
{
    vga_set_50_rows();
    time_init();
    tty_init();
    trap_init();
    sched_init();
    buffer_init();
    hd_init();

    bbp_linux01_init();   /* <-- synthesize + validate the BBP tag list */

    sti();
    move_to_user_mode();
    if (!fork()) { init(); }
    for(;;) pause();
}
```

`bbp_linux01_init()` builds the bootinfo from the fixed RAM model internally
(0..640K RAM, 640K..1M reserved, 1M..HIGH_MEMORY RAM), runs the adapter, logs a
one-line verdict via printk, and stashes the validated context. No other kernel
file needs editing.

Expected serial/console line on success:

    [bbp] linux-0.01 adapter: ok, 3 tags, hhdm=0x0

--------------------------------------------------------------------------
## 4. Consuming tags later in the kernel

Anywhere after `bbp_linux01_init()` ran, with the saved context:

```c
#include "../bbp/linux01_bbp.h"
#include "../bbp/bbp_kernel.h"

const struct bbp_kctx *k = bbp_linux01_boot_ctx();   /* NULL if validation failed */
if (k) {
    const struct bbp_tag_header *t = bbp_find_tag(k, BBP_TAG_MEMORY_MAP);
    if (t) {
        const struct bbp_tag_memory_map *mm = (const void *)t;
        uint32_t n;
        const struct bbp_memory_entry *e =
            bbp_tag_array(t, sizeof(*mm), sizeof(struct bbp_memory_entry),
                          mm->entry_count, &n);        /* clamps n to tag_size */
        for (uint32_t i = 0; i < n; i++) { /* e[i].base, .length, .type ... */ }
    }
}
```

A natural future use (TECH DEBT, §6): cross-check `mem_init()` /
`buffer_init()`'s view of HIGH_MEMORY against the CRC-verified MEMORY_MAP tag,
so a corrupted RAM model is caught at boot instead of faulting later.

--------------------------------------------------------------------------
## 5. Build + verify

    # compile-check the port against the frozen core (freestanding, elf32-i386)
    cd BearBoot/ports/linux01 && make scaffold-check CROSS=x86_64-elf-

    # hosted adapter proof through the frozen parser (no QEMU)
    cd BearBoot/ports/linux01 && make test
    # -> "bbp: linux-0.01 adapter ok, 3 tags, hhdm=0x0 ... RESULT: PASS"

    # core self-test still green
    cd BearBoot && make test

After wiring into the kernel, the same evidence appears on the linux-0.01
console/serial as the `[bbp] linux-0.01 adapter: ok` line from the call site.

--------------------------------------------------------------------------
## 6. Tech debt / future work

- The scratch arena is a 64 KiB static buffer (`BBP_L01_ARENA_BYTES` in osif.c).
  For the 3-tag RAM-model set this is overkill (~250 bytes used). Switch to
  `get_free_page()` only if a future consumer adds many large tags. The real
  fix when that day comes is a strong `bbp_l01_hook_alloc` override in
  linux01_bbp.c bound to the kernel page allocator — the seam already exists.
- `now_ns` uses rdtsc at a nominal 1 GHz (1 tick == 1 ns). Honest approximation
  for relative boot metrics only; linux-0.01 has no calibrated timebase this
  early. Bind it to `jiffies` once a consumer needs real time.
- KERNEL_ADDRESS is 0/0 (linux-0.01 is linked AND loaded at physical 0 by the
  bootstub relocator). If a future build relocates the kernel, feed the real
  load base into `bi.kernel_phys_base` at the call site.
- The RAM model is derived from compile-time HIGH_MEMORY, not probed. linux-0.01
  itself never probes RAM (it trusts config.h), so this is faithful — but if a
  future port adds an e820 query, route it through the adapter's mmap array.

— F E R M I ∞ H A R T  <contact@fermihart.com>
