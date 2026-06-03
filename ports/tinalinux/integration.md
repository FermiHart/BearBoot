# BBP TinaLinux integration — exact paths, flags, and call site

This documents how the native Linux->BBP OSIF (shipped in `ports/tinalinux/`)
is wired into the TinaLinux x86_64 kernel (Linux 6.12 derivative). Nothing here
edits the BBP core; the port is consumed as a vendored arch subdirectory.

Target tree: `/home/alf/OS/TinaLinux`, kernel at `kernel/`.

--------------------------------------------------------------------------
## 0. What the port gives TinaLinux

TinaLinux already consumes the firmware tables (e820, ACPI, cmdline) through the
native Linux boot path. The BBP port is ADDITIVE: at `late_initcall` it
synthesizes a CRC-64/XZ-sealed BBP tag list from those SAME native globals and
validates it through the BBP defensive parser. The kernel can then read hardware
data through `bbp_find_tag()` with per-tag CRC integrity and out-of-line blob
verification — e.g. a CRC-verified ACPI RSDP via `bbp_tina_get_rsdp()` — without
disturbing the existing boot path. It is NON-FATAL: TinaLinux boots normally
whether or not validation succeeds.

--------------------------------------------------------------------------
## 1. Vendored layout (arch/x86/bbp/)

The canonical port lives in `BearBoot/ports/tinalinux/`. It is vendored FLAT
into the kernel at `kernel/arch/x86/bbp/`:

    include/bbp/{bbp.h,bbp_crc64.h,bbp_osif.h}   ABI-FROZEN core headers
    bbp_kernel.{c,h}                             ABI-FROZEN core parser
    bbp_build.{c,h}                              ABI-FROZEN core builder
    osif.{c,h}                                   TinaLinux OSIF (freestanding)
    adapter.{c,h}                                native Linux->BBP adapter
    tina_bbp.{c,h}                               kernel glue + late_initcall
    port/compat/{stdint.h,stddef.h}              shims for the frozen core's
                                                 <stdint.h>/<stddef.h> under
                                                 the kernel -nostdinc build
    Kbuild, Kconfig

The only edit vs the canonical port is the include layout: `adapter.{c,h}` use
`"bbp_kernel.h"` / `"bbp_build.h"` (flat) instead of the canonical
`"../../kernel/..."` relative paths. The core headers themselves are unmodified.

Re-vendor after a port change:
    cp BearBoot/include/bbp/*.h           kernel/arch/x86/bbp/include/bbp/
    cp BearBoot/kernel/bbp_kernel.{c,h}   kernel/arch/x86/bbp/
    cp BearBoot/bootloader/bbp_build.{c,h} kernel/arch/x86/bbp/
    cp BearBoot/ports/tinalinux/{osif,adapter,tina_bbp}.{c,h} kernel/arch/x86/bbp/
    cp BearBoot/ports/tinalinux/compat/*.h kernel/arch/x86/bbp/port/compat/
    # then fix the two flat includes in adapter.{c,h} and tina_bbp.h:
    sed -i 's#"\.\./\.\./bootloader/bbp_build.h"#"bbp_build.h"#; \
            s#"\.\./\.\./kernel/bbp_kernel.h"#"bbp_kernel.h"#' \
        kernel/arch/x86/bbp/adapter.c kernel/arch/x86/bbp/adapter.h \
        kernel/arch/x86/bbp/tina_bbp.h

--------------------------------------------------------------------------
## 2. Build wiring (3 hooks)

(a) arch/x86/Kbuild — add the subdirectory:

        obj-$(CONFIG_BBP_TINALINUX) += bbp/

(b) arch/x86/Kconfig — source the port's Kconfig (next to the kvm one):

        source "arch/x86/bbp/Kconfig"

(c) The port's own Kbuild builds one composite `bbp.o` from the core + port +
    glue, and puts the BBP `<bbp/...>` headers + the compat shim on the right
    include paths:

        obj-$(CONFIG_BBP_TINALINUX) += bbp.o
        bbp-y := bbp_kernel.o bbp_build.o osif.o adapter.o tina_bbp.o
        ccflags-y += -I$(src)/include
        CFLAGS_<each>.o += -idirafter $(src)/port/compat

    `-idirafter` is consulted only when no earlier header matched; under the
    kernel's -nostdinc there is no system <stdint.h>, so the shim is used — but
    it never shadows a real kernel header for the glue TU. The shims also
    `#ifndef _LINUX_TYPES_H` / `_LINUX_STDDEF_H`, so when tina_bbp.c pulls
    <linux/...> first, the kernel's own fixed-width types win and there is no
    typedef clash.

CONFIG_BBP_TINALINUX defaults to y (depends on X86_64 && ACPI).

--------------------------------------------------------------------------
## 3. The call site (already in tina_bbp.c)

`late_initcall(bbp_tina_init)` sources the native Linux boot data and runs the
adapter. No edits to existing kernel files are needed beyond §2 — the call site
ships inside the port. For reference, it does:

```c
bi.hhdm_offset         = page_offset_base;          /* Linux direct map      */
bi.kernel_phys_base    = phys_base;
bi.kernel_virt_base    = (uintptr_t)_text;
bi.have_kernel_address = 1;
for (i = 0; i < e820_table->nr_entries; i++) {      /* firmware e820 map     */
    bbp_mmap[m].base   = e820_table->entries[i].addr;
    bbp_mmap[m].length = e820_table->entries[i].size;
    bbp_mmap[m].type   = e820_table->entries[i].type;  /* RAW E820_TYPE_*    */
    m++;
}
bi.mmap = bbp_mmap; bi.mmap_count = m;
bi.rsdp_phys = acpi_os_get_root_pointer();          /* ACPI RSDP            */
bi.cmdline   = saved_command_line;                  /* boot cmdline         */
bbp_tina_adapter(&bbp_ctx, &bi);                    /* build + validate     */
```

The adapter calls `bbp_tina_set_hhdm()` / `bbp_tina_set_kslide()` for you, so
OSIF `phys_to_virt`/`alloc` are coherent immediately after.

--------------------------------------------------------------------------
## 4. Consuming tags later in the kernel

Include `tina_bbp.h` (+ `bbp_kernel.h`) and use the saved context:

```c
const struct bbp_kctx *k = bbp_tina_boot_ctx();     /* NULL if validation failed */
if (k) {
    const struct bbp_tag_header *t = bbp_find_tag(k, BBP_TAG_MEMORY_MAP);
    if (t) {
        const struct bbp_tag_memory_map *mm = (const void *)t;
        uint32_t n;
        const struct bbp_memory_entry *e =
            bbp_tag_array(t, sizeof(*mm), sizeof(struct bbp_memory_entry),
                          mm->entry_count, &n);       /* clamps n to tag_size */
        for (uint32_t i = 0; i < n; i++) { /* e[i].base, .length, .type ... */ }
    }
}
```

CRC-verified ACPI RSDP (a drop-in for the legacy low-memory RSDP scan):

```c
u64 rsdp = bbp_tina_get_rsdp();   /* 0 if no valid ctx / corrupt ACPI tag */
```

Out-of-line cmdline — ALWAYS verify before trusting (ADR-0006):

```c
const struct bbp_tag_cmdline *cl = (const void *)bbp_find_tag(k, BBP_TAG_CMDLINE);
if (cl && bbp_verify_blob(k, cl->string, cl->length, cl->string_crc, 0) == BBP_OK) {
    const char *s = bbp_phys_to_virt(k, cl->string);  /* safe to read */
}
```

--------------------------------------------------------------------------
## 5. Build + verify

    # compile-check the port against the frozen core (freestanding)
    cd BearBoot/ports/tinalinux && make scaffold-check

    # hosted adapter proof through the frozen parser (no QEMU)
    cd BearBoot/ports/tinalinux && make test
    # -> "bbp: tinalinux adapter ok, 5 tags … RESULT: PASS"

    # in the kernel tree: enable + build
    cd TinaLinux/kernel
    ./scripts/config --file build/kernel/.config --enable BBP_TINALINUX
    make O=build/kernel olddefconfig
    bash ../scripts/build-kernel-initramfs.sh     # bzImage w/ embedded initramfs

    # headless boot proof (serial -> file, per AGENTS.md; never -serial stdio)
    qemu-system-x86_64 -enable-kvm -cpu host,-svm -m 512M -smp 4 \
      -kernel build/kernel/arch/x86/boot/bzImage \
      -vga none -display none -no-reboot \
      -append "console=ttyS0,115200" -serial file:/tmp/bbp-boot.log
    # then: tr -d '\r' < /tmp/bbp-boot.log | grep 'bbp: tinalinux adapter ok'
    #  -> bbp: tinalinux adapter ok, 5 tags, hhdm=0x<real page_offset_base>

--------------------------------------------------------------------------
## 6. Pre-existing config fixes (UNRELATED to BBP, but required to link)

The build dir had never produced a vmlinux. Two native TinaLinux config gaps
surfaced at link and were fixed (no BBP involvement):
- `fs/tinafs/Kconfig` now `select BUFFER_HEAD` + `select LEGACY_DIRECT_IO`
  (TinaFS uses fs/buffer.c: __bread_gfp / sync_dirty_buffer / mark_buffer_dirty).
- `CONFIG_TINAFS=y` — the permanent TinaLinux config; the always-builtin NYX
  entropy pool (lib/crypto/tina-nyx.c) hard-requires fs/tinafs/tina-blake3.o for
  its BLAKE3, and the lib/crypto Makefile documents that the link fails loudly
  without it "by design".

--------------------------------------------------------------------------
## 7. Tech debt / future work

- Route the ACPI subsystem through `bbp_tina_get_rsdp()` (CRC-verified RSDP) to
  replace the legacy low-memory RSDP scan — the accessor is shipped.
- Populate the ACPI tag's xsdt_address / acpi_version by parsing the RSDP.
- Bump BBP_TINA_ARENA_ORDER if a future consumer adds many large tags.
