/*
 * linux01_bbp.c — kernel glue for the Bear Boot Protocol on linux-0.01.
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * This is the TU that turns the freestanding port into a real linux-0.01
 * subsystem. It does three things:
 *
 *   1. Provides STRONG overrides of the port's __weak OSIF hooks, bound to the
 *      kernel's own printk / panic. The link prefers these over the weak COM1
 *      fallbacks in osif.c — same object, kernel world.
 *
 *   2. Builds the neutral bootinfo from linux-0.01's compile-time RAM model
 *      (config.h HIGH_MEMORY + the 640K-1M reserved hole). linux-0.01 has no
 *      firmware memory map; this fixed model IS the kernel's ground truth.
 *
 *   3. Runs the adapter and stashes the validated context for later queries.
 *
 * The kernel is IDENTITY-mapped (pg_dir = 0, first 8 MiB), so HHDM offset is 0
 * and the handoff is SPEC §10.1(a). The call is additive + non-fatal.
 *
 * Build note: linux-0.01 is -nostdinc -m32 gnu89. The BBP core headers pull
 * <stdint.h>/<stddef.h>, satisfied by the compat shims on the include path
 * (-Ibbp/compat when vendored into the kernel; -I.../ports/linux01/compat in
 * the standalone scaffold Makefile).
 */
#include <bbp/bbp.h>
#include "../../kernel/bbp_kernel.h"
#include "osif.h"
#include "adapter.h"
#include "linux01_bbp.h"

/* ===================================================================== *
 *  linux-0.01 kernel symbols we bind to. Declared here (not via the 1991
 *  headers) to keep this TU compilable both in-tree and for review. The
 *  signatures match kernel/printk.c and kernel/panic.c in linux-0.01-modern.
 * ===================================================================== */
extern int  printk(const char *fmt, ...);
extern void panic(const char *s) __attribute__((noreturn));

/* linux-0.01 RAM ceiling. config.h defines HIGH_MEMORY (0x800000 for LINUS_HD).
 * We accept it via -D so this TU does not include the 1991 config.h directly
 * (avoids dragging the whole linux/config.h + HD_TYPE machinery in here). The
 * Kbuild/Makefile passes -DBBP_L01_HIGH_MEMORY=HIGH_MEMORY. Fallback mirrors
 * the canonical LINUS_HD value so the standalone scaffold still builds. */
#ifndef BBP_L01_HIGH_MEMORY
#define BBP_L01_HIGH_MEMORY 0x800000UL   /* 8 MiB — matches config.h LINUS_HD */
#endif

/* The conventional low-memory layout every PC-AT clone (and QEMU) presents,
 * and exactly what Linus' kernel assumes: 0..640K RAM, 640K..1M reserved
 * (legacy video + BIOS), 1M..HIGH_MEMORY RAM. */
#define L01_LOW_RAM_TOP   0x000A0000UL   /* 640 KiB */
#define L01_RESERVED_TOP  0x00100000UL   /* 1 MiB   */

/* ===================================================================== *
 *  1. STRONG OSIF hook overrides (printk / panic).
 * ===================================================================== */
void bbp_l01_hook_log(const char *msg)
{
    if (msg)
        printk("%s", msg);
}

__attribute__((noreturn)) void bbp_l01_hook_panic(const char *msg)
{
    panic(msg ? msg : "bbp: (null) panic");
}

/* ===================================================================== *
 *  2 + 3. Build bootinfo from the fixed RAM model, run the adapter.
 * ===================================================================== */
static struct bbp_kctx l01_boot_ctx;
static int             l01_boot_ctx_valid = 0;

bbp_status_t bbp_linux01_init(void)
{
    struct bbp_l01_mmap_entry mmap[3];
    struct bbp_l01_bootinfo   bi;
    unsigned                  m = 0;
    bbp_status_t              st;
    unsigned                  z;

    /* zero bi without memset (freestanding, no libc) */
    for (z = 0; z < sizeof(bi); z++)
        ((char *)&bi)[z] = 0;

    /* identity-mapped: HHDM offset 0, kernel linked + loaded at physical 0 */
    bi.hhdm_offset         = 0;
    bi.kernel_phys_base    = 0;
    bi.kernel_virt_base    = 0;
    bi.have_kernel_address = 1;

    /* the fixed RAM model (BBP_MEM_* directly — no firmware map to decode):
     * 0..640K usable, 640K..1M reserved (legacy video + BIOS), 1M..ceiling
     * usable. The third region is emitted only if the ceiling is above 1 MiB
     * (it always is for both LINUS_HD=8M and LASU_HD=4M); the guard keeps the
     * length from underflowing to a huge value should a future config shrink
     * HIGH_MEMORY at or below 1 MiB. */
    mmap[m].base = 0x0;             mmap[m].length = L01_LOW_RAM_TOP;
    mmap[m].type = BBP_MEM_USABLE;                                  m++;
    mmap[m].base = L01_LOW_RAM_TOP; mmap[m].length = L01_RESERVED_TOP - L01_LOW_RAM_TOP;
    mmap[m].type = BBP_MEM_RESERVED;                                m++;
    if ((uint64_t)BBP_L01_HIGH_MEMORY > L01_RESERVED_TOP) {
        mmap[m].base   = L01_RESERVED_TOP;
        mmap[m].length = (uint64_t)BBP_L01_HIGH_MEMORY - L01_RESERVED_TOP;
        mmap[m].type   = BBP_MEM_USABLE;                            m++;
    }

    bi.mmap       = mmap;
    bi.mmap_count = m;

    st = bbp_l01_adapter(&l01_boot_ctx, &bi);

    printk("[bbp] linux-0.01 adapter: %s", bbp_strstatus(st));
    if (st == BBP_OK) {
        l01_boot_ctx_valid = 1;
        printk(", %u tags, hhdm=0x%x\n",
               (unsigned)l01_boot_ctx.info->tag_count,
               (unsigned)l01_boot_ctx.hhdm_offset);
    } else {
        printk(" (non-fatal, kernel continues)\n");
    }
    return st;
}

const struct bbp_kctx *bbp_linux01_boot_ctx(void)
{
    return l01_boot_ctx_valid ? &l01_boot_ctx : (const struct bbp_kctx *)0;
}
