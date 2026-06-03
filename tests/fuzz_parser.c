/*
 * fuzz_parser.c — coverage/robustness fuzzer for the BBP kernel parser.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * ADR-0004 says the parser treats the handoff as hostile input. This fuzzer
 * proves it with TWO harnesses:
 *
 *   run_raw()        — arbitrary bytes cast to a bbp_info. Mostly exercises the
 *                      early reject path (random bytes ~never forge a valid
 *                      INFO CRC), but cheap breadth.
 *   run_structured() — builds a VALID info via bbp_build (so it passes init and
 *                      REACHES the tag walk), then overlays fuzz bytes onto the
 *                      tag arena. Because the INFO CRC covers only the fixed
 *                      info struct (not the tags), mutating the tag region
 *                      keeps init succeeding, so EVERY input stresses the
 *                      defensive tag parser — the code that actually matters.
 *
 * The parser must NEVER crash, hang, or read out of bounds. The default driver
 * also reports how many structured inputs reached the walk, so the coverage
 * claim is measured, not assumed.
 *
 * Build modes (see Makefile `fuzz`):
 *   -DBBP_LIBFUZZER  -> libFuzzer entry (clang+ASan): alternates harnesses.
 *   default          -> deterministic driver + reach-rate report.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

#define ARENA 65536

/* Drive every public parser path against an info pointer. Returns 1 if the
 * info validated and the tag walk was reached, else 0.
 *
 * `lo`/`hi`, when hi>lo, are the bounds of the mapped arena holding the tags —
 * the fuzzer passes them so the parser's optional walk window (ADR-0009) is
 * exercised exactly as a real kernel uses it: a tag pointer outside the mapped
 * region is rejected as corruption instead of being dereferenced (which, in
 * this hosted harness, would be a wild host-pointer read). Pass 0,0 to leave
 * the window disabled and exercise the architectural-bound path. */
static int drive(struct bbp_info *info, bbp_phys_t lo, bbp_phys_t hi)
{
    struct bbp_kctx k;
    /* Use bbp_init_win so the walk window is active even for the HHDM lookup
     * bbp_init performs internally — that internal walk is the one a forged
     * next_tag attacks. (bbp_init + a later set_walk_window would leave that
     * first walk unbounded; the fuzzer proved that.) */
    if (bbp_init_win(&k, info, 0, lo, hi) != BBP_OK) {
        struct bbp_kctx z; memset(&z, 0, sizeof(z)); z.info = info;
        z.walk_lo = lo; z.walk_hi = hi;
        (void)bbp_find_tag(&z, BBP_TAG_MEMORY_MAP);   /* safe on rejected ctx */
        return 0;
    }
    static const uint64_t ids[] = {
        BBP_TAG_SMP, BBP_TAG_MODULES, BBP_TAG_CMDLINE, BBP_TAG_MEMORY_MAP,
        BBP_TAG_HHDM, BBP_TAG_KERNEL_ADDRESS, BBP_TAG_FRAMEBUFFER, BBP_TAG_PCIE,
        BBP_TAG_SECURITY, BBP_TAG_ACPI, BBP_TAG_DEVICETREE, BBP_TAG_EFI,
        BBP_TAG_HYPERVISOR, BBP_TAG_SMBIOS, BBP_TAG_METRICS,
    };
    for (size_t i = 0; i < sizeof(ids)/sizeof(ids[0]); i++) {
        const struct bbp_tag_header *t = bbp_find_tag(&k, ids[i]);
        if (t) {
            /* If we found a variable-length tag, exercise the clamped accessor
             * — a corrupt count must never drive an OOB. */
            uint32_t n = 0;
            (void)bbp_tag_array(t, sizeof(struct bbp_tag_header),
                                sizeof(struct bbp_memory_entry),
                                0xFFFFFFFFu, &n);
        }
    }
    int count = 0;
    bbp_for_each_tag(&k, 0, &count);   /* NULL cb returns 0; must not crash */
    return 1;
}

/* Harness 1: arbitrary bytes as the info struct. */
static int run_raw(const uint8_t *data, size_t len)
{
    static uint8_t arena[ARENA];
    memset(arena, 0, sizeof(arena));
    if (len > ARENA) len = ARENA;
    memcpy(arena, data, len);

    struct bbp_info *info = (struct bbp_info *)arena;
    if (len >= sizeof(struct bbp_info)) {
        uint64_t ft = info->first_tag;
        info->first_tag = (bbp_phys_t)(uintptr_t)arena + (ft % ARENA);
    }
    /* The mapped region in this harness is exactly the arena. */
    bbp_phys_t lo = (bbp_phys_t)(uintptr_t)arena;
    return drive(info, lo, lo + ARENA);
}

/* Harness 2: valid info, fuzzed tag arena — guaranteed to reach the walk. */
static int run_structured(const uint8_t *data, size_t len)
{
    static uint8_t arena[ARENA];
    memset(arena, 0, sizeof(arena));

    struct bbp_info *info = (struct bbp_info *)arena;
    struct bbp_builder b;
    uint8_t *tagbase = arena + sizeof(struct bbp_info);
    size_t   tagcap  = sizeof(arena) - sizeof(struct bbp_info);
    bbp_builder_init(&b, tagbase, (bbp_phys_t)(uintptr_t)tagbase, tagcap);

    /* A small, valid baseline chain. */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    if (h) h->offset = 0;
    size_t mmsz = sizeof(struct bbp_tag_memory_map) + 4 * sizeof(struct bbp_memory_entry);
    struct bbp_tag_memory_map *mm = bbp_alloc_tag(&b, BBP_TAG_MEMORY_MAP, 1, mmsz);
    if (mm) { mm->entry_count = 4; mm->entry_size = sizeof(struct bbp_memory_entry); }
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    if (a) a->rsdp_address = 0xE0000;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    /* Overlay fuzz bytes onto the tag arena (NOT the info struct), so the
     * INFO CRC still validates and init reaches the walk, while the tags are
     * arbitrary. Keep first_tag pointing into the arena. */
    size_t off = 0;
    for (size_t i = 0; i < len && off < tagcap; i++, off++)
        tagbase[off] ^= data[i];   /* XOR-mutate to keep some structure */

    /* The mapped region is exactly the arena; bound the walk to it. */
    bbp_phys_t lo = (bbp_phys_t)(uintptr_t)arena;
    return drive(info, lo, lo + ARENA);
}

#ifdef BBP_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Split the corpus byte to pick a harness, fuzz the rest. */
    if (size && (data[0] & 1)) run_structured(data + 1, size - 1);
    else                       run_raw(data, size);
    return 0;
}
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

/* ── Hang watchdog (deterministic driver) ──────────────────────────────────
 * Same rationale as the abi_selftest watchdog: the parser is bounded against
 * cyclic/forged chains, but a REGRESSION dropping a loop guard would make one
 * of the 50k iterations spin forever — a silent 100%-CPU zombie. Arm a SIGALRM
 * deadline so a hang becomes a VISIBLE failure (exit 124) that names the
 * iteration in flight. The Makefile `fuzz` target also wraps this in `timeout`
 * as a second belt. */
#ifndef BBP_FUZZ_TIMEOUT
#define BBP_FUZZ_TIMEOUT 60   /* 50k iters + ASan run in well under this */
#endif

static volatile int   wd_phase = 0;        /* 0=seeds 1=sweep 2=files */
static volatile long  wd_iter  = -1;       /* current sweep iteration */

static void wd_write(const char *s){ size_t n=0; while(s[n])n++; (void)!write(2,s,n); }
static void wd_num(long v){ char b[24]; int i=24; if(v<0){wd_write("?");return;}
    if(v==0){wd_write("0");return;} while(v&&i){b[--i]='0'+(v%10);v/=10;} (void)!write(2,&b[i],24-i); }

static void wd_handler(int sig)
{
    (void)sig;
    wd_write("\nbbp_fuzz: FAILED — TIMED OUT (hang regression in the parser; "
             "a dropped BBP_MAX_TAGS / loop guard).\n  phase=");
    wd_num(wd_phase);
    wd_write(" sweep_iter="); wd_num(wd_iter);
    wd_write("\n");
    _exit(124);
}

int main(int argc, char **argv)
{
    uint8_t buf[256];
    unsigned long reached = 0, structured_total = 0;

    signal(SIGALRM, wd_handler);
    alarm(BBP_FUZZ_TIMEOUT);

    /* Targeted adversarial seeds (raw harness). */
    wd_phase = 0;
    run_raw((const uint8_t *)"", 0);
    memset(buf, 0xAA, sizeof(buf)); run_raw(buf, sizeof(buf));
    memset(buf, 0, sizeof(buf));
    memcpy(buf, BBP_INFO_MAGIC, sizeof(BBP_INFO_MAGIC) - 1);
    run_raw(buf, 8);
    memcpy(buf, BBP_INFO_MAGIC, sizeof(BBP_INFO_MAGIC) - 1);
    buf[16] = BBP_VERSION_MAJOR;
    *(uint32_t *)(buf + 20) = 0xFFFFFFFFu;
    run_raw(buf, sizeof(buf));

    /* Random sweep through BOTH harnesses (deterministic seed). */
    wd_phase = 1;
    unsigned s = 0x1234567u;
    for (int it = 0; it < 50000; it++) {
        wd_iter = it;
        for (size_t i = 0; i < sizeof(buf); i++) {
            s = s * 1103515245u + 12345u;
            buf[i] = (uint8_t)(s >> 16);
        }
        run_raw(buf, sizeof(buf));
        reached += (unsigned)run_structured(buf, sizeof(buf));
        structured_total++;
    }

    /* Files named on argv go through both harnesses. */
    wd_phase = 2;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        static uint8_t fb[ARENA];
        size_t n = fread(fb, 1, sizeof(fb), f);
        fclose(f);
        run_raw(fb, n);
        run_structured(fb, n);
    }

    alarm(0);   /* survived in time: disarm */
    printf("bbp_fuzz: corpus survived (no crash, no hang)\n");
    printf("bbp_fuzz: structured harness reached the tag walk %lu/%lu (%.1f%%)\n",
           reached, structured_total,
           structured_total ? 100.0 * (double)reached / (double)structured_total : 0.0);
    /* The structured harness MUST reach the walk essentially always; if it
     * does not, the fuzzer is testing nothing and that is itself a failure. */
    if (structured_total && reached < structured_total) {
        printf("bbp_fuzz: WARNING: some structured inputs did not reach the walk\n");
        return 1;
    }
    return 0;
}
#endif
