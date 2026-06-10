/*
 * abi_selftest.c — Bear Boot Protocol regression suite.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * Hosted test (runs on the build machine) that proves:
 *   1. CRC-64/XZ matches the canonical check vector for "123456789".
 *   2. Every ABI struct has the exact expected size (defense in depth on
 *      top of the _Static_asserts in bbp.h).
 *   3. The bootloader builder and the kernel parser agree: a full info+tag
 *      arena built by bbp_build.c is validated and walked by bbp_kernel.c.
 *   4. CRC tampering is detected (info-level and tag-level).
 *
 * Built and run by `make test`. Identity-mapped model: phys == virt, hhdm=0.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

static int failures = 0;

/* ── Hang watchdog ─────────────────────────────────────────────────────────
 * The parser is explicitly bounded against cyclic/forged tag chains
 * (BBP_MAX_TAGS, the `&& steps < ...` loop guards). But a REGRESSION that drops
 * one of those guards would turn a malformed input into an infinite loop — and
 * a test with no timeout would then spin at 100% forever, a silent zombie that
 * never reports failure. So the harness arms its OWN deadline: if any test does
 * not finish within BBP_SELFTEST_TIMEOUT seconds, SIGALRM fires, we report the
 * hanging test by name, and exit non-zero. A hang becomes a VISIBLE failure.
 * (The Makefile `test` target also wraps this in `timeout` as a second belt.) */
#ifndef BBP_SELFTEST_TIMEOUT
#define BBP_SELFTEST_TIMEOUT 30   /* the whole suite runs in <1s normally */
#endif

static volatile const char *current_test = "(startup)";

/* async-signal-safe: only write() + a manual strlen, no stdio in the handler. */
static void watchdog_write(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    (void)!write(STDERR_FILENO, s, n);
}

static void watchdog_handler(int sig)
{
    (void)sig;
    watchdog_write("\nFAILED: self-test TIMED OUT in (or just after) test: ");
    watchdog_write((const char *)current_test);
    watchdog_write("\n  -> likely an INFINITE-LOOP REGRESSION in the parser "
                   "(a dropped BBP_MAX_TAGS / loop guard).\n"
                   "  -> the culprit is the LAST '[run]' line printed above.\n");
    _exit(124);   /* 124 = timeout, distinct from 1 (assertion failures) */
}

/* Run a named test under the watchdog. The name is written to STDERR (which is
 * unbuffered) the instant the test STARTS — so if it hangs, the last '[run]'
 * line on the console is the definitive culprit, independent of stdout
 * buffering or any compiler reordering of the volatile `current_test` hint. */
#define RUN(fn) do { \
    current_test = #fn; \
    watchdog_write("[run] " #fn "\n"); \
    fn(); \
} while (0)

#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: " __VA_ARGS__); printf("\n"); failures++; } \
    else         { printf("ok:   " __VA_ARGS__); printf("\n"); } \
} while (0)

static void test_crc64_vector(void)
{
    uint64_t c = bbp_crc64("123456789", 9);
    CHECK(c == 0x995DC9BBDF1939FAULL,
          "CRC-64/XZ('123456789') = 0x%016llX (want 0x995DC9BBDF1939FA)",
          (unsigned long long)c);
}

static void test_abi_sizes(void)
{
    CHECK(sizeof(struct bbp_header)         == 160, "sizeof bbp_header == 160 (%zu)", sizeof(struct bbp_header));
    CHECK(sizeof(struct bbp_info)           == 144, "sizeof bbp_info == 144 (%zu)", sizeof(struct bbp_info));
    CHECK(sizeof(struct bbp_tag_header)     == 32,  "sizeof bbp_tag_header == 32 (%zu)", sizeof(struct bbp_tag_header));
    CHECK(sizeof(struct bbp_tag_request)    == 24,  "sizeof bbp_tag_request == 24 (%zu)", sizeof(struct bbp_tag_request));
    CHECK(sizeof(struct bbp_memory_entry)   == 32,  "sizeof bbp_memory_entry == 32 (%zu)", sizeof(struct bbp_memory_entry));
    CHECK(sizeof(struct bbp_tag_memory_map) == 40,  "sizeof bbp_tag_memory_map == 40 (%zu)", sizeof(struct bbp_tag_memory_map));
    CHECK(sizeof(struct bbp_tag_hhdm)       == 40,  "sizeof bbp_tag_hhdm == 40 (%zu)", sizeof(struct bbp_tag_hhdm));
    CHECK(sizeof(struct bbp_cpu_info)       == 48,  "sizeof bbp_cpu_info == 48 (%zu)", sizeof(struct bbp_cpu_info));
    CHECK(sizeof(struct bbp_measurement)    == 144, "sizeof bbp_measurement == 144 (%zu)", sizeof(struct bbp_measurement));
    CHECK(sizeof(struct bbp_pcie_device)    == 168, "sizeof bbp_pcie_device == 168 (%zu)", sizeof(struct bbp_pcie_device));
    /* v1.1 out-of-line CRC growth (ADR-0006) */
    CHECK(sizeof(struct bbp_tag_security)   == 128, "sizeof bbp_tag_security == 128 (%zu)", sizeof(struct bbp_tag_security));
    CHECK(sizeof(struct bbp_tag_cmdline)    == 56,  "sizeof bbp_tag_cmdline == 56 (%zu)", sizeof(struct bbp_tag_cmdline));
    CHECK(sizeof(struct bbp_display_info)   == 48,  "sizeof bbp_display_info == 48 (%zu)", sizeof(struct bbp_display_info));
    CHECK(sizeof(struct bbp_tag_devicetree) == 80,  "sizeof bbp_tag_devicetree == 80 (%zu)", sizeof(struct bbp_tag_devicetree));
}

/* Build a realistic arena and round-trip it through the kernel parser. */
static uint8_t arena[64 * 1024];

static void test_roundtrip(void)
{
    struct bbp_builder b;
    /* Reserve the info at the front; arena phys == virt (identity). */
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));

    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));

    /* HHDM tag (offset 0 => identity, so parser pointers stay valid). */
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    bbp_seal_tag(&b, h);

    /* Memory map with 2 entries. */
    size_t mmsz = sizeof(struct bbp_tag_memory_map) + 2 * sizeof(struct bbp_memory_entry);
    struct bbp_tag_memory_map *mm = bbp_alloc_tag(&b, BBP_TAG_MEMORY_MAP, 1, mmsz);
    mm->entry_count = 2;
    mm->entry_size  = sizeof(struct bbp_memory_entry);
    struct bbp_memory_entry *e =
        (struct bbp_memory_entry *)((uint8_t *)mm + sizeof(*mm));
    e[0] = (struct bbp_memory_entry){ .base = 0x1000, .length = 0x9F000, .type = BBP_MEM_USABLE };
    e[1] = (struct bbp_memory_entry){ .base = 0x100000, .length = 0x7F00000, .type = BBP_MEM_USABLE };
    bbp_seal_tag(&b, mm);

    /* ACPI tag. */
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000;
    a->acpi_version = 0x0604;
    bbp_seal_tag(&b, a);

    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    CHECK(!b.overflow, "builder did not overflow");
    CHECK(b.tag_count == 3, "builder produced 3 tags (%u)", b.tag_count);

    /* Now consume as the kernel would. */
    struct bbp_kctx k;
    bbp_status_t st = bbp_init(&k, info);
    CHECK(st == BBP_OK, "bbp_init: %s", bbp_strstatus(st));
    CHECK(k.hhdm_offset == 0, "hhdm offset picked up (%llu)", (unsigned long long)k.hhdm_offset);

    const struct bbp_tag_header *t = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    CHECK(t != NULL, "found memory map tag");
    if (t) {
        const struct bbp_tag_memory_map *m = (const struct bbp_tag_memory_map *)t;
        CHECK(m->entry_count == 2, "memory map has 2 entries (%u)", m->entry_count);
    }
    t = bbp_find_tag(&k, BBP_TAG_ACPI);
    CHECK(t != NULL, "found ACPI tag");
    if (t) {
        const struct bbp_tag_acpi *aa = (const struct bbp_tag_acpi *)t;
        CHECK(aa->rsdp_address == 0xE0000, "ACPI rsdp preserved (0x%llX)",
              (unsigned long long)aa->rsdp_address);
    }
    CHECK(bbp_find_tag(&k, BBP_TAG_FRAMEBUFFER) == NULL, "absent tag returns NULL");

    /* count via iterator */
    uint32_t n = bbp_for_each_tag(&k, (bbp_tag_cb)(void *)0, NULL);
    (void)n;
}

static int dummy_cb(const struct bbp_tag_header *t, void *u) { (*(int *)u)++; (void)t; return 0; }

static void test_iter_and_tamper(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0; bbp_seal_tag(&b, h);
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000; bbp_seal_tag(&b, a);
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    struct bbp_kctx k;
    bbp_init(&k, info);
    int count = 0;
    bbp_for_each_tag(&k, dummy_cb, &count);
    CHECK(count == 2, "iterator visited 2 tags (%d)", count);

    /* Tamper the ACPI tag body -> CRC must now reject it on lookup. */
    a->rsdp_address = 0xDEADBEEF;
    CHECK(bbp_find_tag(&k, BBP_TAG_ACPI) == NULL, "tampered tag rejected by CRC");

    /* Tamper the info -> bbp_init must fail. */
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info); /* reseal */
    info->cpu_count = 99; /* mutate after seal */
    struct bbp_kctx k2;
    CHECK(bbp_init(&k2, info) == BBP_ERR_CHECKSUM, "tampered info rejected by CRC");
}

/* ── Adversarial tests: the bootloader/firmware is UNTRUSTED. ──────────────
 * These inject malformed tags directly into the arena and prove the parser
 * refuses to fault, loop, or hand corrupt data to a subsystem. */

static void test_hostile_undersized_tag(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    /* Corrupt the ACPI tag's size to an underflowing value (< header). This
     * used to drive bbp_crc_skip's (len - off - 8) to ~16 EiB -> OOB read. */
    a->header.tag_size = 4;

    struct bbp_kctx k;
    bbp_init(&k, info);
    CHECK(bbp_find_tag(&k, BBP_TAG_ACPI) == NULL,
          "undersized tag_size rejected (no underflow OOB)");
}

static void test_hostile_huge_tag(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    a->header.tag_size = 0xFFFFFFFFu; /* would CRC-scan 4 GiB */
    struct bbp_kctx k;
    bbp_init(&k, info);
    CHECK(bbp_find_tag(&k, BBP_TAG_ACPI) == NULL, "oversized tag_size rejected");
}

static void test_hostile_cycle(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    /* Point the HHDM tag's next_tag back at itself: infinite cycle. */
    h->header.next_tag = info->first_tag;

    struct bbp_kctx k;
    bbp_init(&k, info);
    /* Must terminate (BBP_MAX_TAGS ceiling) and not hang. */
    int count = 0;
    uint32_t visited = bbp_for_each_tag(&k, dummy_cb, &count);
    CHECK(visited <= 1024, "cyclic next_tag bounded by BBP_MAX_TAGS (%u)", visited);
    CHECK(bbp_find_tag(&k, BBP_TAG_ACPI) == NULL, "cycle search terminates");
}

static void test_hostile_misaligned_ptr(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    info->first_tag |= 3; /* misalign the very first pointer */
    /* bbp_init re-reads HHDM via find_tag; misaligned ptr must be refused. */
    struct bbp_kctx k;
    bbp_init(&k, info);
    int count = 0;
    bbp_for_each_tag(&k, dummy_cb, &count);
    CHECK(count == 0, "misaligned first_tag refused (visited 0)");
}

static void test_for_each_skips_corrupt(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    a->rsdp_address = 0xBADBAD; /* tamper body -> CRC fails */
    struct bbp_kctx k;
    bbp_init(&k, info);
    int count = 0;
    bbp_for_each_tag(&k, dummy_cb, &count);
    CHECK(count == 1, "for_each skips CRC-failed tag (visited %d, want 1)", count);
}

static void test_verify_header(void)
{
    /* Build a valid header in a buffer, stamp its CRC, verify it. */
    static struct bbp_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, BBP_HEADER_MAGIC, sizeof(BBP_HEADER_MAGIC) - 1);
    hdr.version_major = BBP_VERSION_MAJOR;
    hdr.version_minor = BBP_VERSION_MINOR;
    hdr.header_size   = sizeof(struct bbp_header);
    hdr.entry_point   = 0x100000;
    hdr.checksum      = 0;
    hdr.checksum      = bbp_header_crc(&hdr);

    CHECK(bbp_verify_header(&hdr) == BBP_OK, "valid header verified");

    hdr.entry_point = 0xDEAD; /* tamper after stamp */
    CHECK(bbp_verify_header(&hdr) == BBP_ERR_CHECKSUM, "tampered header rejected");

    hdr.entry_point = 0x100000; hdr.checksum = bbp_header_crc(&hdr);
    hdr.magic[0] = 'X';
    CHECK(bbp_verify_header(&hdr) == BBP_ERR_MAGIC, "bad header magic rejected");
    CHECK(bbp_verify_header(NULL) == BBP_ERR_NULL, "NULL header rejected");
}

static void test_array_clamp(void)
{
    /* A memory-map tag that CLAIMS 1000 entries but only has room for 2.
     * bbp_tag_array must clamp to 2 — trusting entry_count would OOB-read. */
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));
    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    size_t mmsz = sizeof(struct bbp_tag_memory_map) + 2 * sizeof(struct bbp_memory_entry);
    struct bbp_tag_memory_map *mm = bbp_alloc_tag(&b, BBP_TAG_MEMORY_MAP, 1, mmsz);
    mm->entry_count = 1000;  /* lie */
    mm->entry_size  = sizeof(struct bbp_memory_entry);
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    struct bbp_kctx k;
    bbp_init(&k, info);
    const struct bbp_tag_header *t = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    CHECK(t != NULL, "memory map found");
    uint32_t safe = 0;
    bbp_tag_array(t, sizeof(struct bbp_tag_memory_map),
                  sizeof(struct bbp_memory_entry),
                  ((const struct bbp_tag_memory_map *)t)->entry_count, &safe);
    CHECK(safe == 2, "array count clamped to what fits in tag_size (%u, want 2)", safe);
}

static void test_verify_blob(void)
{
    /* An out-of-line blob (e.g. a measurement log) protected by a sibling CRC
     * (ADR-0006). Identity-mapped, so hhdm offset 0. */
    static const uint8_t blob[] = "measured-boot-log-payload";
    uint64_t good = bbp_crc64(blob, sizeof(blob));

    struct bbp_kctx k;
    memset(&k, 0, sizeof(k));
    /* k.info is unused by bbp_verify_blob except via phys_to_virt; hhdm=0. */
    static struct bbp_info dummy;
    k.info = &dummy; k.hhdm_offset = 0; k.verify_tag_crc = 1;

    CHECK(bbp_verify_blob(&k, (bbp_phys_t)(uintptr_t)blob, sizeof(blob), good, 0) == BBP_OK,
          "out-of-line blob CRC verified");
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)(uintptr_t)blob, sizeof(blob), good ^ 1, 0)
          == BBP_ERR_TAG_CHECKSUM, "tampered blob CRC rejected");
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)(uintptr_t)blob, sizeof(blob), 0, 0)
          == BBP_ERR_TAG_CHECKSUM, "unchecked blob refused without opt-in");
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)(uintptr_t)blob, sizeof(blob), 0, 1)
          == BBP_OK, "unchecked blob allowed with opt-in");
    CHECK(bbp_verify_blob(&k, 0, sizeof(blob), good, 0) == BBP_ERR_NULL,
          "null blob ptr rejected");
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)(uintptr_t)blob, 0x10000000ULL, good, 0)
          == BBP_ERR_SIZE, "oversized blob length rejected");

    /* A2/A3: a near-top physical address + length that would WRAP the address
     * space must be rejected by the overflow-safe region check, not scanned. */
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)0xFFFFFFFFFFFFFF00ULL, 0x1000, good, 0)
          == BBP_ERR_SIZE, "wrapping blob region rejected (overflow-safe)");
    /* A phys just under the 2^48 cap with a length crossing it: rejected. */
    CHECK(bbp_verify_blob(&k, (bbp_phys_t)((1ULL<<48) - 16), 0x100, good, 0)
          == BBP_ERR_SIZE, "blob crossing BBP_MAX_PHYS rejected");
}

/* ── bbp_evidence (v1.2) ─────────────────────────────────────────────
 * Determinism + integrity-sensitivity, with a toy FNV-1a 64 as the
 * caller hash (the API is hash-agnostic; the kernel will use BLAKE3).
 */
static void fnv_update(void *state, const void *data, size_t len)
{
    uint64_t *h = (uint64_t *)state;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        *h ^= p[i];
        *h *= 0x100000001B3ULL;
    }
}

static void test_evidence(void)
{
    struct bbp_builder b;
    struct bbp_info *info = (struct bbp_info *)arena;
    memset(arena, 0, sizeof(arena));
    bbp_builder_init(&b, arena + sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena + sizeof(struct bbp_info)),
                     sizeof(arena) - sizeof(struct bbp_info));

    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b, BBP_TAG_HHDM, 1, sizeof(*h));
    h->offset = 0;
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b, BBP_TAG_ACPI, 1, sizeof(*a));
    a->rsdp_address = 0xE0000;
    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);

    struct bbp_kctx k;
    CHECK(bbp_init(&k, info) == BBP_OK, "evidence: init ok");

    uint64_t h1 = 0xcbf29ce484222325ULL, h2 = 0xcbf29ce484222325ULL;
    uint32_t n1 = bbp_evidence(&k, fnv_update, &h1);
    uint32_t n2 = bbp_evidence(&k, fnv_update, &h2);
    CHECK(n1 == 2 && n2 == 2, "evidence fed both tags (%u/%u)", n1, n2);
    CHECK(h1 == h2, "evidence is deterministic (same digest twice)");

    /* Flip one byte INSIDE a sealed tag body: CRC gate must drop the
     * tag from the evidence stream → digest changes AND tag count
     * drops. The digest is integrity-sensitive end to end. */
    a->rsdp_address ^= 1;
    uint64_t h3 = 0xcbf29ce484222325ULL;
    uint32_t n3 = bbp_evidence(&k, fnv_update, &h3);
    CHECK(n3 == 1, "tampered tag excluded from evidence (%u)", n3);
    CHECK(h3 != h1, "tamper changes the evidence digest");

    CHECK(bbp_evidence(NULL, fnv_update, &h1) == 0, "NULL ctx returns 0");
    CHECK(bbp_evidence(&k, NULL, &h1) == 0, "NULL update returns 0");
}

static void test_hostile_wrapping_tag_ptr(void)
{
    /* A4: first_tag set to a near-top address. Translating + reading the tag
     * header would wrap / fault; the region check must refuse the walk. */
    static struct bbp_info info;
    memset(&info, 0, sizeof(info));
    memcpy(info.magic, BBP_INFO_MAGIC, sizeof(BBP_INFO_MAGIC) - 1);
    info.version_major = BBP_VERSION_MAJOR;
    info.info_size = sizeof(struct bbp_info);
    info.tag_count = 1;
    info.first_tag = 0xFFFFFFFFFFFFFF00ULL;   /* hostile, would wrap */
    /* Seal the info CRC with the checksum field zeroed (same scheme as runtime). */
    {
        struct bbp_info tmp = info; tmp.checksum = 0;
        /* mimic bbp_crc_skip: crc over [0,off)+8 zero+[off+8,end) */
        uint64_t c = bbp_crc64_init();
        size_t off = offsetof(struct bbp_info, checksum);
        static const uint8_t z8[8] = {0};
        c = bbp_crc64_update(c, &tmp, off);
        c = bbp_crc64_update(c, z8, 8);
        c = bbp_crc64_update(c, (const uint8_t *)&tmp + off + 8, sizeof(tmp) - off - 8);
        info.checksum = bbp_crc64_final(c);
    }
    struct bbp_kctx k;
    bbp_status_t st = bbp_init(&k, &info);
    /* init succeeds (info CRC valid) but the HHDM lookup over a wrapping
     * first_tag must find nothing and must NOT fault. */
    CHECK(st == BBP_OK, "info with hostile first_tag still validates (CRC ok)");
    CHECK(bbp_find_tag(&k, BBP_TAG_ACPI) == NULL, "wrapping first_tag walk refused (no fault)");
}

int main(void)
{
    /* Arm the hang watchdog FIRST: install the SIGALRM handler and set the
     * deadline. If any test below spins forever (an infinite-loop regression),
     * the alarm fires, names the culprit, and exits 124 — a hang can never be a
     * silent 100%-CPU zombie. */
    signal(SIGALRM, watchdog_handler);
    alarm(BBP_SELFTEST_TIMEOUT);

    printf("== Bear Boot Protocol self-test ==\n");
    RUN(test_crc64_vector);
    RUN(test_abi_sizes);
    RUN(test_roundtrip);
    RUN(test_iter_and_tamper);
    printf("-- adversarial (untrusted bootloader) --\n");
    RUN(test_hostile_undersized_tag);
    RUN(test_hostile_huge_tag);
    RUN(test_hostile_cycle);
    RUN(test_hostile_misaligned_ptr);
    RUN(test_for_each_skips_corrupt);
    RUN(test_verify_header);
    RUN(test_array_clamp);
    RUN(test_verify_blob);
    RUN(test_hostile_wrapping_tag_ptr);
    printf("-- evidence (v1.2) --\n");
    RUN(test_evidence);

    alarm(0);   /* finished in time: disarm the watchdog */
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
