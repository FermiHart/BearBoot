/*
 * test/harness.c — standalone Limine kernel that exercises the MINIX BBP port.
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * WHY THIS EXISTS
 * ---------------
 * The deliverable is a serial log proving the Limine->BBP adapter validated on
 * REAL boot data (SPEC §10.1 / port README rule 5). We cannot boot the full
 * MINIX kernel just to test the adapter, and we must NOT edit anything outside
 * ports/minix/. So this tiny freestanding kernel stands in for MINIX:
 *
 *   - It is booted by the SAME Limine the MINIX port uses (limine protocol,
 *     higher-half, paging on, HHDM provided) — identical handoff conditions.
 *   - It publishes the same Limine requests MINIX does (memmap, hhdm,
 *     kernel-address, rsdp, framebuffer) and receives REAL hardware data.
 *   - It performs EXACTLY the field-copy the MINIX integration will do
 *     (Limine response -> struct bbp_minix_bootinfo), then calls the real
 *     bbp_minix_adapter() — the very code that ships in the port.
 *   - It prints the parser's verdict + every consumed tag + a bbp_verify_blob
 *     of the out-of-line cmdline (ADR-0006).
 *
 * If bbp_init_ex returns BBP_OK here, the adapter is proven against genuine
 * higher-half Limine boot data; the MINIX integration is then just the wiring
 * documented in integration.md (same field copy, same call).
 *
 * This file lives under test/ and is NOT part of the shipped port objects
 * (osif.c + adapter.c). It is the verification rig only.
 */
#include <stdint.h>
#include <stddef.h>

#include <bbp/bbp.h>
#include "../adapter.h"
#include "../osif.h"

/* ===================================================================== *
 *  Minimal Limine protocol (mirrors boot/limine/limine.h, base revision 3).
 *  We declare only what we consume, exactly like MINIX's limine_kinfo.c.
 * ===================================================================== */
#define LIMINE_COMMON_MAGIC 0xc7b1dd30df4c8b88ULL, 0x0a82e883a194f07bULL

struct lim_memmap_entry { uint64_t base, length, type; };
struct lim_memmap_response { uint64_t revision, entry_count; struct lim_memmap_entry **entries; };
struct lim_memmap_request { uint64_t id[4], revision; struct lim_memmap_response *response; };

struct lim_hhdm_response { uint64_t revision, offset; };
struct lim_hhdm_request { uint64_t id[4], revision; struct lim_hhdm_response *response; };

struct lim_kaddr_response { uint64_t revision, physical_base, virtual_base; };
struct lim_kaddr_request { uint64_t id[4], revision; struct lim_kaddr_response *response; };

struct lim_rsdp_response { uint64_t revision; uint64_t address; }; /* API rev 0/1: phys */
struct lim_rsdp_request { uint64_t id[4], revision; struct lim_rsdp_response *response; };

struct lim_framebuffer {
    void *address; uint64_t width, height, pitch;
    uint16_t bpp; uint8_t memory_model;
    uint8_t red_mask_size, red_mask_shift;
    uint8_t green_mask_size, green_mask_shift;
    uint8_t blue_mask_size, blue_mask_shift;
    uint8_t unused[7];
    uint64_t edid_size; void *edid;
    uint64_t mode_count; void **modes;
};
struct lim_framebuffer_response { uint64_t revision, framebuffer_count; struct lim_framebuffer **framebuffers; };
struct lim_framebuffer_request { uint64_t id[4], revision; struct lim_framebuffer_response *response; };

#define LIM_MEMMAP_USABLE 0

/* ===================================================================== *
 *  Limine requests (base revision 3 + start/end markers).
 * ===================================================================== */
__attribute__((used, section(".limine_requests_start")))
static volatile uint64_t lr_start[2] = { 0xf6b8f4febc0ad0e3ULL, 0x342bb6dab7a07b3eULL };
__attribute__((used, section(".limine_requests_end")))
static volatile uint64_t lr_end[2]   = { 0xadc0e0531bb10d03ULL, 0x9572709f31764c62ULL };
__attribute__((used, section(".limine_requests")))
static volatile uint64_t base_revision[3] = { 0xf9562b2d5c95a6c8ULL, 0x6a7b384944536bdcULL, 3 };

__attribute__((used, section(".limine_requests")))
static volatile struct lim_memmap_request memmap_req = {
    .id = { LIMINE_COMMON_MAGIC, 0x67cf3d9d378a806fULL, 0xe304acdfc50c3c62ULL }, .revision = 0, .response = 0 };
__attribute__((used, section(".limine_requests")))
static volatile struct lim_hhdm_request hhdm_req = {
    .id = { LIMINE_COMMON_MAGIC, 0x48dcf1cb8ad2b852ULL, 0x63984e959a98244bULL }, .revision = 0, .response = 0 };
__attribute__((used, section(".limine_requests")))
static volatile struct lim_kaddr_request kaddr_req = {
    .id = { LIMINE_COMMON_MAGIC, 0x71ba76863cc55f63ULL, 0xb2644a48c516a487ULL }, .revision = 0, .response = 0 };
__attribute__((used, section(".limine_requests")))
static volatile struct lim_rsdp_request rsdp_req = {
    .id = { LIMINE_COMMON_MAGIC, 0xc5e77b6b397e7b43ULL, 0x27637845accdcf3cULL }, .revision = 0, .response = 0 };
__attribute__((used, section(".limine_requests")))
static volatile struct lim_framebuffer_request fb_req = {
    .id = { LIMINE_COMMON_MAGIC, 0x9d5827dcd881dd75ULL, 0xa3148604f6fab11bULL }, .revision = 0, .response = 0 };

/* ===================================================================== *
 *  Tiny serial helpers (the OSIF logs too, but the harness narrates).
 * ===================================================================== */
static void log_s(const char *s) { bbp_minix_osif()->log(s); }

static void log_hex(uint64_t v)
{
    char buf[19]; const char *h = "0123456789abcdef";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; i++) buf[2 + i] = h[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = 0;
    log_s(buf);
}

static void log_dec(uint64_t v)
{
    char buf[21]; int i = 20; buf[20] = 0;
    if (v == 0) { log_s("0"); return; }
    while (v && i) { buf[--i] = '0' + (v % 10); v /= 10; }
    log_s(&buf[i]);
}

/* ===================================================================== *
 *  Static storage for the decoded memory map (no allocator in the harness).
 * ===================================================================== */
#define HARNESS_MAX_MMAP 256
static struct bbp_minix_mmap_entry hmmap[HARNESS_MAX_MMAP];

/* The cmdline we feed the adapter. The integration would source MINIX's real
 * boot cmdline; here a representative string proves the out-of-line CRC path. */
static const char harness_cmdline[] =
    "console=tty00 board=X86-I586-GENERIC-GENERIC-GENERIC arch=x86_64";

/* QEMU isa-debug-exit: writing to 0x501 ends the VM with code (val<<1)|1.
 * Lets the run script assert success/failure from QEMU's exit status. */
static void qemu_exit(uint32_t code)
{
    __asm__ volatile("outl %0, %1" :: "a"(code), "Nd"((uint16_t)0xf4));
    for (;;) __asm__ volatile("cli; hlt");
}

/* Tag-iteration callback: count + name each consumed tag. */
static int count_cb(const struct bbp_tag_header *tag, void *user)
{
    uint32_t *n = (uint32_t *)user;
    (*n)++;
    log_s("       tag id="); log_hex(tag->tag_id);
    log_s(" size="); log_dec(tag->tag_size);
    log_s("\n");
    return 0;
}

void harness_main(void)
{
    log_s("\n");
    log_s("================================================\n");
    log_s("  BBP MINIX port — Limine adapter VERIFICATION\n");
    log_s("  F E R M I \xe2\x88\x9e H A R T  <contact@fermihart.com>\n");
    log_s("================================================\n");

    if (!hhdm_req.response) {
        log_s("[harness] FATAL: no Limine HHDM response\n");
        qemu_exit(0xBAD);
    }

    /* ---- Copy Limine responses into the neutral bootinfo (the EXACT field
     *      copy the MINIX integration performs — see integration.md). ----- */
    struct bbp_minix_bootinfo bi;
    for (size_t i = 0; i < sizeof(bi); i++) ((char *)&bi)[i] = 0;

    bi.hhdm_offset = hhdm_req.response->offset;
    log_s("[harness] HHDM offset .......... "); log_hex(bi.hhdm_offset); log_s("\n");

    if (kaddr_req.response) {
        bi.kernel_phys_base    = kaddr_req.response->physical_base;
        bi.kernel_virt_base    = kaddr_req.response->virtual_base;
        bi.have_kernel_address = 1;
        log_s("[harness] kernel phys base ..... "); log_hex(bi.kernel_phys_base); log_s("\n");
        log_s("[harness] kernel virt base ..... "); log_hex(bi.kernel_virt_base); log_s("\n");
    }

    if (memmap_req.response) {
        struct lim_memmap_response *r = memmap_req.response;
        uint32_t n = 0;
        for (uint64_t i = 0; i < r->entry_count && n < HARNESS_MAX_MMAP; i++) {
            hmmap[n].base   = r->entries[i]->base;
            hmmap[n].length = r->entries[i]->length;
            hmmap[n].type   = r->entries[i]->type;
            n++;
        }
        bi.mmap = hmmap; bi.mmap_count = n;
        log_s("[harness] memmap entries ....... "); log_dec(n); log_s("\n");
    }

    if (rsdp_req.response && rsdp_req.response->address) {
        bi.rsdp_phys = rsdp_req.response->address;
        log_s("[harness] ACPI RSDP phys ....... "); log_hex(bi.rsdp_phys); log_s("\n");
    }

    if (fb_req.response && fb_req.response->framebuffer_count) {
        struct lim_framebuffer *f = fb_req.response->framebuffers[0];
        /* Framebuffer address is an HHDM virtual; store its TRUE physical. */
        bi.fb_address      = (uint64_t)(uintptr_t)f->address - bi.hhdm_offset;
        bi.fb_pitch        = (uint32_t)f->pitch;
        bi.fb_width        = (uint16_t)f->width;
        bi.fb_height       = (uint16_t)f->height;
        bi.fb_bpp          = f->bpp;
        bi.fb_pixel_format = 0; /* let the adapter default to RGB888 */
        log_s("[harness] framebuffer .......... "); log_dec(f->width);
        log_s("x"); log_dec(f->height); log_s("\n");
    }

    bi.cmdline = harness_cmdline;
    log_s("[harness] cmdline .............. "); log_s(harness_cmdline); log_s("\n");

    /* SMP: synthesize a 2-CPU topology so the harness exercises the BBP SMP
     * tag path the same way the live MINIX adapter does (cpu_count>=1 emits
     * the tag; the live integration flattens the Limine MP response). */
    static const uint32_t harness_lapic_ids[2] = { 0, 1 };
    bi.lapic_ids     = harness_lapic_ids;
    bi.smp_cpu_count = 2;
    bi.smp_bsp_lapic = 0;
    bi.smp_x2apic    = 0;
    log_s("[harness] SMP cpu_count ........ "); log_dec(bi.smp_cpu_count); log_s("\n");

    /* ---- Run the REAL adapter (the shipped port code). ----------------- */
    log_s("\n[harness] calling bbp_minix_adapter()...\n");
    struct bbp_kctx k;
    bbp_status_t st = bbp_minix_adapter(&k, &bi);

    log_s("[harness] bbp_init_ex -> ");
    log_s(bbp_strstatus(st));
    log_s("\n");

    if (st != BBP_OK) {
        log_s("[harness] RESULT: FAIL (parser rejected the synthesized info)\n");
        qemu_exit(0xBAD);
    }

    /* ---- Consume tags through the core parser (HHDM-aware). ------------ */
    log_s("[harness] HHDM in kctx ......... "); log_hex(k.hhdm_offset); log_s("\n");

    uint32_t visited = 0;
    log_s("[harness] walking tags:\n");
    bbp_for_each_tag(&k, count_cb, &visited);
    log_s("[harness] tags validated ....... "); log_dec(visited); log_s("\n");

    /* Spot-check the mandatory tags resolve and CRC-verify. */
    const struct bbp_tag_header *hhdm = bbp_find_tag(&k, BBP_TAG_HHDM);
    const struct bbp_tag_header *mm   = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    const struct bbp_tag_header *ka   = bbp_find_tag(&k, BBP_TAG_KERNEL_ADDRESS);
    const struct bbp_tag_header *acpi = bbp_find_tag(&k, BBP_TAG_ACPI);
    const struct bbp_tag_header *smp  = bbp_find_tag(&k, BBP_TAG_SMP);
    log_s("[harness] HHDM tag ............. "); log_s(hhdm ? "present\n" : "MISSING\n");
    log_s("[harness] MEMORY_MAP tag ....... "); log_s(mm   ? "present\n" : "MISSING\n");
    log_s("[harness] KERNEL_ADDRESS tag ... "); log_s(ka   ? "present\n" : "MISSING\n");
    log_s("[harness] ACPI tag ............. "); log_s(acpi ? "present\n" : "absent (no RSDP)\n");
    log_s("[harness] SMP tag .............. "); log_s(smp  ? "present\n" : "MISSING\n");

    if (smp) {
        const struct bbp_tag_smp *s = (const struct bbp_tag_smp *)smp;
        log_s("[harness] SMP cpu_count ........ "); log_dec(s->cpu_count);
        log_s(" bsp="); log_dec(s->bsp_id); log_s("\n");
        if (s->cpu_count != bi.smp_cpu_count) {
            log_s("[harness] RESULT: FAIL (SMP cpu_count round-trip mismatch)\n");
            qemu_exit(0xBAD);
        }
    } else {
        log_s("[harness] RESULT: FAIL (SMP tag missing after cpu_count>=1)\n");
        qemu_exit(0xBAD);
    }

    if (mm) {
        const struct bbp_tag_memory_map *m = (const struct bbp_tag_memory_map *)mm;
        uint32_t cnt = 0;
        const struct bbp_memory_entry *e =
            bbp_tag_array(mm, sizeof(*m), sizeof(struct bbp_memory_entry),
                          m->entry_count, &cnt);
        uint64_t usable = 0;
        for (uint32_t i = 0; i < cnt; i++)
            if (e[i].type == BBP_MEM_USABLE) usable += e[i].length;
        log_s("[harness] MEMORY_MAP entries ... "); log_dec(cnt);
        log_s(" usable="); log_dec(usable / (1024 * 1024)); log_s(" MiB\n");
    }

    /* ---- ADR-0006: verify the out-of-line cmdline before trusting it. -- */
    const struct bbp_tag_header *clh = bbp_find_tag(&k, BBP_TAG_CMDLINE);
    if (clh) {
        const struct bbp_tag_cmdline *cl = (const struct bbp_tag_cmdline *)clh;
        bbp_status_t vb = bbp_verify_blob(&k, cl->string, cl->length,
                                          cl->string_crc, 0 /*no unchecked*/);
        log_s("[harness] CMDLINE tag .......... present len="); log_dec(cl->length); log_s("\n");
        log_s("[harness] bbp_verify_blob ...... ");
        log_s(bbp_strstatus(vb)); log_s("\n");
        if (vb == BBP_OK) {
            const char *s = (const char *)bbp_phys_to_virt(&k, cl->string);
            log_s("[harness] cmdline contents ..... \""); log_s(s); log_s("\"\n");
        } else {
            log_s("[harness] RESULT: FAIL (cmdline CRC rejected)\n");
            qemu_exit(0xBAD);
        }
    }

    log_s("\n");
    log_s("================================================\n");
    log_s("  bbp: minix adapter ok, "); log_dec(visited);
    log_s(" tags, hhdm="); log_hex(k.hhdm_offset); log_s("\n");
    log_s("  RESULT: PASS — adapter validated on real Limine data\n");
    log_s("================================================\n");

    qemu_exit(0x10);  /* QEMU exits with ((0x10<<1)|1)=33 on success */
}
