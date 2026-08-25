/* Process-hosted verification for the MINIX adapter. This uses a synthetic
 * nonzero HHDM snapshot; it is adapter coverage, not evidence of a MINIX boot. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bbp/bbp.h>
#include "../adapter.h"
#include "../osif.h"

#define ARENA_PHYS 0x02000000ULL

static int count_cb(const struct bbp_tag_header *tag, void *user)
{
    (void)tag;
    (*(uint32_t *)user)++;
    return 0;
}

int main(void)
{
    static const struct bbp_minix_mmap_entry mmap[] = {
        { 0x00000000, 0x0009f000, 0 },
        { 0x0009f000, 0x00061000, 1 },
        { 0x00100000, 0x1ff00000, 0 },
        { 0x20000000, 0x00100000, 2 },
        { 0xfd000000, 0x00300000, 7 },
    };
    static const uint32_t lapic_ids[] = { 2, 4 };
    static const uint64_t expected_tags[] = {
        BBP_TAG_HHDM,
        BBP_TAG_MEMORY_MAP,
        BBP_TAG_KERNEL_ADDRESS,
        BBP_TAG_SMP,
        BBP_TAG_ACPI,
        BBP_TAG_FRAMEBUFFER,
        BBP_TAG_CMDLINE,
    };
    static const char cmdline[] = "root=/dev/c0d0p0s0 console=tty00 bbp.hosted=1";

    unsigned long arena_size = 0;
    void *arena = bbp_minix_arena_base(&arena_size);
    uint64_t arena_virt = (uint64_t)(uintptr_t)arena;

    struct bbp_minix_bootinfo bi;
    memset(&bi, 0, sizeof(bi));
    bi.hhdm_offset = arena_virt - ARENA_PHYS;
    bi.kernel_phys_base = ARENA_PHYS;
    bi.kernel_virt_base = arena_virt;
    bi.have_kernel_address = 1;
    bi.mmap = mmap;
    bi.mmap_count = (uint32_t)(sizeof(mmap) / sizeof(mmap[0]));
    bi.rsdp_phys = 0x000f8000;
    bi.fb_address = 0xfd000000;
    bi.fb_pitch = 4096;
    bi.fb_width = 1024;
    bi.fb_height = 768;
    bi.fb_bpp = 32;
    bi.cmdline = cmdline;
    bi.lapic_ids = lapic_ids;
    bi.smp_cpu_count = (uint32_t)(sizeof(lapic_ids) / sizeof(lapic_ids[0]));
    bi.smp_bsp_lapic = 2;

    if (bi.hhdm_offset == 0) {
        fputs("synthetic HHDM unexpectedly zero\n", stderr);
        return 1;
    }

    struct bbp_kctx ctx;
    bbp_status_t status = bbp_minix_adapter(&ctx, &bi);
    if (status != BBP_OK) {
        fprintf(stderr, "bbp_minix_adapter: %s\n", bbp_strstatus(status));
        return 1;
    }
    if (ctx.hhdm_offset != bi.hhdm_offset) {
        fputs("nonzero HHDM snapshot did not round-trip\n", stderr);
        return 1;
    }

    for (size_t i = 0; i < sizeof(expected_tags) / sizeof(expected_tags[0]); i++) {
        if (!bbp_find_tag(&ctx, expected_tags[i])) {
            fprintf(stderr, "expected tag missing: 0x%llx\n",
                    (unsigned long long)expected_tags[i]);
            return 1;
        }
    }
    uint32_t tag_count = 0;
    bbp_for_each_tag(&ctx, count_cb, &tag_count);
    if (tag_count != sizeof(expected_tags) / sizeof(expected_tags[0])) {
        fprintf(stderr, "tag count mismatch: %u\n", tag_count);
        return 1;
    }

    const struct bbp_tag_cmdline *cl =
        (const struct bbp_tag_cmdline *)bbp_find_tag(&ctx, BBP_TAG_CMDLINE);
    status = bbp_verify_blob(&ctx, cl->string, cl->length, cl->string_crc, 0);
    if (status != BBP_OK) {
        fprintf(stderr, "valid cmdline blob rejected: %s\n", bbp_strstatus(status));
        return 1;
    }

    unsigned char *blob = (unsigned char *)bbp_phys_to_virt(&ctx, cl->string);
    unsigned char saved = blob[0];
    blob[0] ^= 0x01;
    status = bbp_verify_blob(&ctx, cl->string, cl->length, cl->string_crc, 0);
    blob[0] = saved;
    if (status != BBP_ERR_TAG_CHECKSUM) {
        fprintf(stderr, "corrupt cmdline blob not rejected: %s\n", bbp_strstatus(status));
        return 1;
    }

    printf("MINIX hosted snapshot: PASS (%u tags, nonzero HHDM, corruption rejected)\n",
           tag_count);
    puts("Scope: synthetic adapter test only; no MINIX boot claim.");
    return 0;
}
