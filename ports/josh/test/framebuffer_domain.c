/* Regression test: Josh glue must convert Limine's HHDM framebuffer pointer
 * to the physical address required by struct bbp_tag_framebuffer. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <bbp/bbp.h>
#include <kernel/boot/limine.h>
#include "../adapter.h"

#define POOL_PHYS 0x02000000ULL
#define FB_PHYS   0xfd000000ULL

static unsigned char pool[128u * 1024u] __attribute__((aligned(4096)));
static size_t pool_used;
uint64_t g_hhdm_offset;

static struct limine_framebuffer framebuffer;
static struct limine_framebuffer *framebuffers[] = { &framebuffer };
static struct limine_framebuffer_response framebuffer_response = {
    .framebuffer_count = 1,
    .framebuffers = framebuffers,
};

uint64_t limine_get_hhdm_offset(void) { return g_hhdm_offset; }
struct limine_memmap_response *limine_get_memmap(void) { return NULL; }
struct limine_framebuffer_response *limine_get_framebuffer(void)
{
    return &framebuffer_response;
}
struct limine_smp_response *limine_get_smp(void) { return NULL; }

void kserial_puts(const char *s) { (void)s; }
void kserial_puthex(uint64_t value) { (void)value; }

__attribute__((noreturn)) void kpanic(const char *msg)
{
    fprintf(stderr, "PANIC: %s\n", msg ? msg : "(null)");
    exit(2);
}

uint64_t pmm_alloc_pages(unsigned char order)
{
    size_t bytes = ((size_t)1 << order) * 4096u;
    size_t start = (pool_used + 4095u) & ~(size_t)4095u;
    if (start > sizeof(pool) || bytes > sizeof(pool) - start)
        return 0;
    pool_used = start + bytes;
    return POOL_PHYS + start;
}

extern int bbp_josh_init(void);
extern const struct bbp_kctx *bbp_josh_context(void);

int main(void)
{
    g_hhdm_offset = (uint64_t)(uintptr_t)pool - POOL_PHYS;
    framebuffer.address = (void *)(uintptr_t)(FB_PHYS + g_hhdm_offset);
    framebuffer.width = 1024;
    framebuffer.height = 768;
    framebuffer.pitch = 4096;
    framebuffer.bpp = 32;

    if (bbp_josh_init() != BBP_OK) {
        fprintf(stderr, "Josh adapter rejected synthetic snapshot\n");
        return 1;
    }

    const struct bbp_kctx *ctx = bbp_josh_context();
    const struct bbp_tag_framebuffer *tag = ctx
        ? (const struct bbp_tag_framebuffer *)bbp_find_tag(ctx, BBP_TAG_FRAMEBUFFER)
        : NULL;
    if (!tag) {
        fprintf(stderr, "FRAMEBUFFER tag missing\n");
        return 1;
    }
    if (tag->address != FB_PHYS) {
        fprintf(stderr, "FRAMEBUFFER address domain mismatch: got 0x%llx, expected physical 0x%llx\n",
                (unsigned long long)tag->address,
                (unsigned long long)FB_PHYS);
        return 1;
    }

    framebuffer.address = (void *)(uintptr_t)(g_hhdm_offset - 1u);
    if (bbp_josh_init() != BBP_OK) {
        fprintf(stderr, "Josh adapter rejected snapshot with omitted framebuffer\n");
        return 1;
    }
    ctx = bbp_josh_context();
    tag = ctx ? (const struct bbp_tag_framebuffer *)bbp_find_tag(
                    ctx, BBP_TAG_FRAMEBUFFER) : NULL;
    if (tag != NULL) {
        fprintf(stderr, "FRAMEBUFFER tag retained an address below the HHDM\n");
        return 1;
    }

    puts("Josh framebuffer physical/HHDM domain regression: PASS");
    return 0;
}
