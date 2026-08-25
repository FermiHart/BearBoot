#ifndef BBP_JOSH_TEST_LIMINE_H
#define BBP_JOSH_TEST_LIMINE_H

#include <stdint.h>

struct limine_memmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;
};

struct limine_memmap_response {
    uint64_t revision;
    uint64_t entry_count;
    struct limine_memmap_entry **entries;
};

struct limine_framebuffer {
    void *address;
    uint64_t width;
    uint64_t height;
    uint64_t pitch;
    uint16_t bpp;
};

struct limine_framebuffer_response {
    uint64_t revision;
    uint64_t framebuffer_count;
    struct limine_framebuffer **framebuffers;
};

struct limine_smp_info {
    uint32_t processor_id;
    uint32_t lapic_id;
};

struct limine_smp_response {
    uint64_t revision;
    uint32_t flags;
    uint32_t bsp_lapic_id;
    uint64_t cpu_count;
    struct limine_smp_info **cpus;
};

uint64_t limine_get_hhdm_offset(void);
struct limine_memmap_response *limine_get_memmap(void);
struct limine_framebuffer_response *limine_get_framebuffer(void);
struct limine_smp_response *limine_get_smp(void);

#endif
