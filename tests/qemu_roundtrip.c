/*
 * qemu_roundtrip.c — bare-metal BBP round-trip, bootable by `qemu -kernel`.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * A 32-bit Multiboot1 kernel that exercises the SAME bbp_build.c (producer)
 * and bbp_kernel.c (consumer) code that ships in the protocol, on real
 * hardware (QEMU), and prints the verdict to COM1. This is the dynamic proof
 * that complements the hosted self-test: the parser validates a
 * builder-produced info+tag list at runtime, on bare metal, identity-mapped.
 *
 * Boot: multiboot1 -> _start (asm) -> kmain. Serial 0x3F8. On success it
 * prints "BBP-QEMU: PASS" and halts; any failure prints "FAIL: <why>".
 */
#include <stdint.h>
#include <stddef.h>

#include <bbp/bbp.h>
#include <bbp/bbp_crc64.h>
#include "../bootloader/bbp_build.h"
#include "../kernel/bbp_kernel.h"

/* ---- COM1 serial ---------------------------------------------------------*/
static inline void outb(uint16_t p, uint8_t v){ __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p)); }
static inline uint8_t inb(uint16_t p){ uint8_t r; __asm__ volatile("inb %1,%0":"=a"(r):"Nd"(p)); return r; }

static void serial_init(void){
    outb(0x3F8+1,0x00); outb(0x3F8+3,0x80); outb(0x3F8+0,0x01);
    outb(0x3F8+1,0x00); outb(0x3F8+3,0x03); outb(0x3F8+2,0xC7); outb(0x3F8+4,0x0B);
}
static void sputc(char c){ while(!(inb(0x3F8+5)&0x20)){} outb(0x3F8,(uint8_t)c); }
static void sputs(const char*s){ while(*s){ if(*s=='\n') sputc('\r'); sputc(*s++);} }
static void shex(uint64_t v){ sputs("0x"); for(int i=60;i>=0;i-=4){ sputc("0123456789abcdef"[(v>>i)&0xF]); } }

/* ---- the round-trip ------------------------------------------------------*/
static uint8_t arena[32*1024] __attribute__((aligned(16)));

static int fail(const char*why){ sputs("BBP-QEMU: FAIL: "); sputs(why); sputs("\n"); return 0; }

void kmain(void){
    serial_init();
    sputs("BBP-QEMU: boot ok, running round-trip\n");

    /* CRC self-check vector first. */
    if (bbp_crc64("123456789",9) != 0x995DC9BBDF1939FAULL){ fail("crc vector"); goto halt; }

    struct bbp_info *info = (struct bbp_info*)arena;
    for (size_t i=0;i<sizeof(arena);i++) arena[i]=0;

    struct bbp_builder b;
    bbp_builder_init(&b, arena+sizeof(struct bbp_info),
                     (bbp_phys_t)(uintptr_t)(arena+sizeof(struct bbp_info)),
                     sizeof(arena)-sizeof(struct bbp_info));

    struct bbp_tag_hhdm *h = bbp_alloc_tag(&b,BBP_TAG_HHDM,1,sizeof(*h));
    h->offset = 0;
    size_t mmsz = sizeof(struct bbp_tag_memory_map)+2*sizeof(struct bbp_memory_entry);
    struct bbp_tag_memory_map *mm = bbp_alloc_tag(&b,BBP_TAG_MEMORY_MAP,1,mmsz);
    mm->entry_count=2; mm->entry_size=sizeof(struct bbp_memory_entry);
    struct bbp_memory_entry *e=(struct bbp_memory_entry*)((uint8_t*)mm+sizeof(*mm));
    e[0].base=0x1000; e[0].length=0x9F000; e[0].type=BBP_MEM_USABLE;
    e[1].base=0x100000; e[1].length=0x7F00000; e[1].type=BBP_MEM_USABLE;
    struct bbp_tag_acpi *a = bbp_alloc_tag(&b,BBP_TAG_ACPI,1,sizeof(*a));
    a->rsdp_address=0xE0000; a->acpi_version=0x0604;

    bbp_builder_finalize(&b, info, (bbp_phys_t)(uintptr_t)info);
    if (b.overflow){ fail("arena overflow"); goto halt; }

    struct bbp_kctx k;
    bbp_status_t st = bbp_init(&k, info);
    if (st != BBP_OK){ fail(bbp_strstatus(st)); goto halt; }

    const struct bbp_tag_header *t = bbp_find_tag(&k, BBP_TAG_MEMORY_MAP);
    if (!t){ fail("no memmap"); goto halt; }
    uint32_t n=0;
    const struct bbp_memory_entry *me=(const struct bbp_memory_entry*)
        bbp_tag_array(t,sizeof(struct bbp_tag_memory_map),
                      sizeof(struct bbp_memory_entry),
                      ((const struct bbp_tag_memory_map*)t)->entry_count,&n);
    if (n!=2){ fail("memmap count"); goto halt; }
    sputs("BBP-QEMU: memmap entries="); shex(n);
    sputs(" base0="); shex(me[0].base); sputs("\n");

    t = bbp_find_tag(&k, BBP_TAG_ACPI);
    if (!t || ((const struct bbp_tag_acpi*)t)->rsdp_address != 0xE0000){ fail("acpi"); goto halt; }

    /* Adversarial in situ: corrupt the ACPI tag, must now be rejected. */
    a->rsdp_address = 0xDEAD;
    if (bbp_find_tag(&k, BBP_TAG_ACPI) != NULL){ fail("corrupt-not-rejected"); goto halt; }

    sputs("BBP-QEMU: PASS\n");
halt:
    /* Signal QEMU to exit via isa-debug-exit (port 0xF4) if present, else hlt.*/
    outb(0xF4, 0x00);
    for(;;) __asm__ volatile("hlt");
}
