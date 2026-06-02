/*
 * bbp.h — Bear Boot Protocol (BBP) v1.0  —  canonical ABI contract.
 *
 *   Author: F E R M I  ∞  H A R T  <contact@fermihart.com>
 *   SPDX-License-Identifier: BSD-3-Clause
 *
 * BBP is a tag-based, UUID-versioned, multi-architecture boot protocol with
 * native measured-boot, observability and CRC64-checksummed structures.
 * It descends from the Aether Boot Protocol draft, rebranded and hardened
 * into a stable on-the-wire ABI shared between an UEFI/BIOS bootloader and a
 * (possibly higher-half) kernel.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * ABI RULES (read before touching any struct below):
 *
 *   1. Every structure crossing the bootloader→kernel boundary is laid out
 *      explicitly and guarded by _Static_assert(sizeof == N). Reordering or
 *      resizing a field is a BREAKING change and bumps version_major.
 *
 *   2. Fields are ordered widest-first so the struct is naturally aligned
 *      even though it is marked packed. There is NO implicit padding — any
 *      pad is a named `reserved*` field, always zero.
 *
 *   3. All multi-byte values are LITTLE-ENDIAN on the wire (x86_64/AArch64/
 *      RISC-V LE). A big-endian target must byteswap.
 *
 *   4. Enumerations describe *constants only*. They are NEVER used as a
 *      struct field type (enum width is implementation-defined). Fields that
 *      carry an enum value are declared as fixed-width integers.
 *
 *   5. Pointers stored in tags (next_tag, first_tag, *_address, data...) are
 *      PHYSICAL addresses (bbp_phys_t). A higher-half kernel must add the
 *      HHDM offset (see BBP_TAG_HHDM) before dereferencing them once it is
 *      on its own page tables. Use the kernel-side parser in kernel/bbp.c
 *      which does this for you.
 * ───────────────────────────────────────────────────────────────────────── */
#ifndef BBP_H
#define BBP_H

#include <stdint.h>
#include <stddef.h>

/* ========================================================================
 * PROTOCOL VERSION
 * ======================================================================== */
#define BBP_VERSION_MAJOR  1
#define BBP_VERSION_MINOR  1  /* v1.1: per-reference CRC for out-of-line data (ADR-0006) */

/* 16-byte magics. The string literals below are placed into magic[16]
 * fields, which zero-fills the trailing bytes; comparison is over all 16
 * bytes (high entropy → no false match when the bootloader scans .bbp_hdr). */
#define BBP_HEADER_MAGIC   "BEAR_BOOT"   /* kernel .bbp_hdr section */
#define BBP_INFO_MAGIC     "BEAR_INFO"   /* bootloader handoff struct */
#define BBP_MAGIC_LEN      16

/* ========================================================================
 * BASE TYPES
 * ======================================================================== */
typedef uint64_t bbp_phys_t;     /* Physical address */
typedef uint64_t bbp_virt_t;     /* Virtual address  */
typedef uint64_t bbp_uuid_t[2];  /* 128-bit UUID     */

/* ========================================================================
 * ARCHITECTURE / PAGING ENUMS (constants only — stored as fixed-width)
 * ======================================================================== */
enum {
    BBP_ARCH_X86_64    = 1,
    BBP_ARCH_AARCH64   = 2,
    BBP_ARCH_RISCV64   = 3,
    BBP_ARCH_LOONGARCH = 4,
};

enum {
    BBP_PAGING_NONE   = 0,
    BBP_PAGING_4LEVEL = 1,
    BBP_PAGING_5LEVEL = 2,
};

/* ========================================================================
 * TAG IDENTIFIERS
 *   bits [63:48] = category | bits [47:0] = id within category
 * ======================================================================== */
#define BBP_TAG_ID(cat, id) (((uint64_t)(cat) << 48) | (uint64_t)(id))

/* Categories */
#define BBP_CAT_CORE       0x0001
#define BBP_CAT_MEMORY     0x0002
#define BBP_CAT_DEVICE     0x0003
#define BBP_CAT_SECURITY   0x0004
#define BBP_CAT_PLATFORM   0x0005
#define BBP_CAT_DEBUG      0x0006
#define BBP_CAT_VENDOR     0xFFFF

/* Canonical tag UUIDs */
#define BBP_TAG_SMP            BBP_TAG_ID(BBP_CAT_CORE,     0x0001)
#define BBP_TAG_MODULES        BBP_TAG_ID(BBP_CAT_CORE,     0x0002)
#define BBP_TAG_CMDLINE        BBP_TAG_ID(BBP_CAT_CORE,     0x0003)

#define BBP_TAG_MEMORY_MAP     BBP_TAG_ID(BBP_CAT_MEMORY,   0x0001)
#define BBP_TAG_HHDM           BBP_TAG_ID(BBP_CAT_MEMORY,   0x0002)
#define BBP_TAG_KERNEL_ADDRESS BBP_TAG_ID(BBP_CAT_MEMORY,   0x0003)

#define BBP_TAG_FRAMEBUFFER    BBP_TAG_ID(BBP_CAT_DEVICE,   0x0001)
#define BBP_TAG_PCIE           BBP_TAG_ID(BBP_CAT_DEVICE,   0x0002)

#define BBP_TAG_SECURITY       BBP_TAG_ID(BBP_CAT_SECURITY, 0x0001)

#define BBP_TAG_ACPI           BBP_TAG_ID(BBP_CAT_PLATFORM, 0x0001)
#define BBP_TAG_DEVICETREE     BBP_TAG_ID(BBP_CAT_PLATFORM, 0x0002)
#define BBP_TAG_EFI            BBP_TAG_ID(BBP_CAT_PLATFORM, 0x0003)
#define BBP_TAG_HYPERVISOR     BBP_TAG_ID(BBP_CAT_PLATFORM, 0x0004)
#define BBP_TAG_SMBIOS         BBP_TAG_ID(BBP_CAT_PLATFORM, 0x0005)

#define BBP_TAG_METRICS        BBP_TAG_ID(BBP_CAT_DEBUG,    0x0001)

/* ========================================================================
 * KERNEL REQUEST TAGS
 *   The kernel publishes an array of these (pointed to by bbp_header.requests)
 *   declaring which tags it wants the bootloader to produce.
 * ======================================================================== */
struct bbp_tag_request {
    uint64_t tag_id;     /* requested tag UUID */
    uint64_t flags;      /* BBP_REQ_* */
    uint64_t reserved;   /* must be 0 */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_request) == 24, "bbp_tag_request ABI");

#define BBP_REQ_OPTIONAL  (1u << 0)  /* absence is not fatal */
#define BBP_REQ_EXTENDED  (1u << 1)  /* request extended variant */

/* ========================================================================
 * BBP HEADER — emitted by the kernel into section ".bbp_hdr"
 * ======================================================================== */
struct bbp_header {
    uint8_t    magic[16];           /* "BEAR_BOOT" + zero padding */
    uint16_t   version_major;
    uint16_t   version_minor;
    uint32_t   header_size;         /* == sizeof(struct bbp_header) */

    uint64_t   flags;               /* BBP_HF_* */
    bbp_phys_t entry_point;         /* address control transfers to, in the
                                     * kernel's OWN address space: physical for
                                     * a lower-half kernel, virtual for higher-
                                     * half. NOT double-translated. (ADR-0008) */

    uint64_t   paging_mode;         /* BBP_PAGING_* */
    bbp_virt_t kernel_virtual_base; /* desired higher-half base */

    uint32_t   request_count;
    uint32_t   reserved0;           /* must be 0 (alignment) */
    bbp_phys_t requests;            /* phys ptr to bbp_tag_request[] */

    bbp_uuid_t kernel_uuid;         /* 128-bit */
    uint8_t    kernel_name[64];     /* NUL-terminated */

    uint64_t   checksum;            /* CRC64/XZ of header w/ this field = 0 */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_header) == 160, "bbp_header ABI");
_Static_assert(offsetof(struct bbp_header, requests)    == 64,  "bbp_header.requests");
_Static_assert(offsetof(struct bbp_header, kernel_uuid) == 72,  "bbp_header.kernel_uuid");
_Static_assert(offsetof(struct bbp_header, kernel_name) == 88,  "bbp_header.kernel_name");
_Static_assert(offsetof(struct bbp_header, checksum)    == 152, "bbp_header.checksum");

/* Header flags */
#define BBP_HF_HIGH_ENTROPY_KASLR    (1u << 0)
#define BBP_HF_ENABLE_5LEVEL_PAGING  (1u << 1)
#define BBP_HF_UNMAP_NULL_PAGE       (1u << 2)
#define BBP_HF_ENABLE_NX             (1u << 3)
#define BBP_HF_SMP_BOOT_ALL          (1u << 4)
#define BBP_HF_FRAMEBUFFER_WANTED    (1u << 5)

/* ========================================================================
 * BBP INFO — handoff structure passed to the kernel
 *   ptr in RDI (x86_64) / X0 (AArch64) / A0 (RISC-V) at entry.
 * ======================================================================== */
struct bbp_info {
    uint8_t    magic[16];              /* "BEAR_INFO" + zero padding */
    uint16_t   version_major;
    uint16_t   version_minor;
    uint32_t   info_size;              /* total bytes incl. all tags */

    uint8_t    bootloader_name[32];
    uint8_t    bootloader_version[16];
    bbp_uuid_t bootloader_uuid;

    uint64_t   bootloader_start_ts;    /* ns */
    uint64_t   kernel_load_ts;         /* ns */
    uint64_t   handoff_ts;             /* ns */

    uint16_t   architecture;           /* BBP_ARCH_* */
    uint16_t   cpu_count;
    uint32_t   tag_count;
    bbp_phys_t first_tag;              /* phys ptr to first bbp_tag_header */

    bbp_phys_t next_context;           /* boot-chain: next bbp_info, 0=none */
    uint64_t   checksum;               /* CRC64/XZ of this struct, field=0 */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_info) == 144, "bbp_info ABI");
_Static_assert(offsetof(struct bbp_info, first_tag)    == 120, "bbp_info.first_tag");
_Static_assert(offsetof(struct bbp_info, next_context) == 128, "bbp_info.next_context");
_Static_assert(offsetof(struct bbp_info, checksum)     == 136, "bbp_info.checksum");

/* ========================================================================
 * TAG HEADER — every tag starts with this
 * ======================================================================== */
struct bbp_tag_header {
    uint64_t   tag_id;       /* tag UUID */
    uint32_t   tag_size;     /* total size incl. header AND trailing array */
    uint16_t   tag_version;
    uint16_t   flags;        /* BBP_TF_* */
    bbp_phys_t next_tag;     /* phys ptr to next tag, 0 = end of list */
    uint64_t   checksum;     /* CRC64/XZ of whole tag w/ this field = 0 */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_header) == 32, "bbp_tag_header ABI");
_Static_assert(offsetof(struct bbp_tag_header, checksum) == 24, "bbp_tag_header.checksum");

#define BBP_TF_NONE  0u

/* ========================================================================
 * MEMORY MAP  (category MEMORY / 0x0001)
 * ======================================================================== */
enum {
    BBP_MEM_USABLE              = 0x0001,
    BBP_MEM_RESERVED            = 0x0002,
    BBP_MEM_ACPI_RECLAIMABLE    = 0x0003,
    BBP_MEM_ACPI_NVS            = 0x0004,
    BBP_MEM_BAD_MEMORY          = 0x0005,
    BBP_MEM_BOOTLOADER_RECLAIM  = 0x0006,
    BBP_MEM_KERNEL_AND_MODULES  = 0x0007,
    BBP_MEM_FRAMEBUFFER         = 0x0008,
    /* BBP extensions */
    BBP_MEM_PERSISTENT          = 0x0010, /* NVDIMM / PMEM */
    BBP_MEM_DEVICE_IO           = 0x0011, /* device MMIO   */
    BBP_MEM_PCI_ECAM            = 0x0012, /* PCIe ECAM      */
    BBP_MEM_USABLE_WITH_GUARD   = 0x0013,
    BBP_MEM_HOTPLUGGABLE        = 0x0014,
    BBP_MEM_SOFT_RESERVED       = 0x0015,
};

#define BBP_MEM_ATTR_READABLE       (1u << 0)
#define BBP_MEM_ATTR_WRITABLE       (1u << 1)
#define BBP_MEM_ATTR_EXECUTABLE     (1u << 2)
#define BBP_MEM_ATTR_CACHED         (1u << 3)
#define BBP_MEM_ATTR_WRITE_COMBINE  (1u << 4)
#define BBP_MEM_ATTR_UNCACHED       (1u << 5)
#define BBP_MEM_ATTR_ENCRYPTED      (1u << 6)  /* AMD SME / Intel TME */

struct bbp_memory_entry {
    bbp_phys_t base;
    uint64_t   length;
    uint32_t   type;        /* BBP_MEM_* */
    uint32_t   attributes;  /* BBP_MEM_ATTR_* */
    uint32_t   numa_node;
    uint32_t   reserved;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_memory_entry) == 32, "bbp_memory_entry ABI");

struct bbp_tag_memory_map {
    struct bbp_tag_header header;
    uint32_t entry_count;
    uint32_t entry_size;    /* == sizeof(struct bbp_memory_entry) */
    /* followed by bbp_memory_entry[entry_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_memory_map) == 40, "bbp_tag_memory_map ABI");

/* ========================================================================
 * HHDM — Higher-Half Direct Map  (category MEMORY / 0x0002)
 *   The single most important tag for a higher-half kernel: the offset such
 *   that  virt = phys + offset  maps ALL physical RAM. Without it the kernel
 *   cannot walk the (physically-linked) tag list after switching CR3.
 * ======================================================================== */
struct bbp_tag_hhdm {
    struct bbp_tag_header header;
    bbp_virt_t offset;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_hhdm) == 40, "bbp_tag_hhdm ABI");

/* ========================================================================
 * KERNEL ADDRESS  (category MEMORY / 0x0003)
 *   Where the bootloader actually loaded/relocated the kernel. Needed to
 *   undo KASLR slide for symbol resolution and to build kernel page tables.
 * ======================================================================== */
struct bbp_tag_kernel_address {
    struct bbp_tag_header header;
    bbp_phys_t physical_base;
    bbp_virt_t virtual_base;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_kernel_address) == 48, "bbp_tag_kernel_address ABI");

/* ========================================================================
 * FRAMEBUFFER  (category DEVICE / 0x0001)
 * ======================================================================== */
enum {
    BBP_FB_RGB888       = 0x0001,
    BBP_FB_RGBA8888     = 0x0002,
    BBP_FB_BGRA8888     = 0x0003,
    BBP_FB_RGB565       = 0x0004,
    BBP_FB_RGBA1010102  = 0x0010,  /* HDR 10-bit */
    BBP_FB_RGBX_FP16    = 0x0011,  /* fp16        */
    BBP_FB_PLANAR_YUV   = 0x0012,
};

struct bbp_display_info {
    uint16_t   width;
    uint16_t   height;
    uint16_t   refresh_rate;       /* Hz * 100 */
    uint16_t   color_depth;        /* bits per channel */
    uint32_t   pixel_format;       /* BBP_FB_* */
    uint16_t   physical_width_mm;
    uint16_t   physical_height_mm;
    uint16_t   dpi_x;
    uint16_t   dpi_y;
    uint16_t   hdr_capabilities;
    uint16_t   color_space;
    uint8_t    max_luminance;      /* nits / 10 */
    uint8_t    min_luminance;
    uint16_t   reserved;
    uint32_t   edid_size;
    bbp_phys_t edid_data;
    uint64_t   edid_crc;           /* v1.1: CRC-64/XZ of edid_data[edid_size]; 0=unchecked (ADR-0006) */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_display_info) == 48, "bbp_display_info ABI");

#define BBP_FB_FLAG_DOUBLE_BUFFERED  (1u << 0)
#define BBP_FB_FLAG_ROTATED_90       (1u << 1)
#define BBP_FB_FLAG_ROTATED_180      (1u << 2)
#define BBP_FB_FLAG_ROTATED_270      (1u << 3)

struct bbp_tag_framebuffer {
    struct bbp_tag_header header;
    bbp_phys_t address;
    uint16_t   display_count;
    uint16_t   flags;
    uint32_t   pitch;          /* bytes per scanline */
    uint64_t   total_size;
    bbp_phys_t cursor_buffer;  /* hw cursor offload, 0 if none */
    uint32_t   cursor_width;
    uint32_t   cursor_height;
    /* followed by bbp_display_info[display_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_framebuffer) == 72, "bbp_tag_framebuffer ABI");

/* ========================================================================
 * SMP  (category CORE / 0x0001)
 * ======================================================================== */
enum {
    BBP_CPU_STATE_STOPPED  = 0,
    BBP_CPU_STATE_RUNNING  = 1,
    BBP_CPU_STATE_SLEEPING = 2,
    BBP_CPU_STATE_OFFLINE  = 3,
};

struct bbp_cpu_info {
    uint32_t   processor_id;   /* ACPI processor id */
    uint32_t   apic_id;        /* LAPIC id (x86) / MPIDR (ARM) */
    uint16_t   state;          /* BBP_CPU_STATE_* */
    uint16_t   flags;
    uint16_t   package_id;
    uint16_t   core_id;
    uint16_t   thread_id;
    uint16_t   numa_node;
    uint32_t   capabilities;   /* AVX-512 / SVE / ... bitmap */
    uint64_t   clock_frequency;/* Hz, 0 if unknown */
    bbp_phys_t wakeup_vector;  /* AP wakeup mailbox */
    uint64_t   extra_argument; /* passed to AP */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_cpu_info) == 48, "bbp_cpu_info ABI");

struct bbp_tag_smp {
    struct bbp_tag_header header;
    uint32_t   cpu_count;
    uint32_t   bsp_id;         /* bootstrap processor id */
    uint64_t   flags;          /* BBP_SMP_FLAG_* */
    /* followed by bbp_cpu_info[cpu_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_smp) == 48, "bbp_tag_smp ABI");

#define BBP_SMP_FLAG_X2APIC          (1ull << 0)
#define BBP_SMP_FLAG_HOTPLUG_CAPABLE (1ull << 1)
#define BBP_SMP_FLAG_HETEROGENEOUS   (1ull << 2)  /* big.LITTLE */

/* ========================================================================
 * SECURITY — TPM 2.0 / Measured Boot / Secure Boot  (SECURITY / 0x0001)
 * ======================================================================== */
enum {
    BBP_HASH_SHA256   = 0x0001,
    BBP_HASH_SHA384   = 0x0002,
    BBP_HASH_SHA512   = 0x0003,
    BBP_HASH_BLAKE2B  = 0x0004,
    BBP_HASH_BLAKE3   = 0x0005,
    BBP_HASH_SHA3_256 = 0x0006,
};

struct bbp_measurement {
    uint32_t pcr_index;
    uint32_t algorithm;        /* BBP_HASH_* */
    uint8_t  hash[64];         /* up to 512-bit */
    uint32_t hash_length;      /* actual bytes used */
    uint32_t reserved;
    uint8_t  component_name[64]; /* "kernel","initrd","cmdline",... */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_measurement) == 144, "bbp_measurement ABI");

struct bbp_secure_boot_info {
    uint8_t  mode;              /* 0=disabled 1=setup 2=deployed */
    uint8_t  signature_verified;
    uint8_t  pk_present;
    uint8_t  kek_present;
    uint8_t  db_present;
    uint8_t  dbx_present;
    uint16_t reserved;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_secure_boot_info) == 8, "bbp_secure_boot_info ABI");

struct bbp_tag_security {
    struct bbp_tag_header header;
    bbp_phys_t tpm_base_address;
    uint16_t   tpm_version;     /* 0=none 0x0102=1.2 0x0200=2.0 */
    uint16_t   tpm_interface;   /* 0=none 1=TIS 2=CRB 3=MMIO */
    uint32_t   tpm_flags;       /* BBP_TPM_FLAG_* */

    struct bbp_secure_boot_info secure_boot;

    uint32_t   measurement_count;
    uint32_t   reserved0;
    bbp_phys_t measurements;    /* bbp_measurement[] */

    uint32_t   public_key_count;
    uint32_t   reserved1;
    bbp_phys_t public_keys;

    uint32_t   entropy_size;    /* bytes of boot entropy */
    uint32_t   reserved2;
    bbp_phys_t entropy_data;    /* CSPRNG seed for the kernel */

    /* v1.1 (ADR-0006): CRC-64/XZ over each out-of-line blob. 0 = unchecked.
     * A consumer MUST verify measurements_crc before trusting/extending the
     * measurement log. Appended at the end → v1.0 readers ignore them. */
    uint64_t   measurements_crc; /* over measurements[measurement_count] */
    uint64_t   public_keys_crc;  /* over the public_keys blob */
    uint64_t   entropy_crc;      /* over entropy_data[entropy_size] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_security) == 128, "bbp_tag_security ABI");

#define BBP_TPM_FLAG_ACTIVE          (1u << 0)
#define BBP_TPM_FLAG_SUPPORTS_SHA384 (1u << 1)
#define BBP_TPM_FLAG_SUPPORTS_SHA512 (1u << 2)

/* ========================================================================
 * ACPI  (category PLATFORM / 0x0001)
 * ======================================================================== */
struct bbp_tag_acpi {
    struct bbp_tag_header header;
    bbp_phys_t rsdp_address;
    bbp_phys_t xsdt_address;   /* 0 if only RSDT */
    uint32_t   oem_id;
    uint16_t   acpi_version;   /* e.g. 0x0604 = 6.4 */
    uint16_t   flags;          /* BBP_ACPI_FLAG_* */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_acpi) == 56, "bbp_tag_acpi ABI");

#define BBP_ACPI_FLAG_XSDT_AVAILABLE (1u << 0)
#define BBP_ACPI_FLAG_SPCR_AVAILABLE (1u << 1)

/* ========================================================================
 * MODULES  (category CORE / 0x0002)
 * ======================================================================== */
struct bbp_module_entry {
    bbp_phys_t base_address;
    uint64_t   size;
    uint8_t    name[64];
    uint32_t   type;           /* 0=generic 1=initrd 2=firmware 3=dtb */
    uint32_t   flags;
    uint32_t   metadata_size;
    uint32_t   reserved0;
    bbp_phys_t metadata;       /* key=value blob, 0 if none */
    uint32_t   hash_algorithm; /* BBP_HASH_* */
    uint32_t   reserved1;
    uint8_t    hash[64];
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_module_entry) == 176, "bbp_module_entry ABI");

struct bbp_tag_modules {
    struct bbp_tag_header header;
    uint32_t module_count;
    uint32_t reserved;
    /* followed by bbp_module_entry[module_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_modules) == 40, "bbp_tag_modules ABI");

/* ========================================================================
 * CMDLINE  (category CORE / 0x0003)
 * ======================================================================== */
struct bbp_tag_cmdline {
    struct bbp_tag_header header;
    bbp_phys_t string;   /* phys ptr to NUL-terminated UTF-8 */
    uint32_t   length;   /* bytes excl. NUL */
    uint32_t   flags;
    uint64_t   string_crc; /* v1.1: CRC-64/XZ of string[length]; 0=unchecked (ADR-0006) */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_cmdline) == 56, "bbp_tag_cmdline ABI");

/* ========================================================================
 * METRICS — boot observability  (category DEBUG / 0x0001)
 * ======================================================================== */
struct bbp_boot_phase {
    uint8_t  name[32];        /* "firmware","loader","decompress",... */
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t peak_memory;     /* bytes */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_boot_phase) == 56, "bbp_boot_phase ABI");

struct bbp_tag_metrics {
    struct bbp_tag_header header;
    uint64_t total_boot_time_ns;
    uint32_t phase_count;
    uint32_t flags;
    uint64_t bytes_loaded;
    uint64_t decompression_ratio; /* ratio * 1000 */
    uint32_t io_operations;
    uint32_t pages_allocated;
    /* followed by bbp_boot_phase[phase_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_metrics) == 72, "bbp_tag_metrics ABI");

/* ========================================================================
 * DEVICE TREE  (category PLATFORM / 0x0002)
 * ======================================================================== */
struct bbp_tag_devicetree {
    struct bbp_tag_header header;
    bbp_phys_t dtb_address;
    uint32_t   dtb_size;
    uint32_t   flags;
    uint32_t   overlay_count;
    uint32_t   reserved;
    bbp_phys_t overlays;   /* array of {phys base; u64 size} */
    uint64_t   dtb_crc;      /* v1.1: CRC-64/XZ of dtb_address[dtb_size]; 0=unchecked (ADR-0006) */
    uint64_t   overlays_crc; /* v1.1: CRC-64/XZ of the overlays array; 0=unchecked */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_devicetree) == 80, "bbp_tag_devicetree ABI");

/* ========================================================================
 * PCIe TOPOLOGY  (category DEVICE / 0x0002)
 * ======================================================================== */
struct bbp_pcie_bar {
    bbp_phys_t base;
    uint64_t   size;
    uint32_t   flags;
    uint32_t   reserved;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_pcie_bar) == 24, "bbp_pcie_bar ABI");

struct bbp_pcie_device {
    uint16_t segment;
    uint8_t  bus;
    uint8_t  device;
    uint8_t  function;
    uint8_t  reserved0;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code[3];
    uint8_t  revision;
    uint16_t reserved1;
    uint32_t bar_count;
    uint32_t reserved2;
    struct bbp_pcie_bar bars[6];
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_pcie_device) == 168, "bbp_pcie_device ABI");

struct bbp_tag_pcie {
    struct bbp_tag_header header;
    bbp_phys_t ecam_base;
    uint32_t   device_count;
    uint32_t   flags;
    /* followed by bbp_pcie_device[device_count] */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_pcie) == 48, "bbp_tag_pcie ABI");

/* ========================================================================
 * EFI SYSTEM TABLE  (category PLATFORM / 0x0003)
 * ======================================================================== */
struct bbp_tag_efi {
    struct bbp_tag_header header;
    bbp_phys_t system_table;
    bbp_phys_t memory_map;        /* raw UEFI memory map (post ExitBootServices) */
    uint32_t   memory_map_size;
    uint32_t   descriptor_size;
    uint32_t   descriptor_version;
    uint32_t   reserved;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_efi) == 64, "bbp_tag_efi ABI");

/* ========================================================================
 * HYPERVISOR DETECTION  (category PLATFORM / 0x0004)
 * ======================================================================== */
struct bbp_tag_hypervisor {
    struct bbp_tag_header header;
    uint8_t  present;          /* 0/1 (CPUID hypervisor bit) */
    uint8_t  reserved0[7];
    uint8_t  vendor[16];       /* e.g. "KVMKVMKVM\0", "Microsoft Hv" */
    uint32_t max_leaf;         /* CPUID hypervisor max leaf */
    uint32_t reserved1;
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_hypervisor) == 64, "bbp_tag_hypervisor ABI");

/* ========================================================================
 * SMBIOS  (category PLATFORM / 0x0005)
 * ======================================================================== */
struct bbp_tag_smbios {
    struct bbp_tag_header header;
    bbp_phys_t entry_32bit;    /* SMBIOS 32-bit entry point, 0 if none */
    bbp_phys_t entry_64bit;    /* SMBIOS 3.0 64-bit entry point, 0 if none */
} __attribute__((packed));
_Static_assert(sizeof(struct bbp_tag_smbios) == 48, "bbp_tag_smbios ABI");

#endif /* BBP_H */
