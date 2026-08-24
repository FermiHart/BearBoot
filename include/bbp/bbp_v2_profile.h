/* Experimental BBP v2 Profile 0 semantics. Not a frozen wire ABI. */
#ifndef BBP_V2_PROFILE_H
#define BBP_V2_PROFILE_H
#include <bbp/bbp_v2.h>
#define BBP_V2_P0_BOOT_IDENTITY  0x4242503200000001ull
#define BBP_V2_P0_MEMORY_MAP     0x4242503200000002ull
#define BBP_V2_P0_KERNEL_ADDRESS 0x4242503200000003ull
#define BBP_V2_P0_DEVICETREE     0x4242503200000004ull
#define BBP_V2_P0_VERSION 1u
#define BBP_V2_P0_MEMORY_ENTRY_SIZE 32u
struct bbp_v2_p0_identity { uint16_t architecture, reserved0; uint32_t cpu_count, flags, reserved1; } __attribute__((packed));
struct bbp_v2_p0_memory_header { uint32_t entry_count, entry_size; } __attribute__((packed));
struct bbp_v2_p0_memory_entry { uint64_t base, length; uint32_t type, attributes, numa_node, reserved; } __attribute__((packed));
struct bbp_v2_p0_kernel_address { uint64_t physical_base, virtual_base; } __attribute__((packed));
struct bbp_v2_p0_devicetree_header { uint32_t flags, dtb_size; } __attribute__((packed));
_Static_assert(sizeof(struct bbp_v2_p0_identity) == 16, "p0 identity ABI");
_Static_assert(sizeof(struct bbp_v2_p0_memory_entry) == 32, "p0 memory entry ABI");
_Static_assert(sizeof(struct bbp_v2_p0_kernel_address) == 16, "p0 kernel ABI");
struct bbp_v2_p0_view { uint16_t architecture; uint32_t cpu_count, memory_entry_count; uint64_t kernel_physical_base, kernel_virtual_base; const uint8_t *dtb; uint32_t dtb_size; };
bbp_v2_status_t bbp_v2_p0_validate(const struct bbp_v2_view *, struct bbp_v2_p0_view *);
#endif
