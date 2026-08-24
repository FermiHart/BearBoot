//! Frozen BBP v1.1 envelope layouts.

/// Protocol major version.
pub const VERSION_MAJOR: u16 = 1;
/// Protocol minor version containing per-reference blob CRCs.
pub const VERSION_MINOR: u16 = 1;

/// Exact 16-byte header magic, including required NUL padding.
pub const HEADER_MAGIC: [u8; 16] = *b"BEAR_BOOT\0\0\0\0\0\0\0";
/// Exact 16-byte info magic, including required NUL padding.
pub const INFO_MAGIC: [u8; 16] = *b"BEAR_INFO\0\0\0\0\0\0\0";

/// Frozen header wire size.
pub const HEADER_SIZE: usize = 160;
/// Frozen info wire size.
pub const INFO_SIZE: usize = 144;
/// Frozen tag-header wire size.
pub const TAG_HEADER_SIZE: usize = 32;
/// Defensive maximum accepted informational info span (64 MiB).
pub const MAX_INFO_SIZE: u32 = 64 * 1024 * 1024;
/// Defensive maximum accepted tag span (16 MiB).
pub const MAX_TAG_SIZE: u32 = 16 * 1024 * 1024;
/// Canonical upper bound for a consumer-managed linked-list walk.
pub const MAX_TAGS: u32 = 1024;
/// Defensive maximum blob slice verified by [`crate::verify_blob`] (64 MiB).
pub const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024;

pub const PAGING_NONE: u64 = 0;
pub const PAGING_4LEVEL: u64 = 1;
pub const PAGING_5LEVEL: u64 = 2;

pub const REQ_OPTIONAL: u64 = 1 << 0;
pub const REQ_EXTENDED: u64 = 1 << 1;

pub const HF_HIGH_ENTROPY_KASLR: u64 = 1 << 0;
pub const HF_ENABLE_5LEVEL_PAGING: u64 = 1 << 1;
pub const HF_UNMAP_NULL_PAGE: u64 = 1 << 2;
pub const HF_ENABLE_NX: u64 = 1 << 3;
pub const HF_SMP_BOOT_ALL: u64 = 1 << 4;
pub const HF_FRAMEBUFFER_WANTED: u64 = 1 << 5;

pub const TF_NONE: u16 = 0;

/// Alignment-one, little-endian `u16` wire value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Le16(pub [u8; 2]);

impl Le16 {
    /// Encodes a native integer in little-endian order.
    pub const fn new(value: u16) -> Self {
        Self(value.to_le_bytes())
    }

    /// Decodes this wire value.
    pub const fn get(self) -> u16 {
        u16::from_le_bytes(self.0)
    }
}

impl From<u16> for Le16 {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<Le16> for u16 {
    fn from(value: Le16) -> Self {
        value.get()
    }
}

/// Alignment-one, little-endian `u32` wire value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Le32(pub [u8; 4]);

impl Le32 {
    /// Encodes a native integer in little-endian order.
    pub const fn new(value: u32) -> Self {
        Self(value.to_le_bytes())
    }

    /// Decodes this wire value.
    pub const fn get(self) -> u32 {
        u32::from_le_bytes(self.0)
    }
}

impl From<u32> for Le32 {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<Le32> for u32 {
    fn from(value: Le32) -> Self {
        value.get()
    }
}

/// Alignment-one, little-endian `u64` wire value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Le64(pub [u8; 8]);

impl Le64 {
    /// Encodes a native integer in little-endian order.
    pub const fn new(value: u64) -> Self {
        Self(value.to_le_bytes())
    }

    /// Decodes this wire value.
    pub const fn get(self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl From<u64> for Le64 {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Le64> for u64 {
    fn from(value: Le64) -> Self {
        value.get()
    }
}

/// Opaque physical-address bits from the wire.
///
/// This type intentionally has no conversion to a Rust pointer and makes no
/// claim that the represented address is mapped, aligned, stable, or safe.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PhysicalAddress(pub Le64);

impl PhysicalAddress {
    /// Encodes opaque physical-address bits.
    pub const fn new(value: u64) -> Self {
        Self(Le64::new(value))
    }

    /// Returns the opaque numeric value without dereferencing it.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact alignment-one BBP header wire layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub magic: [u8; 16],
    pub version_major: Le16,
    pub version_minor: Le16,
    pub header_size: Le32,
    pub flags: Le64,
    /// Transfer address in the kernel's own address space; it may be physical
    /// or virtual according to the header's paging contract.
    pub entry_point: Le64,
    pub paging_mode: Le64,
    pub kernel_virtual_base: Le64,
    pub request_count: Le32,
    pub reserved0: Le32,
    pub requests: PhysicalAddress,
    pub kernel_uuid: [Le64; 2],
    pub kernel_name: [u8; 64],
    pub checksum: Le64,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: [0; 16],
            version_major: Le16::default(),
            version_minor: Le16::default(),
            header_size: Le32::default(),
            flags: Le64::default(),
            entry_point: Le64::default(),
            paging_mode: Le64::default(),
            kernel_virtual_base: Le64::default(),
            request_count: Le32::default(),
            reserved0: Le32::default(),
            requests: PhysicalAddress::default(),
            kernel_uuid: [Le64::default(); 2],
            kernel_name: [0; 64],
            checksum: Le64::default(),
        }
    }
}

/// Exact alignment-one BBP info wire layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Info {
    pub magic: [u8; 16],
    pub version_major: Le16,
    pub version_minor: Le16,
    pub info_size: Le32,
    pub bootloader_name: [u8; 32],
    pub bootloader_version: [u8; 16],
    pub bootloader_uuid: [Le64; 2],
    pub bootloader_start_ts: Le64,
    pub kernel_load_ts: Le64,
    pub handoff_ts: Le64,
    pub architecture: Le16,
    pub cpu_count: Le16,
    pub tag_count: Le32,
    pub first_tag: PhysicalAddress,
    pub next_context: PhysicalAddress,
    pub checksum: Le64,
}

/// Exact alignment-one generic BBP tag-header wire layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TagHeader {
    pub tag_id: Le64,
    pub tag_size: Le32,
    pub tag_version: Le16,
    pub flags: Le16,
    pub next_tag: PhysicalAddress,
    pub checksum: Le64,
}

/// Encodes a category and category-local identifier as a BBP tag ID.
pub const fn tag_id(category: u16, id: u64) -> u64 {
    ((category as u64) << 48) | id
}

pub const CAT_CORE: u16 = 0x0001;
pub const CAT_MEMORY: u16 = 0x0002;
pub const CAT_DEVICE: u16 = 0x0003;
pub const CAT_SECURITY: u16 = 0x0004;
pub const CAT_PLATFORM: u16 = 0x0005;
pub const CAT_DEBUG: u16 = 0x0006;
pub const CAT_VENDOR: u16 = 0xFFFF;

pub const TAG_SMP: u64 = tag_id(CAT_CORE, 0x0001);
pub const TAG_MODULES: u64 = tag_id(CAT_CORE, 0x0002);
pub const TAG_CMDLINE: u64 = tag_id(CAT_CORE, 0x0003);
pub const TAG_MEMORY_MAP: u64 = tag_id(CAT_MEMORY, 0x0001);
pub const TAG_HHDM: u64 = tag_id(CAT_MEMORY, 0x0002);
pub const TAG_KERNEL_ADDRESS: u64 = tag_id(CAT_MEMORY, 0x0003);
pub const TAG_FRAMEBUFFER: u64 = tag_id(CAT_DEVICE, 0x0001);
pub const TAG_PCIE: u64 = tag_id(CAT_DEVICE, 0x0002);
pub const TAG_SECURITY: u64 = tag_id(CAT_SECURITY, 0x0001);
pub const TAG_ACPI: u64 = tag_id(CAT_PLATFORM, 0x0001);
pub const TAG_DEVICETREE: u64 = tag_id(CAT_PLATFORM, 0x0002);
pub const TAG_EFI: u64 = tag_id(CAT_PLATFORM, 0x0003);
pub const TAG_HYPERVISOR: u64 = tag_id(CAT_PLATFORM, 0x0004);
pub const TAG_SMBIOS: u64 = tag_id(CAT_PLATFORM, 0x0005);
pub const TAG_METRICS: u64 = tag_id(CAT_DEBUG, 0x0001);

pub const ARCH_X86_64: u16 = 1;
pub const ARCH_AARCH64: u16 = 2;
pub const ARCH_RISCV64: u16 = 3;
pub const ARCH_LOONGARCH: u16 = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn frozen_layouts_have_exact_sizes_offsets_and_alignment() {
        assert_eq!(size_of::<Header>(), HEADER_SIZE);
        assert_eq!(align_of::<Header>(), 1);
        assert_eq!(offset_of!(Header, requests), 64);
        assert_eq!(offset_of!(Header, kernel_uuid), 72);
        assert_eq!(offset_of!(Header, kernel_name), 88);
        assert_eq!(offset_of!(Header, checksum), 152);

        assert_eq!(size_of::<Info>(), INFO_SIZE);
        assert_eq!(align_of::<Info>(), 1);
        assert_eq!(offset_of!(Info, first_tag), 120);
        assert_eq!(offset_of!(Info, next_context), 128);
        assert_eq!(offset_of!(Info, checksum), 136);

        assert_eq!(size_of::<TagHeader>(), TAG_HEADER_SIZE);
        assert_eq!(align_of::<TagHeader>(), 1);
        assert_eq!(offset_of!(TagHeader, checksum), 24);
    }

    #[test]
    fn integer_fields_are_little_endian_and_alignment_one() {
        assert_eq!(Le16::new(0x1234).0, [0x34, 0x12]);
        assert_eq!(Le32::new(0x1234_5678).0, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(
            Le64::new(0x0123_4567_89AB_CDEF).0,
            [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,]
        );
        assert_eq!(align_of::<Le16>(), 1);
        assert_eq!(align_of::<Le32>(), 1);
        assert_eq!(align_of::<Le64>(), 1);
        assert_eq!(align_of::<PhysicalAddress>(), 1);
    }
}
