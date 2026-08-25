#![no_std]
#![forbid(unsafe_code)]

//! Bear Boot Protocol v1.1 wire framing for freestanding Rust consumers.
//!
//! This crate validates byte slices already made accessible by the caller. It
//! deliberately has no physical-address translation or pointer dereferencing
//! API. Successful validation establishes framing and CRC integrity, not that a
//! physical address is mapped, that producer-owned memory is immutable, or that
//! any field is semantically safe to use.

mod auth;
mod crc;
mod refs;
mod v2;
mod wire;

pub use auth::{
    V2AuthEnvelopeRef, V2AuthError, V2_AUTH_ALGORITHM_HMAC_SHA256, V2_AUTH_HEADER_SIZE,
    V2_AUTH_KEY_ID_SIZE, V2_AUTH_MAGIC, V2_AUTH_TAG_SIZE, V2_AUTH_VERSION,
};
pub use crc::{crc64, crc64_finalize, crc64_init, crc64_update, Crc64};
pub use refs::{
    trailing_record_count, verify_blob, BlobPolicy, BlobVerification, HeaderRef, InfoRef, TagRef,
    ValidationError,
};
pub use v2::{
    V2CapsuleRef, V2EntryRef, V2Error, V2Profile0, V2_DIRECTORY_ENTRY_SIZE, V2_HEADER_SIZE,
    V2_MAGIC, V2_MAX_ALIGNMENT, V2_MAX_CRC_WORK, V2_MAX_ENTRIES, V2_MAX_EXTENT,
    V2_P0_BOOT_IDENTITY, V2_P0_DEVICETREE, V2_P0_KERNEL_ADDRESS, V2_P0_MEMORY_MAP, V2_P0_VERSION,
    V2_VERSION_MAJOR, V2_VERSION_MINOR,
};
pub use wire::{
    tag_id, Header, Info, Le16, Le32, Le64, PhysicalAddress, TagHeader, ARCH_AARCH64,
    ARCH_LOONGARCH, ARCH_RISCV64, ARCH_X86_64, CAT_CORE, CAT_DEBUG, CAT_DEVICE, CAT_MEMORY,
    CAT_PLATFORM, CAT_SECURITY, CAT_VENDOR, HEADER_MAGIC, HEADER_SIZE, HF_ENABLE_5LEVEL_PAGING,
    HF_ENABLE_NX, HF_FRAMEBUFFER_WANTED, HF_HIGH_ENTROPY_KASLR, HF_SMP_BOOT_ALL,
    HF_UNMAP_NULL_PAGE, INFO_MAGIC, INFO_SIZE, MAX_BLOB_SIZE, MAX_INFO_SIZE, MAX_TAGS,
    MAX_TAG_SIZE, PAGING_4LEVEL, PAGING_5LEVEL, PAGING_NONE, REQ_EXTENDED, REQ_OPTIONAL, TAG_ACPI,
    TAG_CMDLINE, TAG_DEVICETREE, TAG_EFI, TAG_FRAMEBUFFER, TAG_HEADER_SIZE, TAG_HHDM,
    TAG_HYPERVISOR, TAG_KERNEL_ADDRESS, TAG_MEMORY_MAP, TAG_METRICS, TAG_MODULES, TAG_PCIE,
    TAG_SECURITY, TAG_SMBIOS, TAG_SMP, TF_NONE, VERSION_MAJOR, VERSION_MINOR,
};
