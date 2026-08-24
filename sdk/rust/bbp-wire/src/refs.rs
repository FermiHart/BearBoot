//! Bounds-first validators over caller-owned byte slices.

use crate::crc::{crc64, crc64_zeroed_field};
use crate::wire::{
    PhysicalAddress, HEADER_MAGIC, HEADER_SIZE, INFO_MAGIC, INFO_SIZE, MAX_BLOB_SIZE,
    MAX_INFO_SIZE, MAX_TAG_SIZE, TAG_HEADER_SIZE, VERSION_MAJOR,
};

const HEADER_CHECKSUM_OFFSET: usize = 152;
const INFO_CHECKSUM_OFFSET: usize = 136;
const TAG_CHECKSUM_OFFSET: usize = 24;

/// A framing or integrity validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// The supplied slice does not contain the fixed structure or declared tag.
    Truncated { needed: usize, available: usize },
    /// The complete 16-byte magic, including padding, did not match.
    BadMagic,
    /// The major version is incompatible. Minor versions are accepted.
    UnsupportedMajor { found: u16 },
    /// A header declared a size other than the frozen 160-byte size.
    InvalidHeaderSize { found: u32 },
    /// INFO's informational span was outside the defensive range.
    InvalidInfoSize { found: u32 },
    /// A tag's declared span was outside `[32, 16 MiB]`.
    InvalidTagSize { found: u32 },
    /// A checksum did not match the bytes supplied by the caller.
    ChecksumMismatch { expected: u64, actual: u64 },
    /// Out-of-line data was empty.
    EmptyBlob,
    /// Out-of-line data exceeded the 64 MiB verification bound.
    BlobTooLarge { size: usize },
    /// The producer supplied zero instead of a blob checksum and policy rejects it.
    MissingBlobChecksum,
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Validated view of one fixed 160-byte BBP header.
#[derive(Clone, Copy, Debug)]
pub struct HeaderRef<'a> {
    bytes: &'a [u8],
}

impl<'a> HeaderRef<'a> {
    /// Validates magic, major version, frozen size, and checksum.
    pub fn validate(input: &'a [u8]) -> Result<Self, ValidationError> {
        let bytes = input.get(..HEADER_SIZE).ok_or(ValidationError::Truncated {
            needed: HEADER_SIZE,
            available: input.len(),
        })?;
        if bytes[..16] != HEADER_MAGIC {
            return Err(ValidationError::BadMagic);
        }
        let major = read_u16(bytes, 16);
        if major != VERSION_MAJOR {
            return Err(ValidationError::UnsupportedMajor { found: major });
        }
        let size = read_u32(bytes, 20);
        if size != HEADER_SIZE as u32 {
            return Err(ValidationError::InvalidHeaderSize { found: size });
        }
        let expected = read_u64(bytes, HEADER_CHECKSUM_OFFSET);
        let actual = crc64_zeroed_field(bytes, HEADER_CHECKSUM_OFFSET);
        if actual != expected {
            return Err(ValidationError::ChecksumMismatch { expected, actual });
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn version_major(&self) -> u16 {
        read_u16(self.bytes, 16)
    }

    pub fn version_minor(&self) -> u16 {
        read_u16(self.bytes, 18)
    }

    pub fn header_size(&self) -> u32 {
        read_u32(self.bytes, 20)
    }

    pub fn flags(&self) -> u64 {
        read_u64(self.bytes, 24)
    }

    /// Returns transfer-address bits without interpreting them as physical or virtual.
    pub fn entry_point(&self) -> u64 {
        read_u64(self.bytes, 32)
    }

    pub fn paging_mode(&self) -> u64 {
        read_u64(self.bytes, 40)
    }

    pub fn kernel_virtual_base(&self) -> u64 {
        read_u64(self.bytes, 48)
    }

    pub fn request_count(&self) -> u32 {
        read_u32(self.bytes, 56)
    }

    pub fn reserved0(&self) -> u32 {
        read_u32(self.bytes, 60)
    }

    pub fn requests(&self) -> PhysicalAddress {
        PhysicalAddress::new(read_u64(self.bytes, 64))
    }

    pub fn kernel_uuid(&self) -> [u64; 2] {
        [read_u64(self.bytes, 72), read_u64(self.bytes, 80)]
    }

    pub fn kernel_name(&self) -> &'a [u8; 64] {
        self.bytes[88..152]
            .try_into()
            .expect("validated fixed header range")
    }

    pub fn checksum(&self) -> u64 {
        read_u64(self.bytes, HEADER_CHECKSUM_OFFSET)
    }
}

/// Validated view of one fixed 144-byte BBP info object.
#[derive(Clone, Copy, Debug)]
pub struct InfoRef<'a> {
    bytes: &'a [u8],
}

impl<'a> InfoRef<'a> {
    /// Validates magic, major version, plausible informational size, and the
    /// checksum over exactly the fixed INFO object.
    pub fn validate(input: &'a [u8]) -> Result<Self, ValidationError> {
        let bytes = input.get(..INFO_SIZE).ok_or(ValidationError::Truncated {
            needed: INFO_SIZE,
            available: input.len(),
        })?;
        if bytes[..16] != INFO_MAGIC {
            return Err(ValidationError::BadMagic);
        }
        let major = read_u16(bytes, 16);
        if major != VERSION_MAJOR {
            return Err(ValidationError::UnsupportedMajor { found: major });
        }
        let size = read_u32(bytes, 20);
        if size < INFO_SIZE as u32 || size > MAX_INFO_SIZE {
            return Err(ValidationError::InvalidInfoSize { found: size });
        }
        let expected = read_u64(bytes, INFO_CHECKSUM_OFFSET);
        let actual = crc64_zeroed_field(bytes, INFO_CHECKSUM_OFFSET);
        if actual != expected {
            return Err(ValidationError::ChecksumMismatch { expected, actual });
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn version_major(&self) -> u16 {
        read_u16(self.bytes, 16)
    }

    pub fn version_minor(&self) -> u16 {
        read_u16(self.bytes, 18)
    }

    pub fn info_size(&self) -> u32 {
        read_u32(self.bytes, 20)
    }

    pub fn bootloader_name(&self) -> &'a [u8; 32] {
        self.bytes[24..56]
            .try_into()
            .expect("validated fixed info range")
    }

    pub fn bootloader_version(&self) -> &'a [u8; 16] {
        self.bytes[56..72]
            .try_into()
            .expect("validated fixed info range")
    }

    pub fn bootloader_uuid(&self) -> [u64; 2] {
        [read_u64(self.bytes, 72), read_u64(self.bytes, 80)]
    }

    pub fn bootloader_start_ts(&self) -> u64 {
        read_u64(self.bytes, 88)
    }

    pub fn kernel_load_ts(&self) -> u64 {
        read_u64(self.bytes, 96)
    }

    pub fn handoff_ts(&self) -> u64 {
        read_u64(self.bytes, 104)
    }

    pub fn architecture(&self) -> u16 {
        read_u16(self.bytes, 112)
    }

    pub fn cpu_count(&self) -> u16 {
        read_u16(self.bytes, 114)
    }

    pub fn tag_count(&self) -> u32 {
        read_u32(self.bytes, 116)
    }

    pub fn first_tag(&self) -> PhysicalAddress {
        PhysicalAddress::new(read_u64(self.bytes, 120))
    }

    pub fn next_context(&self) -> PhysicalAddress {
        PhysicalAddress::new(read_u64(self.bytes, 128))
    }

    pub fn checksum(&self) -> u64 {
        read_u64(self.bytes, INFO_CHECKSUM_OFFSET)
    }
}

/// Validated view of any BBP tag, including unknown tag IDs.
#[derive(Clone, Copy, Debug)]
pub struct TagRef<'a> {
    bytes: &'a [u8],
}

impl<'a> TagRef<'a> {
    /// Validates the fixed header, declared extent, and full-tag checksum.
    /// Length and slice bounds are checked before CRC scanning.
    pub fn validate(input: &'a [u8]) -> Result<Self, ValidationError> {
        if input.len() < TAG_HEADER_SIZE {
            return Err(ValidationError::Truncated {
                needed: TAG_HEADER_SIZE,
                available: input.len(),
            });
        }

        let declared = read_u32(input, 8);
        if !(TAG_HEADER_SIZE as u32..=MAX_TAG_SIZE).contains(&declared) {
            return Err(ValidationError::InvalidTagSize { found: declared });
        }
        let declared = declared as usize;
        let bytes = input.get(..declared).ok_or(ValidationError::Truncated {
            needed: declared,
            available: input.len(),
        })?;

        let expected = read_u64(bytes, TAG_CHECKSUM_OFFSET);
        let actual = crc64_zeroed_field(bytes, TAG_CHECKSUM_OFFSET);
        if actual != expected {
            return Err(ValidationError::ChecksumMismatch { expected, actual });
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn tag_id(&self) -> u64 {
        read_u64(self.bytes, 0)
    }

    pub fn tag_size(&self) -> u32 {
        read_u32(self.bytes, 8)
    }

    pub fn tag_version(&self) -> u16 {
        read_u16(self.bytes, 12)
    }

    pub fn flags(&self) -> u16 {
        read_u16(self.bytes, 14)
    }

    pub fn next_tag(&self) -> PhysicalAddress {
        PhysicalAddress::new(read_u64(self.bytes, 16))
    }

    pub fn checksum(&self) -> u64 {
        read_u64(self.bytes, TAG_CHECKSUM_OFFSET)
    }

    pub fn body(&self) -> &'a [u8] {
        &self.bytes[TAG_HEADER_SIZE..]
    }

    /// Clamps a claimed trailing-record count to complete records inside this
    /// tag's validated extent.
    pub fn trailing_record_count(
        &self,
        fixed_size: usize,
        record_size: usize,
        claimed: u32,
    ) -> u32 {
        trailing_record_count(self.bytes.len(), fixed_size, record_size, claimed)
    }

    /// Returns bytes after a caller-supplied fixed tag-body size, if that size
    /// lies inside the validated tag.
    pub fn trailing_bytes(&self, fixed_size: usize) -> Option<&'a [u8]> {
        self.bytes.get(fixed_size..)
    }
}

/// Clamps a claimed trailing-record count to complete records in `tag_size`.
///
/// Zero-sized records, fixed prefixes outside the tag, and prefixes smaller
/// than the generic tag header yield zero.
pub const fn trailing_record_count(
    tag_size: usize,
    fixed_size: usize,
    record_size: usize,
    claimed: u32,
) -> u32 {
    if record_size == 0 || fixed_size < TAG_HEADER_SIZE || tag_size <= fixed_size {
        return 0;
    }
    let fit = (tag_size - fixed_size) / record_size;
    let fit = if fit > u32::MAX as usize {
        u32::MAX
    } else {
        fit as u32
    };
    if claimed < fit {
        claimed
    } else {
        fit
    }
}

/// Policy for a zero blob checksum, which BBP defines as "unchecked".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobPolicy {
    /// Reject a blob whose producer supplied no checksum.
    RequireChecksum,
    /// Accept it explicitly, while reporting that no integrity check occurred.
    AllowUnchecked,
}

/// Honest outcome of blob verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobVerification {
    /// A nonzero producer checksum matched the supplied bytes.
    Verified,
    /// Policy allowed a zero checksum; no integrity verification occurred.
    Unchecked,
}

/// Verifies bytes already mapped and bounded by the caller.
///
/// This function never uses a BBP physical-address field. It cannot establish
/// mapping, lifetime, immutability, authenticity, or semantic correctness.
pub fn verify_blob(
    bytes: &[u8],
    expected_crc: u64,
    policy: BlobPolicy,
) -> Result<BlobVerification, ValidationError> {
    if bytes.is_empty() {
        return Err(ValidationError::EmptyBlob);
    }
    if bytes.len() > MAX_BLOB_SIZE {
        return Err(ValidationError::BlobTooLarge { size: bytes.len() });
    }
    if expected_crc == 0 {
        return match policy {
            BlobPolicy::RequireChecksum => Err(ValidationError::MissingBlobChecksum),
            BlobPolicy::AllowUnchecked => Ok(BlobVerification::Unchecked),
        };
    }

    let actual = crc64(bytes);
    if actual != expected_crc {
        return Err(ValidationError::ChecksumMismatch {
            expected: expected_crc,
            actual,
        });
    }
    Ok(BlobVerification::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_counts_are_bounded_without_arithmetic_wrap() {
        assert_eq!(trailing_record_count(104, 40, 32, 99), 2);
        assert_eq!(trailing_record_count(104, 40, 32, 1), 1);
        assert_eq!(trailing_record_count(40, 40, 32, 1), 0);
        assert_eq!(trailing_record_count(104, 40, 0, u32::MAX), 0);
        assert_eq!(trailing_record_count(usize::MAX, 32, 1, u32::MAX), u32::MAX);
    }
}
