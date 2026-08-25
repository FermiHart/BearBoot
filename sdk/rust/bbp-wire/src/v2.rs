//! Experimental, offline-only BBP v2 capsule and Profile 0 validation.

use crate::{crc64, Crc64};

pub const V2_MAGIC: [u8; 8] = *b"BBP2CAP\0";
pub const V2_VERSION_MAJOR: u16 = 2;
pub const V2_VERSION_MINOR: u16 = 0;
pub const V2_HEADER_SIZE: usize = 64;
pub const V2_DIRECTORY_ENTRY_SIZE: usize = 48;
pub const V2_MAX_ENTRIES: u32 = 1024;
pub const V2_MAX_ALIGNMENT: u32 = 4096;
pub const V2_MAX_EXTENT: usize = 64 * 1024 * 1024;
pub const V2_MAX_CRC_WORK: u64 = 96 * 1024 * 1024;

pub const V2_P0_BOOT_IDENTITY: u64 = 0x4242_5032_0000_0001;
pub const V2_P0_MEMORY_MAP: u64 = 0x4242_5032_0000_0002;
pub const V2_P0_KERNEL_ADDRESS: u64 = 0x4242_5032_0000_0003;
pub const V2_P0_DEVICETREE: u64 = 0x4242_5032_0000_0004;
pub const V2_P0_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2Error {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    InvalidFormat,
    InvalidExtent,
    TooManyEntries,
    InvalidAlignment,
    OverlappingSpans,
    NonzeroPadding,
    ChecksumMismatch,
    WorkLimit,
    EntryOutOfRange,
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

fn overlaps(a: usize, a_size: usize, b: usize, b_size: usize) -> bool {
    a < b + b_size && b < a + a_size
}

#[derive(Clone, Copy, Debug)]
pub struct V2CapsuleRef<'a> {
    bytes: &'a [u8],
    directory_offset: usize,
    entry_count: u32,
}

impl<'a> V2CapsuleRef<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, V2Error> {
        if bytes.len() < V2_HEADER_SIZE {
            return Err(V2Error::Truncated);
        }
        if bytes.len() > V2_MAX_EXTENT {
            return Err(V2Error::InvalidExtent);
        }
        if bytes[..8] != V2_MAGIC {
            return Err(V2Error::BadMagic);
        }
        if read_u16(bytes, 8) != V2_VERSION_MAJOR || read_u16(bytes, 10) != V2_VERSION_MINOR {
            return Err(V2Error::UnsupportedVersion);
        }
        if read_u16(bytes, 12) as usize != V2_HEADER_SIZE
            || read_u16(bytes, 14) as usize != V2_DIRECTORY_ENTRY_SIZE
            || read_u32(bytes, 16) != 0
            || read_u64(bytes, 48) != 0
            || read_u64(bytes, 56) != 0
        {
            return Err(V2Error::InvalidFormat);
        }
        if read_u64(bytes, 24) != bytes.len() as u64 {
            return Err(V2Error::InvalidExtent);
        }

        let entry_count = read_u32(bytes, 20);
        if entry_count > V2_MAX_ENTRIES {
            return Err(V2Error::TooManyEntries);
        }
        let directory_offset_u64 = read_u64(bytes, 32);
        if directory_offset_u64 & 7 != 0 || directory_offset_u64 > bytes.len() as u64 {
            return Err(V2Error::InvalidAlignment);
        }
        let directory_offset = directory_offset_u64 as usize;
        if entry_count == 0 && (directory_offset != V2_HEADER_SIZE || bytes.len() != V2_HEADER_SIZE)
        {
            return Err(V2Error::InvalidFormat);
        }
        let directory_size = entry_count as usize * V2_DIRECTORY_ENTRY_SIZE;
        if directory_offset < V2_HEADER_SIZE || directory_size > bytes.len() - directory_offset {
            return Err(V2Error::InvalidExtent);
        }

        let candidate = Self {
            bytes,
            directory_offset,
            entry_count,
        };
        let mut work = bytes.len() as u64;
        for index in 0..entry_count {
            let entry = candidate.unchecked_entry(index);
            if entry.reserved0() != 0 || entry.reserved1() != 0 || entry.size() == 0 {
                return Err(V2Error::InvalidFormat);
            }
            let alignment = entry.alignment();
            if alignment == 0
                || !alignment.is_power_of_two()
                || alignment > V2_MAX_ALIGNMENT
                || entry.offset() & u64::from(alignment - 1) != 0
            {
                return Err(V2Error::InvalidAlignment);
            }
            let offset = usize::try_from(entry.offset()).map_err(|_| V2Error::InvalidExtent)?;
            let size = usize::try_from(entry.size()).map_err(|_| V2Error::InvalidExtent)?;
            if offset > bytes.len() || size > bytes.len() - offset {
                return Err(V2Error::InvalidExtent);
            }
            if overlaps(offset, size, 0, V2_HEADER_SIZE)
                || (entry_count != 0 && overlaps(offset, size, directory_offset, directory_size))
            {
                return Err(V2Error::OverlappingSpans);
            }
            for prior in 0..index {
                let other = candidate.unchecked_entry(prior);
                if overlaps(offset, size, other.offset() as usize, other.size() as usize) {
                    return Err(V2Error::OverlappingSpans);
                }
            }
            work = work.checked_add(entry.size()).ok_or(V2Error::WorkLimit)?;
            if work > V2_MAX_CRC_WORK {
                return Err(V2Error::WorkLimit);
            }
        }

        candidate.validate_padding()?;
        let mut checksum = Crc64::new();
        checksum.update(&bytes[..40]);
        checksum.update(&[0; 8]);
        checksum.update(&bytes[48..]);
        if checksum.finalize() != read_u64(bytes, 40) {
            return Err(V2Error::ChecksumMismatch);
        }
        for index in 0..entry_count {
            let entry = candidate.unchecked_entry(index);
            if crc64(entry.data()) != entry.checksum() {
                return Err(V2Error::ChecksumMismatch);
            }
        }
        Ok(candidate)
    }

    fn validate_padding(&self) -> Result<(), V2Error> {
        let span_count = 1 + if self.entry_count == 0 {
            0
        } else {
            1 + self.entry_count as usize
        };
        let mut cursor = 0;
        for _ in 0..span_count {
            let mut best = (self.bytes.len(), 0);
            if cursor == 0 {
                best = (0, V2_HEADER_SIZE);
            }
            let directory_size = self.entry_count as usize * V2_DIRECTORY_ENTRY_SIZE;
            if self.entry_count != 0
                && self.directory_offset >= cursor
                && self.directory_offset < best.0
            {
                best = (self.directory_offset, directory_size);
            }
            for index in 0..self.entry_count {
                let entry = self.unchecked_entry(index);
                let start = entry.offset() as usize;
                if start >= cursor && start < best.0 {
                    best = (start, entry.size() as usize);
                }
            }
            if best.1 == 0 {
                return Err(V2Error::InvalidFormat);
            }
            if self.bytes[cursor..best.0].iter().any(|byte| *byte != 0) {
                return Err(V2Error::NonzeroPadding);
            }
            cursor = best.0 + best.1;
        }
        if self.bytes[cursor..].iter().any(|byte| *byte != 0) {
            return Err(V2Error::NonzeroPadding);
        }
        Ok(())
    }

    fn unchecked_entry(&self, index: u32) -> V2EntryRef<'a> {
        let offset = self.directory_offset + index as usize * V2_DIRECTORY_ENTRY_SIZE;
        V2EntryRef {
            frame: &self.bytes[offset..offset + V2_DIRECTORY_ENTRY_SIZE],
            capsule: self.bytes,
        }
    }

    pub fn entry(&self, index: u32) -> Result<V2EntryRef<'a>, V2Error> {
        if index >= self.entry_count {
            return Err(V2Error::EntryOutOfRange);
        }
        Ok(self.unchecked_entry(index))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn total_size(&self) -> usize {
        self.bytes.len()
    }

    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }
}

#[derive(Clone, Copy, Debug)]
pub struct V2EntryRef<'a> {
    frame: &'a [u8],
    capsule: &'a [u8],
}

impl<'a> V2EntryRef<'a> {
    pub fn entry_type(&self) -> u64 {
        read_u64(self.frame, 0)
    }

    pub fn flags(&self) -> u32 {
        read_u32(self.frame, 8)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.frame, 12)
    }

    fn reserved0(&self) -> u16 {
        read_u16(self.frame, 14)
    }

    pub fn offset(&self) -> u64 {
        read_u64(self.frame, 16)
    }

    pub fn size(&self) -> u64 {
        read_u64(self.frame, 24)
    }

    pub fn checksum(&self) -> u64 {
        read_u64(self.frame, 32)
    }

    pub fn alignment(&self) -> u32 {
        read_u32(self.frame, 40)
    }

    fn reserved1(&self) -> u32 {
        read_u32(self.frame, 44)
    }

    pub fn data(&self) -> &'a [u8] {
        let offset = self.offset() as usize;
        &self.capsule[offset..offset + self.size() as usize]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct V2Profile0<'a> {
    architecture: u16,
    cpu_count: u32,
    memory_entry_count: u32,
    kernel_physical_base: u64,
    kernel_virtual_base: u64,
    devicetree: &'a [u8],
}

impl<'a> V2Profile0<'a> {
    pub fn validate(capsule: &V2CapsuleRef<'a>) -> Result<Self, V2Error> {
        let mut seen = 0_u8;
        let mut profile = Self {
            architecture: 0,
            cpu_count: 0,
            memory_entry_count: 0,
            kernel_physical_base: 0,
            kernel_virtual_base: 0,
            devicetree: &[],
        };
        for index in 0..capsule.entry_count() {
            let entry = capsule.entry(index)?;
            let bit = match entry.entry_type() {
                V2_P0_BOOT_IDENTITY => 1,
                V2_P0_MEMORY_MAP => 2,
                V2_P0_KERNEL_ADDRESS => 4,
                V2_P0_DEVICETREE => 8,
                _ => continue,
            };
            if seen & bit != 0 || entry.version() != V2_P0_VERSION || entry.flags() != 0 {
                return Err(V2Error::InvalidFormat);
            }
            seen |= bit;
            let data = entry.data();
            match bit {
                1 => {
                    if data.len() != 16
                        || read_u16(data, 2) != 0
                        || read_u32(data, 8) != 0
                        || read_u32(data, 12) != 0
                    {
                        return Err(V2Error::InvalidFormat);
                    }
                    profile.architecture = read_u16(data, 0);
                    profile.cpu_count = read_u32(data, 4);
                    if !(1..=4).contains(&profile.architecture) || profile.cpu_count == 0 {
                        return Err(V2Error::InvalidFormat);
                    }
                }
                2 => {
                    if data.len() < 8 {
                        return Err(V2Error::InvalidFormat);
                    }
                    let count = read_u32(data, 0);
                    if count == 0
                        || count > 4096
                        || read_u32(data, 4) != 32
                        || count as usize * 32 != data.len() - 8
                    {
                        return Err(V2Error::InvalidFormat);
                    }
                    for record in data[8..].chunks_exact(32) {
                        let base = read_u64(record, 0);
                        let length = read_u64(record, 8);
                        if length == 0
                            || base.checked_add(length).is_none()
                            || read_u32(record, 16) == 0
                            || read_u32(record, 28) != 0
                        {
                            return Err(V2Error::InvalidFormat);
                        }
                    }
                    profile.memory_entry_count = count;
                }
                4 => {
                    if data.len() != 16 {
                        return Err(V2Error::InvalidFormat);
                    }
                    profile.kernel_physical_base = read_u64(data, 0);
                    profile.kernel_virtual_base = read_u64(data, 8);
                    if profile.kernel_physical_base == 0 {
                        return Err(V2Error::InvalidFormat);
                    }
                }
                _ => {
                    if data.len() <= 8
                        || read_u32(data, 0) != 0
                        || read_u32(data, 4) as usize != data.len() - 8
                    {
                        return Err(V2Error::InvalidFormat);
                    }
                    profile.devicetree = &data[8..];
                }
            }
        }
        if seen != 15 {
            return Err(V2Error::InvalidFormat);
        }
        Ok(profile)
    }

    pub fn architecture(&self) -> u16 {
        self.architecture
    }
    pub fn cpu_count(&self) -> u32 {
        self.cpu_count
    }
    pub fn memory_entry_count(&self) -> u32 {
        self.memory_entry_count
    }
    pub fn kernel_physical_base(&self) -> u64 {
        self.kernel_physical_base
    }
    pub fn kernel_virtual_base(&self) -> u64 {
        self.kernel_virtual_base
    }
    pub fn devicetree(&self) -> &'a [u8] {
        self.devicetree
    }
}
