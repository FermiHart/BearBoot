//! Experimental BBP v2 authentication-envelope framing.
//!
//! Parsing validates framing and the enclosed capsule CRCs. It does not verify
//! the HMAC; callers must feed [`V2AuthEnvelopeRef::for_each_mac_part`] to an
//! approved HMAC-SHA256 implementation and compare its result to [`tag`](V2AuthEnvelopeRef::tag).

use crate::{V2CapsuleRef, V2Error, V2_MAX_EXTENT};

pub const V2_AUTH_MAGIC: [u8; 8] = *b"BBP2AUTH";
pub const V2_AUTH_VERSION: u16 = 1;
pub const V2_AUTH_ALGORITHM_HMAC_SHA256: u16 = 1;
pub const V2_AUTH_HEADER_SIZE: usize = 80;
pub const V2_AUTH_KEY_ID_SIZE: usize = 16;
pub const V2_AUTH_TAG_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2AuthError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedFlags,
    InvalidExtent,
    InvalidCapsule(V2Error),
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

#[derive(Clone, Copy, Debug)]
pub struct V2AuthEnvelopeRef<'a> {
    bytes: &'a [u8],
    capsule: V2CapsuleRef<'a>,
}

impl<'a> V2AuthEnvelopeRef<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, V2AuthError> {
        if bytes.len() < V2_AUTH_HEADER_SIZE {
            return Err(V2AuthError::Truncated);
        }
        if bytes[..8] != V2_AUTH_MAGIC {
            return Err(V2AuthError::BadMagic);
        }
        if read_u16(bytes, 8) != V2_AUTH_VERSION {
            return Err(V2AuthError::UnsupportedVersion);
        }
        if read_u16(bytes, 10) != V2_AUTH_ALGORITHM_HMAC_SHA256 {
            return Err(V2AuthError::UnsupportedAlgorithm);
        }
        if read_u32(bytes, 12) != 0 {
            return Err(V2AuthError::UnsupportedFlags);
        }
        let payload_size = bytes.len() - V2_AUTH_HEADER_SIZE;
        if payload_size > V2_MAX_EXTENT || read_u64(bytes, 24) != payload_size as u64 {
            return Err(V2AuthError::InvalidExtent);
        }
        let capsule = V2CapsuleRef::parse(&bytes[V2_AUTH_HEADER_SIZE..])
            .map_err(V2AuthError::InvalidCapsule)?;
        Ok(Self { bytes, capsule })
    }

    pub fn rollback_index(&self) -> u64 {
        read_u64(self.bytes, 16)
    }

    pub fn key_identity(&self) -> &'a [u8; V2_AUTH_KEY_ID_SIZE] {
        self.bytes[32..48]
            .try_into()
            .expect("validated auth header")
    }

    pub fn tag(&self) -> &'a [u8; V2_AUTH_TAG_SIZE] {
        self.bytes[48..80]
            .try_into()
            .expect("validated auth header")
    }

    pub fn capsule(&self) -> V2CapsuleRef<'a> {
        self.capsule
    }

    pub fn for_each_mac_part(&self, mut update: impl FnMut(&[u8])) {
        const ZERO_TAG: [u8; V2_AUTH_TAG_SIZE] = [0; V2_AUTH_TAG_SIZE];
        update(&self.bytes[..48]);
        update(&ZERO_TAG);
        update(self.capsule.as_bytes());
    }
}
