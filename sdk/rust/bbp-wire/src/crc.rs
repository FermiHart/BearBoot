//! CRC-64/XZ (ECMA-182), reflected form.

/// Reflected CRC-64/XZ polynomial.
pub const CRC64_POLY_REFLECTED: u64 = 0xC96C_5795_D787_0F42;
/// Initial CRC-64/XZ state.
pub const CRC64_INIT: u64 = u64::MAX;

/// Starts an incremental CRC-64/XZ computation.
pub const fn crc64_init() -> u64 {
    CRC64_INIT
}

/// Folds `bytes` into an unfinalized CRC-64/XZ state.
pub fn crc64_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        for _ in 0..8 {
            let mask = 0_u64.wrapping_sub(state & 1);
            state = (state >> 1) ^ (CRC64_POLY_REFLECTED & mask);
        }
    }
    state
}

/// Applies the CRC-64/XZ final XOR.
pub const fn crc64_finalize(state: u64) -> u64 {
    state ^ u64::MAX
}

/// Computes CRC-64/XZ in one shot.
pub fn crc64(bytes: &[u8]) -> u64 {
    crc64_finalize(crc64_update(crc64_init(), bytes))
}

/// Incremental CRC-64/XZ state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Crc64 {
    state: u64,
}

impl Crc64 {
    /// Creates a fresh CRC-64/XZ computation.
    pub const fn new() -> Self {
        Self {
            state: crc64_init(),
        }
    }

    /// Folds another byte slice into this computation.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state = crc64_update(self.state, bytes);
    }

    /// Returns the finalized checksum without changing this state.
    pub const fn finalize(&self) -> u64 {
        crc64_finalize(self.state)
    }
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn crc64_zeroed_field(bytes: &[u8], offset: usize) -> u64 {
    const ZEROES: [u8; 8] = [0; 8];

    let mut crc = Crc64::new();
    crc.update(&bytes[..offset]);
    crc.update(&ZEROES);
    crc.update(&bytes[offset + ZEROES.len()..]);
    crc.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vector_and_incremental_match() {
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);

        let mut crc = Crc64::new();
        crc.update(b"123");
        crc.update(b"456");
        crc.update(b"789");
        assert_eq!(crc.finalize(), crc64(b"123456789"));
    }
}
