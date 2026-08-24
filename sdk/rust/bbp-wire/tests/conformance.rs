use bbp_wire::{
    crc64, verify_blob, BlobPolicy, BlobVerification, HeaderRef, InfoRef, TagRef, ValidationError,
    HEADER_MAGIC, HEADER_SIZE, INFO_MAGIC, INFO_SIZE, MAX_INFO_SIZE, MAX_TAG_SIZE, TAG_HEADER_SIZE,
    VERSION_MAJOR, VERSION_MINOR,
};

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn seal(bytes: &mut [u8], checksum_offset: usize) {
    bytes[checksum_offset..checksum_offset + 8].fill(0);
    let checksum = crc64(bytes);
    put_u64(bytes, checksum_offset, checksum);
}

fn valid_header() -> [u8; HEADER_SIZE] {
    let mut bytes = [0_u8; HEADER_SIZE];
    bytes[..16].copy_from_slice(&HEADER_MAGIC);
    put_u16(&mut bytes, 16, VERSION_MAJOR);
    put_u16(&mut bytes, 18, VERSION_MINOR);
    put_u32(&mut bytes, 20, HEADER_SIZE as u32);
    seal(&mut bytes, 152);
    bytes
}

fn valid_info() -> [u8; INFO_SIZE] {
    let mut bytes = [0_u8; INFO_SIZE];
    bytes[..16].copy_from_slice(&INFO_MAGIC);
    put_u16(&mut bytes, 16, VERSION_MAJOR);
    put_u16(&mut bytes, 18, VERSION_MINOR);
    put_u32(&mut bytes, 20, INFO_SIZE as u32);
    seal(&mut bytes, 136);
    bytes
}

fn valid_tag(tag_id: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; size];
    put_u64(&mut bytes, 0, tag_id);
    put_u32(&mut bytes, 8, size as u32);
    put_u16(&mut bytes, 12, 1);
    seal(&mut bytes, 24);
    bytes
}

#[test]
fn magic_padding_is_part_of_validation() {
    let mut header = valid_header();
    header[15] = 1;
    seal(&mut header, 152);
    assert_eq!(
        HeaderRef::validate(&header).unwrap_err(),
        ValidationError::BadMagic
    );

    let mut info = valid_info();
    info[12] = 1;
    seal(&mut info, 136);
    assert_eq!(
        InfoRef::validate(&info).unwrap_err(),
        ValidationError::BadMagic
    );
}

#[test]
fn versions_and_declared_sizes_are_enforced() {
    let mut header = valid_header();
    put_u16(&mut header, 16, VERSION_MAJOR + 1);
    seal(&mut header, 152);
    assert_eq!(
        HeaderRef::validate(&header).unwrap_err(),
        ValidationError::UnsupportedMajor {
            found: VERSION_MAJOR + 1
        }
    );

    let mut info = valid_info();
    put_u16(&mut info, 16, VERSION_MAJOR + 1);
    seal(&mut info, 136);
    assert_eq!(
        InfoRef::validate(&info).unwrap_err(),
        ValidationError::UnsupportedMajor {
            found: VERSION_MAJOR + 1
        }
    );

    let mut header = valid_header();
    put_u32(&mut header, 20, (HEADER_SIZE - 1) as u32);
    seal(&mut header, 152);
    assert_eq!(
        HeaderRef::validate(&header).unwrap_err(),
        ValidationError::InvalidHeaderSize {
            found: (HEADER_SIZE - 1) as u32
        }
    );

    let mut info = valid_info();
    put_u32(&mut info, 20, (INFO_SIZE - 1) as u32);
    seal(&mut info, 136);
    assert!(matches!(
        InfoRef::validate(&info),
        Err(ValidationError::InvalidInfoSize { .. })
    ));

    let mut info = valid_info();
    put_u32(&mut info, 20, MAX_INFO_SIZE + 1);
    seal(&mut info, 136);
    assert!(matches!(
        InfoRef::validate(&info),
        Err(ValidationError::InvalidInfoSize { .. })
    ));

    let mut future_minor = valid_info();
    put_u16(&mut future_minor, 18, u16::MAX);
    seal(&mut future_minor, 136);
    assert_eq!(
        InfoRef::validate(&future_minor).unwrap().version_minor(),
        u16::MAX
    );

    let mut future_minor = valid_header();
    put_u16(&mut future_minor, 18, u16::MAX);
    seal(&mut future_minor, 152);
    assert_eq!(
        HeaderRef::validate(&future_minor).unwrap().version_minor(),
        u16::MAX
    );
}

#[test]
fn crc_vector_and_record_checksums_are_verified() {
    assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    assert!(HeaderRef::validate(&valid_header()).is_ok());
    assert!(InfoRef::validate(&valid_info()).is_ok());

    let mut header = valid_header();
    header[40] ^= 1;
    assert!(matches!(
        HeaderRef::validate(&header),
        Err(ValidationError::ChecksumMismatch { .. })
    ));
}

#[test]
fn tag_bounds_are_checked_before_crc() {
    let short = [0_u8; TAG_HEADER_SIZE - 1];
    assert_eq!(
        TagRef::validate(&short).unwrap_err(),
        ValidationError::Truncated {
            needed: TAG_HEADER_SIZE,
            available: TAG_HEADER_SIZE - 1
        }
    );

    let mut header_only = [0_u8; TAG_HEADER_SIZE];
    put_u32(&mut header_only, 8, MAX_TAG_SIZE);
    put_u64(&mut header_only, 24, 0xDEAD_BEEF);
    assert_eq!(
        TagRef::validate(&header_only).unwrap_err(),
        ValidationError::Truncated {
            needed: MAX_TAG_SIZE as usize,
            available: TAG_HEADER_SIZE
        }
    );

    put_u32(&mut header_only, 8, TAG_HEADER_SIZE as u32 - 1);
    assert!(matches!(
        TagRef::validate(&header_only),
        Err(ValidationError::InvalidTagSize { .. })
    ));
    put_u32(&mut header_only, 8, MAX_TAG_SIZE + 1);
    assert!(matches!(
        TagRef::validate(&header_only),
        Err(ValidationError::InvalidTagSize { .. })
    ));
}

#[test]
fn unknown_but_valid_tags_are_preserved() {
    let unknown = 0xFFFF_1234_5678_9ABC;
    let mut bytes = valid_tag(unknown, 46);
    bytes[32..].copy_from_slice(b"opaque-payload");
    seal(&mut bytes, 24);

    let tag = TagRef::validate(&bytes).unwrap();
    assert_eq!(tag.tag_id(), unknown);
    assert_eq!(tag.body(), b"opaque-payload");
}

#[test]
fn trailing_array_counts_are_clamped_to_validated_extent() {
    let bytes = valid_tag(0x0002_0000_0000_0001, 104);
    let tag = TagRef::validate(&bytes).unwrap();
    assert_eq!(tag.trailing_record_count(40, 32, 999), 2);
    assert_eq!(tag.trailing_record_count(40, 32, 1), 1);
    assert_eq!(tag.trailing_record_count(105, 32, 999), 0);
    assert_eq!(tag.trailing_record_count(40, 0, 999), 0);
}

#[test]
fn blob_policy_distinguishes_verified_from_unchecked() {
    let blob = b"measured-boot-log-payload";
    let checksum = crc64(blob);
    assert_eq!(
        verify_blob(blob, checksum, BlobPolicy::RequireChecksum),
        Ok(BlobVerification::Verified)
    );
    assert!(matches!(
        verify_blob(blob, checksum ^ 1, BlobPolicy::RequireChecksum),
        Err(ValidationError::ChecksumMismatch { .. })
    ));
    assert_eq!(
        verify_blob(blob, 0, BlobPolicy::RequireChecksum),
        Err(ValidationError::MissingBlobChecksum)
    );
    assert_eq!(
        verify_blob(blob, 0, BlobPolicy::AllowUnchecked),
        Ok(BlobVerification::Unchecked)
    );
    assert_eq!(
        verify_blob(&[], checksum, BlobPolicy::AllowUnchecked),
        Err(ValidationError::EmptyBlob)
    );
}

#[test]
fn physical_values_remain_opaque_numeric_bits() {
    let mut info = valid_info();
    let first = 0xFFFF_8000_DEAD_BEEFu64;
    let next = 0x0123_4567_89AB_CDEFu64;
    put_u64(&mut info, 120, first);
    put_u64(&mut info, 128, next);
    seal(&mut info, 136);

    let parsed = InfoRef::validate(&info).unwrap();
    assert_eq!(parsed.first_tag().get(), first);
    assert_eq!(parsed.next_context().get(), next);
}

#[test]
fn deterministic_arbitrary_malformed_inputs_never_panic() {
    let mut state = 0xA5A5_5A5A_D3C4_B2E1u64;
    let mut bytes = [0_u8; 512];

    for len in 0..=bytes.len() {
        for byte in &mut bytes[..len] {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 56) as u8;
        }
        let input = &bytes[..len];
        let _ = HeaderRef::validate(input);
        let _ = InfoRef::validate(input);
        let _ = TagRef::validate(input);
        let _ = verify_blob(input, state, BlobPolicy::RequireChecksum);
    }
}
