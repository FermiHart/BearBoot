use bbp_wire::{V2AuthEnvelopeRef, V2CapsuleRef, V2Error, V2Profile0, V2_AUTH_HEADER_SIZE};

const VECTOR: &str = include_str!("vectors/bbp-v2-profile0-auth-v1.json");

fn hex_field(name: &str) -> Vec<u8> {
    let marker = format!("\"{name}\": \"");
    let start = VECTOR.find(&marker).unwrap() + marker.len();
    let value = &VECTOR[start..start + VECTOR[start..].find('"').unwrap()];
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(value: u8) -> u8 {
                match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("non-hex canonical vector"),
                }
            }
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

#[test]
fn canonical_capsule_has_valid_profile_zero() {
    let bytes = hex_field("capsule_hex");
    let capsule = V2CapsuleRef::parse(&bytes).unwrap();
    assert_eq!(capsule.entry_count(), 4);
    assert_eq!(capsule.total_size(), bytes.len());

    let profile = V2Profile0::validate(&capsule).unwrap();
    assert_eq!(profile.architecture(), 2);
    assert_eq!(profile.cpu_count(), 1);
    assert_eq!(profile.memory_entry_count(), 1);
    assert_eq!(profile.kernel_physical_base(), 0x4008_0000);
    assert_eq!(profile.kernel_virtual_base(), 0xffff_ffff_8000_0000);
    assert_eq!(profile.devicetree(), &[0xd0, 0x0d, 0xfe, 0xed]);
}

#[test]
fn canonical_auth_envelope_exposes_exact_unverified_mac_framing() {
    let bytes = hex_field("envelope_hex");
    let envelope = V2AuthEnvelopeRef::parse(&bytes).unwrap();
    assert_eq!(envelope.rollback_index(), 42);
    assert_eq!(envelope.key_identity().as_slice(), hex_field("key_id_hex"));
    assert_eq!(envelope.capsule().entry_count(), 4);

    let mut framed = Vec::new();
    envelope.for_each_mac_part(|part| framed.extend_from_slice(part));
    let mut expected = bytes.clone();
    expected[48..V2_AUTH_HEADER_SIZE].fill(0);
    assert_eq!(framed, expected);
    assert_ne!(envelope.tag(), &[0_u8; 32]);
}

#[test]
fn v2_parsers_reject_truncation_and_checksum_tampering() {
    let mut capsule = hex_field("capsule_hex");
    assert!(V2CapsuleRef::parse(&capsule[..capsule.len() - 1]).is_err());
    let last_payload_byte = capsule.len() - 5;
    capsule[last_payload_byte] ^= 1;
    assert!(matches!(
        V2CapsuleRef::parse(&capsule),
        Err(V2Error::ChecksumMismatch)
    ));

    let envelope = hex_field("envelope_hex");
    assert!(V2AuthEnvelopeRef::parse(&envelope[..V2_AUTH_HEADER_SIZE - 1]).is_err());
    assert!(V2AuthEnvelopeRef::parse(&envelope[..envelope.len() - 1]).is_err());
}

#[test]
fn deterministic_malformed_slices_never_panic() {
    let mut state = 0xa5a5_5a5a_d3c4_b2e1_u64;
    let mut bytes = [0_u8; 512];
    for len in 0..=bytes.len() {
        for byte in &mut bytes[..len] {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 56) as u8;
        }
        let _ = V2CapsuleRef::parse(&bytes[..len]);
        let _ = V2AuthEnvelopeRef::parse(&bytes[..len]);
    }
}
