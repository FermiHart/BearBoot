use bbp_wire::V2AuthEnvelopeRef;

const VECTOR: &str = include_str!("../tests/vectors/bbp-v2-profile0-auth-v1.json");

fn hex_field(name: &str) -> Vec<u8> {
    let marker = format!("\"{name}\": \"");
    let start = VECTOR.find(&marker).expect("vector field") + marker.len();
    let value = &VECTOR[start..start + VECTOR[start..].find('"').expect("closing quote")];
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid canonical hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn main() {
    let bytes = hex_field("envelope_hex");
    let envelope = V2AuthEnvelopeRef::parse(&bytes).expect("canonical auth framing");
    let mut authenticated_size = 0;
    envelope.for_each_mac_part(|part| authenticated_size += part.len());
    assert_eq!(authenticated_size, bytes.len());
    assert_eq!(envelope.rollback_index(), 42);
    assert_eq!(envelope.capsule().entry_count(), 4);
    println!("BBP Rust v2 auth framing vector: PASS (HMAC not verified)");
}
