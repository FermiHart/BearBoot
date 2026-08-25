use bbp_wire::{V2CapsuleRef, V2Profile0};

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
    let bytes = hex_field("capsule_hex");
    let capsule = V2CapsuleRef::parse(&bytes).expect("canonical capsule framing");
    let profile = V2Profile0::validate(&capsule).expect("canonical Profile 0");
    assert_eq!(profile.architecture(), 2);
    assert_eq!(profile.memory_entry_count(), 1);
    assert_eq!(profile.devicetree(), &[0xd0, 0x0d, 0xfe, 0xed]);
    println!("BBP Rust v2 Profile 0 vector: PASS");
}
