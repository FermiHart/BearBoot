use std::fs;
use std::path::PathBuf;

use bbp_wire::{V2CapsuleRef, V2Error, V2Profile0};

fn corpus() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/vectors/bbp-v2-corpus-v1.txt");
    fs::read_to_string(path).expect("read repository BBP v2 corpus")
}

fn decode_lower_hex(value: &str, context: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "{context}: odd hex length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(value: u8, context: &str) -> u8 {
                match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("{context}: expected lowercase hex"),
                }
            }
            digit(pair[0], context) << 4 | digit(pair[1], context)
        })
        .collect()
}

fn parse_hex_u64(value: &str, context: &str) -> u64 {
    let digits = value
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("{context}: expected 0x-prefixed hex"));
    u64::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("{context}: invalid u64 hex"))
}

fn expected_generic_error(name: &str) -> Option<V2Error> {
    Some(match name {
        "generic_negative_count_cap" => V2Error::TooManyEntries,
        "generic_negative_directory_alignment" => V2Error::InvalidAlignment,
        "generic_negative_directory_bounds" => V2Error::InvalidExtent,
        "generic_negative_entry_reserved"
        | "generic_negative_header_framing"
        | "generic_negative_header_reserved"
        | "generic_negative_zero_payload" => V2Error::InvalidFormat,
        "generic_negative_invalid_alignment" => V2Error::InvalidAlignment,
        "generic_negative_magic" => V2Error::BadMagic,
        "generic_negative_nonzero_padding" => V2Error::NonzeroPadding,
        "generic_negative_payload_out_of_bounds" => V2Error::InvalidExtent,
        "generic_negative_payload_overlap" => V2Error::OverlappingSpans,
        "generic_negative_version" => V2Error::UnsupportedVersion,
        "generic_negative_payload_crc" | "generic_negative_whole_capsule_crc" => {
            V2Error::ChecksumMismatch
        }
        _ => return None,
    })
}

#[test]
fn shared_v2_corpus_matches_generic_and_profile_zero_validation() {
    let source = corpus();
    assert!(source.is_ascii(), "corpus must be ASCII");
    let mut lines = source.lines().enumerate().filter(|(_, line)| {
        let trimmed = line.trim_start();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    });
    let (marker_line, marker) = lines.next().expect("corpus version marker");
    assert_eq!(
        marker,
        "bbp-v2-corpus-v1",
        "line {}: unsupported corpus version",
        marker_line + 1
    );

    let mut row_count = 0;
    for (line_number, line) in lines {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 11, "line {}: TSV columns", line_number + 1);
        let name = columns[0];
        let context = format!("line {} ({name})", line_number + 1);
        let bytes = decode_lower_hex(columns[10], &context);
        row_count += 1;

        match columns[1] {
            "ok" => {
                let capsule = V2CapsuleRef::parse(&bytes)
                    .unwrap_or_else(|error| panic!("{context}: generic rejection: {error:?}"));
                assert_eq!(capsule.total_size(), bytes.len(), "{context}: total size");
                match columns[2] {
                    "ok" => {
                        let profile = V2Profile0::validate(&capsule).unwrap_or_else(|error| {
                            panic!("{context}: Profile 0 rejection: {error:?}")
                        });
                        assert_eq!(
                            profile.architecture(),
                            columns[4].parse::<u16>().expect("architecture"),
                            "{context}: architecture"
                        );
                        assert_eq!(
                            profile.cpu_count(),
                            columns[5].parse::<u32>().expect("CPU count"),
                            "{context}: CPU count"
                        );
                        assert_eq!(
                            profile.memory_entry_count(),
                            columns[6].parse::<u32>().expect("memory count"),
                            "{context}: memory count"
                        );
                        assert_eq!(
                            profile.kernel_physical_base(),
                            parse_hex_u64(columns[7], &context),
                            "{context}: kernel physical"
                        );
                        assert_eq!(
                            profile.kernel_virtual_base(),
                            parse_hex_u64(columns[8], &context),
                            "{context}: kernel virtual"
                        );
                        assert_eq!(
                            profile.devicetree(),
                            decode_lower_hex(columns[9], &context),
                            "{context}: Device Tree"
                        );
                    }
                    "reject" => assert!(
                        V2Profile0::validate(&capsule).is_err(),
                        "{context}: Profile 0 unexpectedly accepted"
                    ),
                    expectation => panic!("{context}: invalid Profile 0 expectation {expectation}"),
                }
            }
            "reject" => {
                assert_eq!(columns[2], "skip", "{context}: Profile 0 must skip");
                let error =
                    V2CapsuleRef::parse(&bytes).expect_err("generic corpus rejection was accepted");
                if let Some(expected) = expected_generic_error(name) {
                    assert_eq!(error, expected, "{context}: rejection class");
                }
            }
            expectation => panic!("{context}: invalid generic expectation {expectation}"),
        }
    }
    assert!(row_count > 0, "corpus has no rows");
}
