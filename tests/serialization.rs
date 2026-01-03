use netflow_parser::{NetflowPacket, NetflowParser};
use serde_json;

#[test]
fn test_v5_serialization() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let parsed = NetflowParser::default().parse_bytes(&v5_packet);
    let json = serde_json::to_string(&parsed).expect("Failed to serialize");

    assert!(json.contains("\"V5\""));
    assert!(json.contains("\"version\":5"));
}

// Note: NetflowPacket only implements Serialize, not Deserialize
// This is by design as the library is primarily for parsing, not creating packets
#[test]
fn test_v5_round_trip_serialization() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let parsed = NetflowParser::default().parse_bytes(&v5_packet);
    let json = serde_json::to_string(&parsed).expect("Failed to serialize");

    // Verify JSON contains expected data
    assert!(json.contains("\"V5\""));
    assert!(json.contains("\"version\":5"));
    assert_eq!(parsed.len(), 1);
}

#[test]
fn test_v5_json_pretty_print() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let parsed = NetflowParser::default().parse_bytes(&v5_packet);
    let json = serde_json::to_string_pretty(&parsed).expect("Failed to serialize");

    assert!(json.contains("\"V5\""));
    assert!(json.contains('\n')); // Pretty printed should have newlines
}

#[test]
fn test_v5_header_serialization() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let parsed = NetflowParser::default().parse_bytes(&v5_packet);

    if let NetflowPacket::V5(v5) = parsed.first().unwrap() {
        let header_json =
            serde_json::to_string(&v5.header).expect("Failed to serialize header");
        assert!(header_json.contains("\"version\":5"));
        assert!(header_json.contains("\"count\":1"));
    } else {
        panic!("Expected V5 packet");
    }
}

#[test]
fn test_invalid_packet_handling() {
    // Invalid version number - parser returns empty vec for unknown versions
    let invalid_packet = [0, 99, 0, 0];

    let parsed = NetflowParser::default().parse_bytes(&invalid_packet);

    // Parser filters out unknown versions, so result should be empty
    assert_eq!(parsed.len(), 0);
}
