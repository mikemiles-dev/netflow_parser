//! Round-trip serialization tests: parse → to_be_bytes → assert equal.
//!
//! Verifies that parsing bytes and re-serializing produces identical output
//! for V5, V7, V9 (template + data), and IPFIX (template + data) packets,
//! as well as all individual IANA field types.

use netflow_parser::variable_versions::field_value::{FieldDataType, FieldValue};
use netflow_parser::{NetflowPacket, NetflowParser};

// ---------------------------------------------------------------------------
// V7 packet round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_v7_round_trip() {
    // V7 header (24 bytes): version=7, count=1, sys_up_time, unix_secs, unix_nsecs, flow_seq, reserved
    // V7 flowset (52 bytes): one flow record
    let mut packet = vec![0u8; 24 + 52];
    // version = 7
    packet[0] = 0;
    packet[1] = 7;
    // count = 1
    packet[2] = 0;
    packet[3] = 1;
    // Fill remaining header + flowset with deterministic values
    for i in 4..packet.len() {
        packet[i] = (i % 256) as u8;
    }

    if let NetflowPacket::V7(v7) = NetflowParser::default()
        .parse_bytes(&packet)
        .packets
        .first()
        .unwrap()
    {
        assert_eq!(v7.to_be_bytes(), packet);
    } else {
        panic!("Expected V7 packet");
    }
}

// ---------------------------------------------------------------------------
// V9 template + data round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_v9_template_and_data_round_trip() {
    // Template packet: defines template 256 with 4 aligned fields (each 4 bytes):
    //   sourceIPv4Address(8) len=4, destinationIPv4Address(12) len=4,
    //   ingressInterface(10) len=4, egressInterface(14) len=4
    // Record size = 16 bytes (4-byte aligned, no padding needed)
    //
    // V9 header (20 bytes): version=9, count=1, sysUpTime, unixSecs, seq=1, srcId=1
    // Template flowset: flowsetId=0, length=24, templateId=256, fieldCount=4, 4 fields
    let hex_template = "0009000100000e1061db09bd00000001000000010000001801000004\
                         00080004000c0004000a0004000e0004";

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let template_bytes = hex::decode(hex_template).unwrap();
    let template_result = parser.parse_bytes(&template_bytes);
    assert!(template_result.error.is_none(), "Template parse failed");

    // Data packet: one record with the above template (16 bytes, aligned)
    //   src=192.168.1.1, dst=10.0.0.1, ingress=10, egress=20
    // Data flowset: flowsetId=256, length=20 (4 header + 16 data)
    let hex_data = "0009000100000e1061db09bd000000020000000101000014\
                    c0a801010a0000010000000a00000014";

    let data_bytes = hex::decode(hex_data).unwrap();
    let data_result = parser.parse_bytes(&data_bytes);
    assert!(data_result.error.is_none(), "Data parse failed");

    if let Some(NetflowPacket::V9(v9)) = data_result.packets.first() {
        let serialized = v9.to_be_bytes().expect("V9 serialization failed");
        assert_eq!(
            serialized, data_bytes,
            "V9 data packet round-trip failed"
        );
    } else {
        panic!("Expected V9 data packet");
    }
}

#[test]
fn test_v9_template_only_round_trip() {
    // Same template as above: 4 aligned fields, no padding
    let hex_template = "0009000100000e1061db09bd00000001000000010000001801000004\
                         00080004000c0004000a0004000e0004";

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let template_bytes = hex::decode(hex_template).unwrap();
    let result = parser.parse_bytes(&template_bytes);

    if let Some(NetflowPacket::V9(v9)) = result.packets.first() {
        let serialized = v9.to_be_bytes().expect("V9 template serialization failed");
        assert_eq!(
            serialized, template_bytes,
            "V9 template packet round-trip failed"
        );
    } else {
        panic!("Expected V9 template packet");
    }
}

// ---------------------------------------------------------------------------
// IPFIX template + data round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_ipfix_template_and_data_round_trip() {
    // IPFIX template: Set ID=2, template_id=256, 4 aligned fields:
    //   sourceIPv4Address(8) len=4, destinationIPv4Address(12) len=4,
    //   ingressInterface(10) len=4, egressInterface(14) len=4
    // Record size = 16 bytes (4-byte aligned, no padding)
    // IPFIX header: version=10, length=40, exportTime, seqNum=8, obsDomainId
    // Template set: setId=2, length=24 (4 header + 4 template header + 16 fields)
    let hex_template = "000a002862a0b1b9000000086c6a7e11\
                         000200180100000400080004000c0004000a0004000e0004";

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let template_bytes = hex::decode(hex_template).unwrap();
    let template_result = parser.parse_bytes(&template_bytes);
    assert!(template_result.error.is_none(), "IPFIX template parse failed");

    // IPFIX data: src=192.168.1.1, dst=10.0.0.1, ingress=10, egress=20
    // Data set: setId=256, length=20 (4 header + 16 data)
    // IPFIX header: length=36 (16 header + 20 data set)
    let hex_data = "000a002462a0b1b9000000096c6a7e11\
                    01000014c0a801010a0000010000000a00000014";

    let data_bytes = hex::decode(hex_data).unwrap();
    let data_result = parser.parse_bytes(&data_bytes);

    if let Some(NetflowPacket::IPFix(ipfix)) = data_result.packets.first() {
        let serialized = ipfix.to_be_bytes().expect("IPFIX serialization failed");
        assert_eq!(
            serialized, data_bytes,
            "IPFIX data packet round-trip failed"
        );
    } else {
        panic!("Expected IPFIX data packet");
    }
}

#[test]
fn test_ipfix_template_only_round_trip() {
    let hex_template = "000a002462a0b1b9000000086c6a7e11\
                         000200140100000300080004000c000400040001";

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let template_bytes = hex::decode(hex_template).unwrap();
    let result = parser.parse_bytes(&template_bytes);

    if let Some(NetflowPacket::IPFix(ipfix)) = result.packets.first() {
        let serialized = ipfix.to_be_bytes().expect("IPFIX template serialization failed");
        assert_eq!(
            serialized, template_bytes,
            "IPFIX template packet round-trip failed"
        );
    } else {
        panic!("Expected IPFIX template packet");
    }
}

// ---------------------------------------------------------------------------
// Individual IANA field type round-trips via FieldValue
// ---------------------------------------------------------------------------

/// Helper: parse raw bytes as a given FieldDataType, then write_be_bytes, assert equal.
fn assert_field_round_trip(raw: &[u8], data_type: FieldDataType) {
    let (remaining, field_value) =
        FieldValue::from_field_type(raw, data_type.clone(), raw.len() as u16)
            .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", data_type, e));
    assert!(
        remaining.is_empty(),
        "leftover bytes for {:?}: {} remaining",
        data_type,
        remaining.len()
    );
    let mut buf = Vec::new();
    field_value
        .write_be_bytes(&mut buf)
        .unwrap_or_else(|e| panic!("write failed for {:?}: {:?}", data_type, e));
    assert_eq!(
        buf, raw,
        "round-trip failed for {:?}: expected {:?}, got {:?}",
        data_type, raw, buf
    );
}

#[test]
fn test_field_round_trip_forwarding_status() {
    // 0x40 = status=1 (Forwarded), reason=0
    assert_field_round_trip(&[0x40], FieldDataType::ForwardingStatus);
    // 0xC3 = status=3 (Consumed), reason=3
    assert_field_round_trip(&[0xC3], FieldDataType::ForwardingStatus);
}

#[test]
fn test_field_round_trip_fragment_flags() {
    // 0x05 = reserved=true, more_fragments=true
    assert_field_round_trip(&[0x05], FieldDataType::FragmentFlags);
    // 0x02 = dont_fragment=true
    assert_field_round_trip(&[0x02], FieldDataType::FragmentFlags);
}

#[test]
fn test_field_round_trip_tcp_control_bits() {
    // 0x0012 = SYN + ACK
    assert_field_round_trip(&[0x00, 0x12], FieldDataType::TcpControlBits);
    // 0x01FF = all 9 flags set
    assert_field_round_trip(&[0x01, 0xFF], FieldDataType::TcpControlBits);
}

#[test]
fn test_field_round_trip_ipv6_extension_headers() {
    assert_field_round_trip(&[0x00, 0x00, 0x00, 0x3F], FieldDataType::Ipv6ExtensionHeaders);
    assert_field_round_trip(&[0xFF, 0xFF, 0xFF, 0xFF], FieldDataType::Ipv6ExtensionHeaders);
}

#[test]
fn test_field_round_trip_ipv4_options() {
    assert_field_round_trip(&[0x00, 0x7F, 0xFF, 0xFF], FieldDataType::Ipv4Options);
    assert_field_round_trip(&[0xFF, 0xFF, 0xFF, 0xFF], FieldDataType::Ipv4Options);
}

#[test]
fn test_field_round_trip_tcp_options() {
    assert_field_round_trip(
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        FieldDataType::TcpOptions,
    );
    assert_field_round_trip(
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        FieldDataType::TcpOptions,
    );
}

#[test]
fn test_field_round_trip_is_multicast() {
    assert_field_round_trip(&[0x00], FieldDataType::IsMulticast);
    assert_field_round_trip(&[0x01], FieldDataType::IsMulticast);
    assert_field_round_trip(&[0xFF], FieldDataType::IsMulticast);
}

#[test]
fn test_field_round_trip_mpls_label_exp() {
    // Only 3 bits are preserved (0-7)
    assert_field_round_trip(&[0x00], FieldDataType::MplsLabelExp);
    assert_field_round_trip(&[0x07], FieldDataType::MplsLabelExp);
}

#[test]
fn test_field_round_trip_flow_end_reason() {
    assert_field_round_trip(&[0x01], FieldDataType::FlowEndReason); // IdleTimeout
    assert_field_round_trip(&[0x05], FieldDataType::FlowEndReason); // LackOfResources
    assert_field_round_trip(&[0xFF], FieldDataType::FlowEndReason); // Unknown(255)
}

#[test]
fn test_field_round_trip_nat_event() {
    assert_field_round_trip(&[0x01], FieldDataType::NatEvent); // NatCreateEvent
    assert_field_round_trip(&[0x12], FieldDataType::NatEvent); // NatQuotaExceeded
    assert_field_round_trip(&[0xFF], FieldDataType::NatEvent); // Unknown(255)
}

#[test]
fn test_field_round_trip_firewall_event() {
    assert_field_round_trip(&[0x00], FieldDataType::FirewallEvent); // Ignored
    assert_field_round_trip(&[0x05], FieldDataType::FirewallEvent); // FlowUpdate
    assert_field_round_trip(&[0xAB], FieldDataType::FirewallEvent); // Unknown(171)
}

#[test]
fn test_field_round_trip_mpls_top_label_type() {
    assert_field_round_trip(&[0x00], FieldDataType::MplsTopLabelType); // Unknown
    assert_field_round_trip(&[0x06], FieldDataType::MplsTopLabelType); // Vpn
    assert_field_round_trip(&[0x7F], FieldDataType::MplsTopLabelType); // Unassigned(127)
}

#[test]
fn test_field_round_trip_nat_originating_address_realm() {
    assert_field_round_trip(&[0x01], FieldDataType::NatOriginatingAddressRealm); // Private
    assert_field_round_trip(&[0x02], FieldDataType::NatOriginatingAddressRealm); // Public
    assert_field_round_trip(&[0x00], FieldDataType::NatOriginatingAddressRealm); // Unknown(0)
}

// ---------------------------------------------------------------------------
// Already-covered types: verify they still work
// ---------------------------------------------------------------------------

#[test]
fn test_field_round_trip_ip4addr() {
    assert_field_round_trip(&[192, 168, 0, 1], FieldDataType::Ip4Addr);
}

#[test]
fn test_field_round_trip_ip6addr() {
    assert_field_round_trip(
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        FieldDataType::Ip6Addr,
    );
}

#[test]
fn test_field_round_trip_mac_addr() {
    assert_field_round_trip(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7], FieldDataType::MacAddr);
}

#[test]
fn test_field_round_trip_protocol_type() {
    assert_field_round_trip(&[6], FieldDataType::ProtocolType); // TCP
    assert_field_round_trip(&[17], FieldDataType::ProtocolType); // UDP
}

#[test]
fn test_field_round_trip_unsigned_data_number() {
    // 1 byte
    assert_field_round_trip(&[42], FieldDataType::UnsignedDataNumber);
    // 2 bytes
    assert_field_round_trip(&[0x30, 0x39], FieldDataType::UnsignedDataNumber);
    // 4 bytes
    assert_field_round_trip(&[0x01, 0x02, 0x03, 0x04], FieldDataType::UnsignedDataNumber);
    // 8 bytes
    assert_field_round_trip(
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        FieldDataType::UnsignedDataNumber,
    );
}

#[test]
fn test_field_round_trip_signed_data_number() {
    // 1 byte
    assert_field_round_trip(&[0x80], FieldDataType::SignedDataNumber); // -128
    // 2 bytes
    assert_field_round_trip(&[0xFF, 0x00], FieldDataType::SignedDataNumber);
    // 3 bytes
    assert_field_round_trip(&[0xFF, 0x80, 0x00], FieldDataType::SignedDataNumber);
    // 4 bytes
    assert_field_round_trip(&[0xFF, 0xFF, 0xFF, 0xFE], FieldDataType::SignedDataNumber);
    // 8 bytes
    assert_field_round_trip(
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE],
        FieldDataType::SignedDataNumber,
    );
}

#[test]
fn test_field_round_trip_float64() {
    let bytes = 123.456f64.to_be_bytes();
    assert_field_round_trip(&bytes, FieldDataType::Float64);
}

#[test]
fn test_field_round_trip_duration_seconds() {
    // 4 bytes
    assert_field_round_trip(&[0x00, 0x00, 0x30, 0x39], FieldDataType::DurationSeconds);
    // 8 bytes
    assert_field_round_trip(
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39],
        FieldDataType::DurationSeconds,
    );
}

#[test]
fn test_field_round_trip_duration_millis() {
    // 4 bytes
    assert_field_round_trip(&[0x00, 0x01, 0x51, 0x80], FieldDataType::DurationMillis);
    // 8 bytes
    assert_field_round_trip(
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x51, 0x80],
        FieldDataType::DurationMillis,
    );
}

#[test]
fn test_field_round_trip_string() {
    assert_field_round_trip(b"hello", FieldDataType::String);
}

// ---------------------------------------------------------------------------
// FieldValue direct construction round-trips for write_be_bytes
// ---------------------------------------------------------------------------

#[test]
fn test_field_value_application_id_round_trip() {
    // 1 byte engine ID + 3 byte selector = 4 bytes total
    let raw = &[0x0A, 0x01, 0x02, 0x03];
    let (remaining, field_value) =
        FieldValue::from_field_type(raw, FieldDataType::ApplicationId, 4).unwrap();
    assert!(remaining.is_empty());

    let mut buf = Vec::new();
    field_value.write_be_bytes(&mut buf).unwrap();
    assert_eq!(buf, raw, "ApplicationId round-trip failed");
}

#[test]
fn test_field_value_application_id_1_byte() {
    // 1 byte engine ID only, no selector
    let raw = &[0x05];
    let (remaining, field_value) =
        FieldValue::from_field_type(raw, FieldDataType::ApplicationId, 1).unwrap();
    assert!(remaining.is_empty());

    let mut buf = Vec::new();
    field_value.write_be_bytes(&mut buf).unwrap();
    assert_eq!(buf, raw, "ApplicationId 1-byte round-trip failed");
}

// ---------------------------------------------------------------------------
// Typed field with wrong length falls back to Vec (still round-trips)
// ---------------------------------------------------------------------------

#[test]
fn test_field_wrong_length_fallback_round_trips() {
    // Ip4Addr expects 4 bytes; give it 8 → falls back to Vec
    let raw = &[1, 2, 3, 4, 5, 6, 7, 8];
    let (remaining, field_value) =
        FieldValue::from_field_type(raw, FieldDataType::Ip4Addr, 8).unwrap();
    assert!(remaining.is_empty());
    assert!(matches!(field_value, FieldValue::Vec(_)));

    let mut buf = Vec::new();
    field_value.write_be_bytes(&mut buf).unwrap();
    assert_eq!(buf, raw, "Vec fallback round-trip failed");
}
