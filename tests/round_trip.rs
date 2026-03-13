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
    for (i, byte) in packet.iter_mut().enumerate().skip(4) {
        *byte = (i % 256) as u8;
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
        assert_eq!(serialized, data_bytes, "V9 data packet round-trip failed");
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
    assert!(
        template_result.error.is_none(),
        "IPFIX template parse failed"
    );

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
        let serialized = ipfix
            .to_be_bytes()
            .expect("IPFIX template serialization failed");
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
    assert_field_round_trip(
        &[0x00, 0x00, 0x00, 0x3F],
        FieldDataType::Ipv6ExtensionHeaders,
    );
    assert_field_round_trip(
        &[0xFF, 0xFF, 0xFF, 0xFF],
        FieldDataType::Ipv6ExtensionHeaders,
    );
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
    assert_field_round_trip(
        &[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7],
        FieldDataType::MacAddr,
    );
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

// ---------------------------------------------------------------------------
// IPFIX variable-length field round-trips (RFC 7011 Section 7)
// ---------------------------------------------------------------------------

/// Build an IPFIX message from raw template set bytes and data set bytes.
fn build_ipfix_message(export_time: u32, seq: u32, obs_domain: u32, sets: &[u8]) -> Vec<u8> {
    let total_len = (16 + sets.len()) as u16;
    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&10u16.to_be_bytes()); // version
    msg.extend_from_slice(&total_len.to_be_bytes()); // length
    msg.extend_from_slice(&export_time.to_be_bytes());
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&obs_domain.to_be_bytes());
    msg.extend_from_slice(sets);
    msg
}

/// Build an IPFIX template set (Set ID = 2) with the given template_id and
/// field definitions as (field_type_number, field_length) pairs.
fn build_ipfix_template_set(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    // Set header (4) + template header (4) + fields (4 each)
    let set_len = (4 + 4 + fields.len() * 4) as u16;
    let mut set = Vec::with_capacity(set_len as usize);
    set.extend_from_slice(&2u16.to_be_bytes()); // Set ID = 2 (template)
    set.extend_from_slice(&set_len.to_be_bytes());
    set.extend_from_slice(&template_id.to_be_bytes());
    set.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for &(type_num, length) in fields {
        set.extend_from_slice(&type_num.to_be_bytes());
        set.extend_from_slice(&length.to_be_bytes());
    }
    set
}

#[test]
fn test_ipfix_varlen_short_round_trip() {
    // Template: sourceIPv4Address(8) len=4, applicationDescription(94) len=65535
    let template_set = build_ipfix_template_set(256, &[(8, 4), (94, 65535)]);
    let template_msg = build_ipfix_message(0x62A0B1B9, 8, 1, &template_set);

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let result = parser.parse_bytes(&template_msg);
    assert!(result.error.is_none(), "Template parse failed");

    // Data: src=192.168.1.1, varlen "abc" (1-byte prefix: 0x03)
    // Record = 4 + 1 + 3 = 8 bytes (4-byte aligned)
    let mut data_set = Vec::new();
    data_set.extend_from_slice(&256u16.to_be_bytes()); // Set ID
    data_set.extend_from_slice(&12u16.to_be_bytes()); // Set length = 4 header + 8 body
    data_set.extend_from_slice(&[192, 168, 1, 1]); // sourceIPv4Address
    data_set.push(3); // varlen prefix: length=3
    data_set.extend_from_slice(b"abc"); // applicationDescription

    let data_msg = build_ipfix_message(0x62A0B1B9, 9, 1, &data_set);
    let data_result = parser.parse_bytes(&data_msg);
    assert!(
        data_result.error.is_none(),
        "Data parse failed: {:?}",
        data_result.error
    );

    if let Some(NetflowPacket::IPFix(ipfix)) = data_result.packets.first() {
        let serialized = ipfix
            .to_be_bytes()
            .expect("IPFIX varlen serialization failed");
        assert_eq!(
            serialized, data_msg,
            "IPFIX varlen short field round-trip failed"
        );
    } else {
        panic!("Expected IPFIX data packet");
    }
}

#[test]
fn test_ipfix_varlen_long_round_trip() {
    // Template: single variable-length string field
    // Using interfaceDescription (83) as a variable-length string field
    let template_set = build_ipfix_template_set(257, &[(83, 65535)]);
    let template_msg = build_ipfix_message(0x62A0B1B9, 10, 1, &template_set);

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let result = parser.parse_bytes(&template_msg);
    assert!(result.error.is_none(), "Template parse failed");

    // Data with 3-byte prefix (value length = 300 bytes, >= 255)
    let value_len: u16 = 300;
    let value: Vec<u8> = (0..value_len).map(|i| (i % 26 + 0x61) as u8).collect(); // "abcdef..."

    let body_len = 3 + value_len as usize; // 3-byte prefix + 300 bytes
    let padding_needed = (4 - (body_len % 4)) % 4;
    let set_len = 4 + body_len + padding_needed;

    let mut data_set = Vec::new();
    data_set.extend_from_slice(&257u16.to_be_bytes()); // Set ID
    data_set.extend_from_slice(&(set_len as u16).to_be_bytes());
    data_set.push(255); // varlen marker: length >= 255
    data_set.extend_from_slice(&value_len.to_be_bytes()); // 2-byte length
    data_set.extend_from_slice(&value);
    // Padding
    for _ in 0..padding_needed {
        data_set.push(0);
    }

    let data_msg = build_ipfix_message(0x62A0B1B9, 11, 1, &data_set);
    let data_result = parser.parse_bytes(&data_msg);
    assert!(
        data_result.error.is_none(),
        "Long varlen data parse failed: {:?}",
        data_result.error
    );

    if let Some(NetflowPacket::IPFix(ipfix)) = data_result.packets.first() {
        let serialized = ipfix
            .to_be_bytes()
            .expect("IPFIX long varlen serialization failed");
        assert_eq!(
            serialized, data_msg,
            "IPFIX varlen long field (3-byte prefix) round-trip failed"
        );
    } else {
        panic!("Expected IPFIX data packet");
    }
}

#[test]
fn test_ipfix_mixed_fixed_and_varlen_round_trip() {
    // Template: fixed(4) + varlen + fixed(4) — varlen field sandwiched between fixed
    // sourceIPv4Address(8) len=4, applicationDescription(94) len=65535, egressInterface(14) len=4
    let template_set = build_ipfix_template_set(258, &[(8, 4), (94, 65535), (14, 4)]);
    let template_msg = build_ipfix_message(0x62A0B1B9, 12, 1, &template_set);

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let result = parser.parse_bytes(&template_msg);
    assert!(result.error.is_none(), "Template parse failed");

    // Data: src=10.0.0.1, varlen "test" (4 bytes, 1-byte prefix), egress=42
    // Record = 4 + 1 + 4 + 4 = 13 bytes → 3 bytes padding to reach 16
    let mut data_set = Vec::new();
    data_set.extend_from_slice(&258u16.to_be_bytes());
    let body_len = 4 + 1 + 4 + 4; // 13
    let padding = (4 - (body_len % 4)) % 4; // 3
    let set_len = 4 + body_len + padding;
    data_set.extend_from_slice(&(set_len as u16).to_be_bytes());
    data_set.extend_from_slice(&[10, 0, 0, 1]); // sourceIPv4Address
    data_set.push(4); // varlen prefix: length=4
    data_set.extend_from_slice(b"test"); // applicationDescription
    data_set.extend_from_slice(&42u32.to_be_bytes()); // egressInterface
    for _ in 0..padding {
        data_set.push(0);
    }

    let data_msg = build_ipfix_message(0x62A0B1B9, 13, 1, &data_set);
    let data_result = parser.parse_bytes(&data_msg);
    assert!(
        data_result.error.is_none(),
        "Mixed parse failed: {:?}",
        data_result.error
    );

    if let Some(NetflowPacket::IPFix(ipfix)) = data_result.packets.first() {
        let serialized = ipfix
            .to_be_bytes()
            .expect("Mixed varlen serialization failed");
        assert_eq!(
            serialized, data_msg,
            "IPFIX mixed fixed+varlen round-trip failed"
        );
    } else {
        panic!("Expected IPFIX data packet");
    }
}

#[test]
fn test_ipfix_fixed_only_template_no_varlen_overhead() {
    // Verify that a template with only fixed-length fields does NOT
    // populate template_field_lengths (optimization check).
    let hex_template = "000a002862a0b1b9000000086c6a7e11\
                         000200180100000400080004000c0004000a0004000e0004";

    let mut parser = NetflowParser::builder()
        .with_cache_size(100)
        .build()
        .unwrap();

    let template_bytes = hex::decode(hex_template).unwrap();
    let _ = parser.parse_bytes(&template_bytes);

    // Parse data
    let hex_data = "000a002462a0b1b9000000096c6a7e11\
                    01000014c0a801010a0000010000000a00000014";
    let data_bytes = hex::decode(hex_data).unwrap();
    let data_result = parser.parse_bytes(&data_bytes);

    if let Some(NetflowPacket::IPFix(ipfix)) = data_result.packets.first() {
        // Verify round-trip still works
        let serialized = ipfix.to_be_bytes().expect("serialization failed");
        assert_eq!(serialized, data_bytes);

        // Verify template_field_lengths is empty (optimization)
        for flowset in &ipfix.flowsets {
            if let netflow_parser::variable_versions::ipfix::FlowSetBody::Data(data) =
                &flowset.body
            {
                assert!(
                    !data.has_varlen_metadata(),
                    "template_field_lengths should be empty for fixed-length-only templates"
                );
            }
        }
    } else {
        panic!("Expected IPFIX data packet");
    }
}
