use netflow_parser::{NetflowPacket, NetflowParser};

#[test]
fn test_parse_v5_packet() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let packets = NetflowParser::default().parse_bytes(&v5_packet).packets;
    assert_eq!(packets.len(), 1);

    match packets.first().unwrap() {
        NetflowPacket::V5(v5) => {
            assert_eq!(v5.header.version, 5);
            assert_eq!(v5.header.count, 1);
        }
        _ => panic!("Expected V5 packet"),
    }
}

#[test]
fn test_parse_v5_with_version_filter() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    // Allow only V9
    let mut parser = NetflowParser::builder()
        .with_allowed_versions([9].into())
        .build()
        .expect("Failed to build parser");

    let packets = parser.parse_bytes(&v5_packet).packets;
    assert_eq!(packets.len(), 0); // Should be filtered out
}

#[test]
fn test_filter_v5_packets() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let parsed = NetflowParser::default().parse_bytes(&v5_packet).packets;
    let v5_parsed: Vec<NetflowPacket> = parsed.into_iter().filter(|p| p.is_v5()).collect();

    assert_eq!(v5_parsed.len(), 1);
    assert!(v5_parsed.first().unwrap().is_v5());
}

#[test]
fn test_v5_round_trip() {
    let packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    if let NetflowPacket::V5(v5) = NetflowParser::default()
        .parse_bytes(&packet)
        .packets
        .first()
        .unwrap()
    {
        assert_eq!(v5.to_be_bytes(), packet);
    } else {
        panic!("Expected V5 packet");
    }
}

#[test]
fn test_iterator_api() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let mut parser = NetflowParser::default();
    let mut count = 0;

    for packet in parser.iter_packets(&v5_packet) {
        count += 1;
        assert!(packet.unwrap().is_v5());
    }

    assert_eq!(count, 1);
}

#[test]
fn test_iterator_completion() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let mut parser = NetflowParser::default();
    let mut iter = parser.iter_packets(&v5_packet);

    while iter.next().is_some() {}

    assert!(iter.is_complete());
    assert_eq!(iter.remaining().len(), 0);
}

#[test]
fn test_iterator_filter() {
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let mut parser = NetflowParser::default();
    let count = parser
        .iter_packets(&v5_packet)
        .filter_map(|p| p.ok())
        .filter(|p| p.is_v5())
        .count();

    assert_eq!(count, 1);
}
