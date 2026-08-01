use netflow_parser::NetflowParser;

#[test]
fn template_id_255_is_rejected() {
    let mut packet = Vec::new();
    packet.extend_from_slice(&9u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&2u32.to_be_bytes());
    packet.extend_from_slice(&3u32.to_be_bytes());
    packet.extend_from_slice(&4u32.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&255u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());

    assert!(NetflowParser::default().parse_bytes(&packet).is_err());
}

#[test]
fn options_template_id_255_is_rejected() {
    let mut packet = Vec::new();
    packet.extend_from_slice(&9u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&2u32.to_be_bytes());
    packet.extend_from_slice(&3u32.to_be_bytes());
    packet.extend_from_slice(&4u32.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&18u16.to_be_bytes());
    packet.extend_from_slice(&255u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&4u16.to_be_bytes());

    assert!(NetflowParser::default().parse_bytes(&packet).is_err());
}
