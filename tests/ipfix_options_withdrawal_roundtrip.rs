use netflow_parser::{NetflowPacket, NetflowParser};

fn message_with_set(id: u16, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(20 + body.len()).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    message.extend_from_slice(body);
    message
}

#[test]
fn reexport_preserves_an_options_template_withdrawal() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&149u16.to_be_bytes());
    template.extend_from_slice(&4u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    assert!(parser.parse_bytes(&message_with_set(3, &template)).is_ok());

    let mut withdrawal = Vec::new();
    withdrawal.extend_from_slice(&256u16.to_be_bytes());
    withdrawal.extend_from_slice(&0u16.to_be_bytes());
    let wire = message_with_set(3, &withdrawal);
    let decoded = parser.parse_bytes(&wire);
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
        panic!("expected IPFIX packet");
    };

    assert_eq!(packet.flowsets.len(), 1);
    assert_eq!(packet.to_be_bytes().unwrap(), wire);
}
