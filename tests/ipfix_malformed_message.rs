use netflow_parser::NetflowParser;

fn append_set(message: &mut Vec<u8>, id: u16, body: &[u8]) {
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    message.extend_from_slice(body);
}

#[test]
fn malformed_message_does_not_commit_an_earlier_template() {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());

    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&4u16.to_be_bytes());
    append_set(&mut message, 2, &template);

    message.extend_from_slice(&2u16.to_be_bytes());
    message.extend_from_slice(&3u16.to_be_bytes());
    let length = u16::try_from(message.len()).unwrap();
    message[2..4].copy_from_slice(&length.to_be_bytes());

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message);

    assert!(result.error.is_some());
    assert!(result.packets.is_empty());
    assert!(!parser.has_ipfix_template(256));
}
