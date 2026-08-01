use netflow_parser::variable_versions::field_value::FieldValue;
use netflow_parser::variable_versions::ipfix::FlowSetBody;
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
fn variable_length_ie266_is_decoded_as_opaque_octets() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&266u16.to_be_bytes());
    template.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut parser = NetflowParser::default();
    assert!(parser.parse_bytes(&message_with_set(2, &template)).is_ok());

    let value = vec![0x5a; 300];
    let mut wire = vec![255, 1, 44];
    wire.extend_from_slice(&value);
    let decoded = parser.parse_bytes(&message_with_set(256, &wire));
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
        panic!("expected IPFIX packet");
    };
    let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
        panic!("expected IPFIX data");
    };
    assert!(matches!(
        &data.fields[0][0].1,
        FieldValue::Vec(parsed) if parsed == &value
    ));
}
