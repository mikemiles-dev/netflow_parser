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
fn four_octet_reduced_float64_value_is_decoded() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&311u16.to_be_bytes());
    template.extend_from_slice(&4u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    assert!(parser.parse_bytes(&message_with_set(2, &template)).is_ok());

    let decoded = parser.parse_bytes(&message_with_set(256, &1.5f32.to_be_bytes()));
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
        panic!("expected IPFIX packet");
    };
    let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
        panic!("expected IPFIX data");
    };
    assert!(matches!(
        data.fields[0][0].1,
        FieldValue::Float64(value) if value == 1.5
    ));
    assert_eq!(
        packet.to_be_bytes().unwrap(),
        message_with_set(256, &1.5f32.to_be_bytes())
    );
}
