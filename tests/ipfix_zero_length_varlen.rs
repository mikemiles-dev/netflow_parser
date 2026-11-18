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
fn one_octet_zero_length_value_is_a_data_record() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&82u16.to_be_bytes());
    template.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut parser = NetflowParser::default();
    let learned = parser.parse_bytes(&message_with_set(2, &template));
    assert!(learned.error.is_none(), "{:#?}", learned.error);

    let data_message = message_with_set(256, &[0]);
    let decoded = parser.parse_bytes(&data_message);
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
        panic!("expected IPFIX packet");
    };
    let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
        panic!("expected IPFIX data");
    };
    assert_eq!(data.fields.len(), 1);
    assert!(matches!(
        &data.fields[0][0].1,
        FieldValue::String(value) if value.raw.is_empty()
    ));
    assert!(packet.to_be_bytes().is_ok());
}

#[test]
fn extended_zero_length_value_is_a_data_record() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&82u16.to_be_bytes());
    template.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut parser = NetflowParser::default();
    let learned = parser.parse_bytes(&message_with_set(2, &template));
    assert!(learned.error.is_none(), "{:#?}", learned.error);

    let decoded = parser.parse_bytes(&message_with_set(256, &[255, 0, 0]));
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
        panic!("expected IPFIX packet");
    };
    let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
        panic!("expected IPFIX data");
    };
    assert_eq!(data.fields.len(), 1);
    assert!(matches!(
        &data.fields[0][0].1,
        FieldValue::String(value) if value.raw.is_empty()
    ));
}
