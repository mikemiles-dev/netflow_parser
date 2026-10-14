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
fn reduced_forwarding_status_is_decoded_as_an_unsigned_value() {
    for (field_length, field_value) in [
        (2u16, &[0, 1][..]),
        (3, &[0, 0, 1][..]),
        (4, &[0, 0, 0, 1][..]),
    ] {
        let mut template = Vec::new();
        template.extend_from_slice(&256u16.to_be_bytes());
        template.extend_from_slice(&1u16.to_be_bytes());
        template.extend_from_slice(&89u16.to_be_bytes());
        template.extend_from_slice(&field_length.to_be_bytes());

        let mut parser = NetflowParser::default();
        assert!(parser.parse_bytes(&message_with_set(2, &template)).is_ok());

        let decoded = parser.parse_bytes(&message_with_set(256, field_value));
        assert!(decoded.error.is_none(), "{:#?}", decoded.error);
        let NetflowPacket::IPFix(packet) = &decoded.packets[0] else {
            panic!("expected IPFIX packet");
        };
        let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
            panic!("expected IPFIX data");
        };
        assert_eq!(data.fields[0][0].1.as_u64(), Some(1));
    }
}
