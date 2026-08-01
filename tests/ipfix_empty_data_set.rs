use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ipfix::{
    Data, FlowSet, FlowSetBody, FlowSetHeader, Header, IPFix,
};

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
fn empty_known_template_data_set_is_rejected() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&4u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    assert!(parser.parse_bytes(&message_with_set(2, &template)).is_ok());

    assert!(parser.parse_bytes(&message_with_set(256, &[])).is_err());
}

#[test]
fn empty_unknown_template_data_set_is_rejected() {
    assert!(
        NetflowParser::default()
            .parse_bytes(&message_with_set(257, &[]))
            .is_err()
    );
}

#[test]
fn empty_data_set_is_not_serialized() {
    let packet = IPFix {
        header: Header {
            version: 10,
            length: 20,
            export_time: 1,
            sequence_number: 2,
            observation_domain_id: 3,
        },
        flowsets: vec![FlowSet {
            header: FlowSetHeader {
                header_id: 256,
                length: 4,
            },
            body: FlowSetBody::Data(Data::new(Vec::new())),
        }],
    };

    assert!(packet.to_be_bytes().is_err());
}
