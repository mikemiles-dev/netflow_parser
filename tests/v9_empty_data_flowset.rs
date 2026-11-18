use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::v9::{
    Data, FlowSet, FlowSetBody, FlowSetHeader, Header, V9,
};

fn header() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&9u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&2u32.to_be_bytes());
    packet.extend_from_slice(&3u32.to_be_bytes());
    packet.extend_from_slice(&4u32.to_be_bytes());
    packet
}

fn append_flowset(packet: &mut Vec<u8>, id: u16, body: &[u8]) {
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    packet.extend_from_slice(body);
}

#[test]
fn empty_known_template_data_flowset_is_rejected() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&4u16.to_be_bytes());
    let mut template_packet = header();
    append_flowset(&mut template_packet, 0, &template);

    let mut parser = NetflowParser::default();
    assert!(parser.parse_bytes(&template_packet).is_ok());

    let mut empty_data = header();
    append_flowset(&mut empty_data, 256, &[]);
    assert!(parser.parse_bytes(&empty_data).is_err());
}

#[test]
fn empty_unknown_template_data_flowset_is_rejected() {
    let mut empty_data = header();
    append_flowset(&mut empty_data, 257, &[]);

    assert!(NetflowParser::default().parse_bytes(&empty_data).is_err());
}

#[test]
fn empty_data_flowset_is_not_serialized() {
    let packet = V9 {
        header: Header {
            version: 9,
            count: 1,
            sys_up_time: 1,
            unix_secs: 2,
            sequence_number: 3,
            source_id: 4,
        },
        flowsets: vec![FlowSet {
            header: FlowSetHeader {
                flowset_id: 256,
                length: 4,
            },
            body: FlowSetBody::Data(Data::new(Vec::new())),
        }],
    };

    assert!(packet.to_be_bytes().is_err());
}
