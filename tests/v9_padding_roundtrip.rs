use netflow_parser::variable_versions::v9::FlowSetBody;
use netflow_parser::{NetflowPacket, NetflowParser};

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
fn reexport_preserves_nonzero_data_flowset_padding() {
    let mut template = Vec::new();
    template.extend_from_slice(&256u16.to_be_bytes());
    template.extend_from_slice(&1u16.to_be_bytes());
    template.extend_from_slice(&82u16.to_be_bytes());
    template.extend_from_slice(&5u16.to_be_bytes());
    let mut template_packet = header();
    append_flowset(&mut template_packet, 0, &template);

    let mut parser = NetflowParser::default();
    let learned = parser.parse_bytes(&template_packet);
    assert!(learned.error.is_none(), "{:#?}", learned.error);

    let mut body = b"hello".to_vec();
    body.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    let mut wire = header();
    append_flowset(&mut wire, 256, &body);
    let decoded = parser.parse_bytes(&wire);
    assert!(decoded.error.is_none(), "{:#?}", decoded.error);
    let NetflowPacket::V9(packet) = &decoded.packets[0] else {
        panic!("expected NetFlow v9 packet");
    };
    let FlowSetBody::Data(data) = &packet.flowsets[0].body else {
        panic!("expected NetFlow v9 data");
    };

    assert_eq!(data.padding, [0xaa, 0xbb, 0xcc]);
    assert_eq!(packet.to_be_bytes().unwrap(), wire);
}
