//! Chained export packets must each be routed to their own scoped parser.
//!
//! The reproducer in `chained_ipfix_messages_are_scoped_by_each_domain` comes
//! from Costa Tsaousis (netflow_parser#325).

use std::net::SocketAddr;

use netflow_parser::{AutoScopedParser, NetflowPacket};

/// One IPFIX message carrying a single Template Set with one field spec.
fn template_message(domain: u32, template_id: u16, ie: u16, field_len: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&28u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&domain.to_be_bytes());
    message.extend_from_slice(&2u16.to_be_bytes());
    message.extend_from_slice(&12u16.to_be_bytes());
    message.extend_from_slice(&template_id.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&ie.to_be_bytes());
    message.extend_from_slice(&field_len.to_be_bytes());
    message
}

/// One IPFIX message carrying a single Data Set with a 4-byte record.
fn data_message(domain: u32, template_id: u16, payload: [u8; 4]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&24u16.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());
    message.extend_from_slice(&4u32.to_be_bytes());
    message.extend_from_slice(&domain.to_be_bytes());
    message.extend_from_slice(&template_id.to_be_bytes());
    message.extend_from_slice(&8u16.to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

fn source() -> SocketAddr {
    "192.0.2.1:2055".parse().unwrap()
}

/// Render the first decoded field of the first data record as `"Name=Value"`.
fn first_field(packets: &[NetflowPacket]) -> String {
    let data = packets
        .iter()
        .filter_map(|p| match p {
            NetflowPacket::IPFix(i) => Some(i),
            _ => None,
        })
        .flat_map(|ipfix| ipfix.flowsets.iter())
        .find_map(|fs| match &fs.body {
            netflow_parser::variable_versions::ipfix::FlowSetBody::Data(d) => Some(d),
            _ => None,
        })
        .expect("expected a Data FlowSet");

    let (key, value) = data
        .fields
        .first()
        .and_then(|record| record.first())
        .expect("expected one decoded field");

    format!("{key:?}={value:?}")
}

#[test]
fn chained_ipfix_messages_are_scoped_by_each_domain() {
    let mut batch = template_message(1, 256, 1, 4);
    batch.extend_from_slice(&template_message(2, 257, 1, 4));

    let mut parser = AutoScopedParser::new();
    let result = parser.parse_from_source(source(), &batch);

    assert!(result.error.is_none(), "{:#?}", result.error);
    assert_eq!(result.packets.len(), 2);
    assert_eq!(parser.ipfix_source_count(), 2);
}

/// Two domains reusing one Template ID with different layouts must not share a
/// template cache. Before the routing fix, the chained batch parsed without
/// error but decoded domain 1's `sourceIPv4Address` as `packetDeltaCount`.
#[test]
fn chained_domains_reusing_a_template_id_do_not_corrupt_decoding() {
    // IE 8 = sourceIPv4Address, IE 2 = packetDeltaCount. Both 4 bytes wide, so
    // the layouts differ only in meaning and the misdecode is silent.
    let mut batch = template_message(1, 256, 8, 4);
    batch.extend_from_slice(&template_message(2, 256, 2, 4));

    let mut chained = AutoScopedParser::new();
    let setup = chained.parse_from_source(source(), &batch);
    assert!(setup.error.is_none(), "{:#?}", setup.error);
    assert_eq!(chained.ipfix_source_count(), 2);

    let chained_out =
        chained.parse_from_source(source(), &data_message(1, 256, [192, 0, 2, 1]));
    assert!(chained_out.error.is_none(), "{:#?}", chained_out.error);

    // Same templates delivered one per call: the already-correct path.
    let mut separate = AutoScopedParser::new();
    let _ = separate.parse_from_source(source(), &template_message(1, 256, 8, 4));
    let _ = separate.parse_from_source(source(), &template_message(2, 256, 2, 4));
    let separate_out =
        separate.parse_from_source(source(), &data_message(1, 256, [192, 0, 2, 1]));
    assert!(separate_out.error.is_none(), "{:#?}", separate_out.error);

    // Chaining must not change how domain 1's record decodes.
    assert_eq!(
        first_field(&chained_out.packets),
        first_field(&separate_out.packets),
    );
    assert!(
        first_field(&chained_out.packets).contains("SourceIpv4address"),
        "domain 1 decoded with the wrong template: {}",
        first_field(&chained_out.packets),
    );
}

#[test]
fn chained_messages_from_one_domain_still_share_a_parser() {
    let mut batch = template_message(7, 256, 8, 4);
    batch.extend_from_slice(&data_message(7, 256, [192, 0, 2, 9]));

    let mut parser = AutoScopedParser::new();
    let result = parser.parse_from_source(source(), &batch);

    assert!(result.error.is_none(), "{:#?}", result.error);
    assert_eq!(result.packets.len(), 2);
    // The data record resolved against the template from the same batch, which
    // only works if both messages shared one parser.
    assert_eq!(parser.ipfix_source_count(), 1);
    assert!(first_field(&result.packets).contains("SourceIpv4address"));
}
