//! A Set declaring an impossible length must be reported, not dropped silently.
//!
//! The reproducer in `malformed_message_does_not_commit_an_earlier_template`
//! comes from Costa Tsaousis (netflow_parser#310).

use netflow_parser::NetflowParser;

fn message(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&10u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // patched below
    m.extend_from_slice(&1u32.to_be_bytes());
    m.extend_from_slice(&2u32.to_be_bytes());
    m.extend_from_slice(&3u32.to_be_bytes());
    m.extend_from_slice(body);
    let len = u16::try_from(m.len()).unwrap();
    m[2..4].copy_from_slice(&len.to_be_bytes());
    m
}

/// Template Set defining Template 256 with one 4-octet sourceIPv4Address.
fn template_set() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&2u16.to_be_bytes());
    s.extend_from_slice(&12u16.to_be_bytes());
    s.extend_from_slice(&256u16.to_be_bytes());
    s.extend_from_slice(&1u16.to_be_bytes());
    s.extend_from_slice(&8u16.to_be_bytes());
    s.extend_from_slice(&4u16.to_be_bytes());
    s
}

/// Data Set for Template 256 carrying one record.
fn data_set(payload: [u8; 4]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&256u16.to_be_bytes());
    s.extend_from_slice(&8u16.to_be_bytes());
    s.extend_from_slice(&payload);
    s
}

fn data_record_count(packets: &[netflow_parser::NetflowPacket]) -> usize {
    packets
        .iter()
        .filter_map(|p| match p {
            netflow_parser::NetflowPacket::IPFix(i) => Some(i),
            _ => None,
        })
        .flat_map(|i| i.flowsets.iter())
        .map(|fs| match &fs.body {
            netflow_parser::variable_versions::ipfix::FlowSetBody::Data(d) => d.fields.len(),
            _ => 0,
        })
        .sum()
}

/// A Set length below the 4-octet Set Header cannot be walked past.
#[test]
fn malformed_set_length_is_reported() {
    let mut body = template_set();
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(result.error.is_some(), "malformed framing must be reported");
    assert!(result.packets.is_empty());
}

/// The remaining half of netflow_parser#310, which this framing check does not
/// address: the message is now rejected, but the Template Set in its valid
/// prefix was already committed to the cache before the framing error was
/// discovered. RFC 7011 Section 9.1 requires discarding the whole message, so
/// no state from it should survive.
///
/// Reaching this needs the parse to stage template/pending-flow/metric
/// mutations and commit them only once the message is known to be well formed.
/// Ignored until that transaction boundary exists; remove the attribute then.
#[test]
#[ignore = "requires transactional message-discard semantics; see netflow_parser#310"]
fn malformed_message_does_not_commit_an_earlier_template() {
    let mut body = template_set();
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(result.error.is_some());
    assert!(result.packets.is_empty());
    assert!(!parser.has_ipfix_template(256));
}

/// The case with teeth: a valid Data Set behind a malformed one was silently
/// discarded while the message still reported success.
#[test]
fn data_behind_a_malformed_set_is_not_silently_discarded() {
    let mut body = template_set();
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());
    body.extend_from_slice(&data_set([192, 0, 2, 2]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(
        result.error.is_some(),
        "losing a valid Data Set must not be reported as success"
    );
    assert_eq!(data_record_count(&result.packets), 0);
}

/// Truncation: a Set header claiming more octets than the message carries.
#[test]
fn set_overrunning_the_message_is_rejected() {
    let mut body = template_set();
    body.extend_from_slice(&256u16.to_be_bytes());
    body.extend_from_slice(&64u16.to_be_bytes()); // claims 64, only 4 follow
    body.extend_from_slice(&[1, 2, 3, 4]);

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(result.error.is_some(), "truncated Set must be reported");
}

/// Guard against over-correction: well-formed messages must still parse, and
/// fewer than 4 trailing octets stay tolerated as padding.
#[test]
fn well_formed_messages_are_unaffected() {
    let mut body = template_set();
    body.extend_from_slice(&data_set([192, 0, 2, 1]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));
    assert!(result.error.is_none(), "{:#?}", result.error);
    assert_eq!(data_record_count(&result.packets), 1);

    for padding in 1..4usize {
        let mut padded = template_set();
        padded.extend_from_slice(&data_set([192, 0, 2, 1]));
        padded.extend_from_slice(&vec![0u8; padding]);

        let mut parser = NetflowParser::default();
        let result = parser.parse_bytes(&message(&padded));
        assert!(
            result.error.is_none(),
            "{padding} octets of trailing padding must be tolerated: {:#?}",
            result.error
        );
        assert_eq!(data_record_count(&result.packets), 1);
    }
}
