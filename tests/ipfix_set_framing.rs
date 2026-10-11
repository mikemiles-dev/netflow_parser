//! A Set declaring an impossible length must be reported, not dropped silently.
//!
//! The reproducer in `malformed_message_does_not_commit_an_earlier_template`
//! comes from Costa Tsaousis (netflow_parser#310).

use netflow_parser::{NetflowError, NetflowParser};

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

/// The remaining half of netflow_parser#310: RFC 7011 Section 9.1 requires
/// discarding the whole message, so no state from its valid prefix should
/// survive.
///
/// Framing is validated across the whole Set chain before any Set is parsed,
/// so a framing rejection commits no template. This is not full transactional
/// discard — a message rejected for some other reason mid-walk can still leave
/// a template behind — but it covers every message this check rejects.
#[test]
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
        matches!(
            result.error,
            Some(NetflowError::MalformedSetFraming {
                offset: 12,
                declared: 3,
                available: 12,
                observation_domain_id: 3,
                sequence_number: 2,
                export_time: 1,
                ..
            })
        ),
        "losing a valid Data Set must not be reported as success, and the \
         offending Set must be locatable: {:?}",
        result.error
    );
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

/// Guard against over-correction: well-formed messages must still parse.
/// Trailing padding is covered by `trailing_zero_padding_is_tolerated`.
#[test]
fn well_formed_messages_are_unaffected() {
    let mut body = template_set();
    body.extend_from_slice(&data_set([192, 0, 2, 1]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));
    assert!(result.error.is_none(), "{:#?}", result.error);
    assert_eq!(data_record_count(&result.packets), 1);
}

/// Trailing zero octets are alignment padding, not a Set declaring length 0.
/// Sets align to 4- or 8-octet boundaries, so a legitimate tail is at most 7
/// octets; rejecting all of them cost every record in the message.
#[test]
fn trailing_zero_padding_is_tolerated() {
    for padding in 1..=7usize {
        let mut body = template_set();
        body.extend_from_slice(&data_set([192, 0, 2, 1]));
        body.extend_from_slice(&vec![0u8; padding]);

        let mut parser = NetflowParser::default();
        let result = parser.parse_bytes(&message(&body));
        assert!(
            result.error.is_none(),
            "{padding} octets of trailing padding must be tolerated: {:?}",
            result.error
        );
        assert_eq!(
            data_record_count(&result.packets),
            1,
            "{padding} octets of padding must not cost the message's records"
        );
    }
}

/// A zero run too long to be alignment padding is a truncated or zero-filled
/// message, and must not be excused as padding.
#[test]
fn an_over_long_zero_tail_is_still_rejected() {
    let mut body = template_set();
    body.extend_from_slice(&data_set([192, 0, 2, 1]));
    body.extend_from_slice(&[0u8; 8]);

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));
    assert!(
        matches!(result.error, Some(NetflowError::MalformedSetFraming { .. })),
        "8 zero octets cannot be alignment padding: {:?}",
        result.error
    );
}

/// A zero run in the middle of a message is not padding either, even though
/// its last 4 octets would read as a Set declaring length 0 on their own.
#[test]
fn a_zero_gap_mid_message_is_rejected() {
    let mut body = template_set();
    body.extend_from_slice(&[0u8; 4]);
    body.extend_from_slice(&data_set([192, 0, 2, 1]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));
    assert!(
        matches!(result.error, Some(NetflowError::MalformedSetFraming { .. })),
        "a zero gap mid-message is not padding: {:?}",
        result.error
    );
}

/// RFC 7011 Section 9.1 discards the *Message*. A datagram carrying several
/// chained messages must not lose the ones behind a malformed sibling, since
/// each Message Header declares its own length.
#[test]
fn a_malformed_message_does_not_discard_the_rest_of_the_datagram() {
    let mut bad = template_set();
    bad.extend_from_slice(&2u16.to_be_bytes());
    bad.extend_from_slice(&3u16.to_be_bytes());

    let mut good = template_set();
    good.extend_from_slice(&data_set([192, 0, 2, 9]));

    let mut datagram = message(&bad);
    datagram.extend_from_slice(&message(&good));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&datagram);

    assert!(
        matches!(result.error, Some(NetflowError::MalformedSetFraming { .. })),
        "the malformed message must still be reported: {:?}",
        result.error
    );
    assert_eq!(
        data_record_count(&result.packets),
        1,
        "the following message's Data Set must survive"
    );
}

/// `iter_packets` resumes after a discarded message too, so the two APIs agree
/// about which errors are recoverable.
#[test]
fn the_iterator_resumes_after_a_discarded_message() {
    let mut bad = template_set();
    bad.extend_from_slice(&2u16.to_be_bytes());
    bad.extend_from_slice(&3u16.to_be_bytes());

    let mut good = template_set();
    good.extend_from_slice(&data_set([192, 0, 2, 9]));

    let mut datagram = message(&bad);
    datagram.extend_from_slice(&message(&good));

    let mut parser = NetflowParser::default();
    let items: Vec<_> = parser.iter_packets(&datagram).collect();

    assert_eq!(
        items.len(),
        2,
        "expected one error then one packet: {items:#?}"
    );
    assert!(matches!(
        items[0],
        Err(NetflowError::MalformedSetFraming { .. })
    ));
    let packets: Vec<_> = items.into_iter().filter_map(Result::ok).collect();
    assert_eq!(data_record_count(&packets), 1);
}

/// A message whose header length does not locate a successor is a hard stop:
/// there is no trustworthy boundary to resume from, and resuming must never
/// stall the caller's loop.
#[test]
fn a_message_with_no_locatable_successor_stops_parsing() {
    let mut body = template_set();
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));
    assert!(matches!(
        result.error,
        Some(NetflowError::MalformedSetFraming { .. })
    ));
    assert!(result.packets.is_empty());
}

/// The framing error must stay small. It previously formatted the whole Set
/// region into a string, amplifying an attacker-chosen datagram several times
/// over while ignoring `max_error_sample_size`.
#[test]
fn the_framing_error_does_not_echo_the_message() {
    let mut body = template_set();
    body.extend_from_slice(&data_set([1, 2, 3, 4]));

    // One well-framed but undecodable Set filling the message, then 4 octets
    // declaring a Set length of 0.
    let filler_len = 65535 - 16 - body.len() - 4;
    body.extend_from_slice(&999u16.to_be_bytes());
    body.extend_from_slice(&u16::try_from(filler_len).unwrap().to_be_bytes());
    body.extend_from_slice(&vec![7u8; filler_len - 4]);
    body.extend_from_slice(&[0u8, 2, 0, 0]);

    let datagram = message(&body);
    assert_eq!(datagram.len(), 65535);

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&datagram);
    let rendered = result.error.as_ref().map(ToString::to_string).unwrap();
    assert!(
        rendered.len() < 256,
        "error must not echo the message ({} bytes): {rendered}",
        rendered.len()
    );
}
