//! A Set this parser cannot decode must not take the Sets behind it down.
//!
//! The remaining half of netflow_parser#310. The framing check could not reach
//! this case, because such a Set is perfectly well framed — only its body is
//! undecodable — so `many0` stopped there and every Set behind it was dropped
//! while the message reported success.

use netflow_parser::variable_versions::NoTemplateReason;
use netflow_parser::variable_versions::ipfix::FlowSetBody;
use netflow_parser::{NetflowPacket, NetflowParser, PendingFlowsConfig};

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
    for v in [2u16, 12, 256, 1, 8, 4] {
        s.extend_from_slice(&v.to_be_bytes());
    }
    s
}

/// A Template Set whose declared `field_count` exceeds the octets present, so
/// the Set is well framed but its body cannot be decoded.
fn undecodable_set() -> Vec<u8> {
    let mut s = Vec::new();
    for v in [2u16, 12, 257, 100, 8, 4] {
        s.extend_from_slice(&v.to_be_bytes());
    }
    s
}

fn data_set(payload: [u8; 4]) -> Vec<u8> {
    let mut s = Vec::new();
    for v in [256u16, 8] {
        s.extend_from_slice(&v.to_be_bytes());
    }
    s.extend_from_slice(&payload);
    s
}

fn data_record_count(packets: &[NetflowPacket]) -> usize {
    packets
        .iter()
        .filter_map(|p| match p {
            NetflowPacket::IPFix(i) => Some(i),
            _ => None,
        })
        .flat_map(|i| i.flowsets.iter())
        .map(|fs| match &fs.body {
            FlowSetBody::Data(d) => d.fields.len(),
            _ => 0,
        })
        .sum()
}

fn no_template_bodies(packets: &[NetflowPacket]) -> Vec<(u16, NoTemplateReason)> {
    packets
        .iter()
        .filter_map(|p| match p {
            NetflowPacket::IPFix(i) => Some(i),
            _ => None,
        })
        .flat_map(|i| i.flowsets.iter())
        .filter_map(|fs| match &fs.body {
            FlowSetBody::NoTemplate(info) => Some((info.template_id, info.reason)),
            _ => None,
        })
        .collect()
}

/// The case with teeth: a valid Data Set behind an undecodable Set.
#[test]
fn data_behind_an_undecodable_set_survives() {
    let mut body = template_set();
    body.extend_from_slice(&undecodable_set());
    body.extend_from_slice(&data_set([192, 0, 2, 3]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(
        data_record_count(&result.packets),
        1,
        "the Data Set behind the undecodable Set must still decode"
    );
}

/// The skipped Set stays visible, and is marked as something a retry cannot fix.
#[test]
fn the_undecodable_set_is_reported_as_undecodable() {
    let mut body = template_set();
    body.extend_from_slice(&undecodable_set());
    body.extend_from_slice(&data_set([192, 0, 2, 3]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert_eq!(
        no_template_bodies(&result.packets),
        vec![(2, NoTemplateReason::UndecodableBody)],
        "exactly the skipped Set must be reported, as undecodable"
    );
}

/// A genuinely missing template keeps its own reason and stays replayable;
/// the new variant must not swallow the pre-existing case.
#[test]
fn a_missing_template_is_still_reported_as_missing() {
    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&data_set([1, 2, 3, 4])));

    assert_eq!(
        no_template_bodies(&result.packets),
        vec![(256, NoTemplateReason::MissingTemplate)]
    );
}

/// The subtle part: an undecodable Set must never enter the pending-flow cache.
/// No template arriving later changes its octets, so a cached entry would be
/// replayed and fail forever.
#[test]
fn an_undecodable_set_is_never_cached_for_replay() {
    let mut parser = NetflowParser::builder()
        .with_pending_flows(PendingFlowsConfig::new(16))
        .build()
        .expect("valid config");

    // A data Set for an absent template is cached; the undecodable Set is not.
    let mut body = undecodable_set();
    body.extend_from_slice(&data_set([192, 0, 2, 4]));
    let result = parser.parse_bytes(&message(&body));
    assert!(result.error.is_none(), "{:?}", result.error);

    let stats = parser.ipfix_cache_info();
    assert_eq!(
        stats.pending_flow_count, 1,
        "only the missing-template Set may be cached"
    );
    assert_eq!(
        stats.metrics.pending_cached, 1,
        "the undecodable Set must not be counted as cached"
    );

    // And it must not be counted as a drop either: it was never a candidate.
    assert_eq!(
        stats.metrics.pending_dropped, 0,
        "an undecodable Set is skipped, not dropped from the cache"
    );
}

/// Guard against over-correction: a message of entirely decodable Sets is
/// unaffected, and nothing is reported as undecodable.
#[test]
fn well_formed_messages_are_unaffected() {
    let mut body = template_set();
    body.extend_from_slice(&data_set([192, 0, 2, 1]));
    body.extend_from_slice(&data_set([192, 0, 2, 2]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(data_record_count(&result.packets), 2);
    assert!(no_template_bodies(&result.packets).is_empty());
}

/// Several undecodable Sets in one message are each skipped independently.
#[test]
fn consecutive_undecodable_sets_are_each_skipped() {
    let mut body = template_set();
    body.extend_from_slice(&undecodable_set());
    body.extend_from_slice(&undecodable_set());
    body.extend_from_slice(&data_set([192, 0, 2, 5]));

    let mut parser = NetflowParser::default();
    let result = parser.parse_bytes(&message(&body));

    assert_eq!(data_record_count(&result.packets), 1);
    assert_eq!(
        no_template_bodies(&result.packets),
        vec![
            (2, NoTemplateReason::UndecodableBody),
            (2, NoTemplateReason::UndecodableBody)
        ]
    );
}
