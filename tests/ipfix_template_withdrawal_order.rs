use netflow_parser::variable_versions::ipfix::FlowSetBody;
use netflow_parser::{NetflowPacket, NetflowParser, TemplateEvent};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn append_set(message: &mut Vec<u8>, id: u16, body: &[u8]) {
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    message.extend_from_slice(body);
}

#[test]
fn template_withdrawal_takes_effect_in_wire_order() {
    let mut message = Vec::new();
    message.extend_from_slice(&10u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u32.to_be_bytes());
    message.extend_from_slice(&2u32.to_be_bytes());
    message.extend_from_slice(&3u32.to_be_bytes());

    let mut records = Vec::new();
    records.extend_from_slice(&256u16.to_be_bytes());
    records.extend_from_slice(&1u16.to_be_bytes());
    records.extend_from_slice(&1u16.to_be_bytes());
    records.extend_from_slice(&4u16.to_be_bytes());
    records.extend_from_slice(&256u16.to_be_bytes());
    records.extend_from_slice(&0u16.to_be_bytes());
    append_set(&mut message, 2, &records);
    append_set(&mut message, 256, &42u32.to_be_bytes());
    let length = u16::try_from(message.len()).unwrap();
    message[2..4].copy_from_slice(&length.to_be_bytes());

    let learned_events = Arc::new(AtomicUsize::new(0));
    let learned_events_for_hook = Arc::clone(&learned_events);
    let mut parser = NetflowParser::builder()
        .on_template_event(move |event| {
            if matches!(event, TemplateEvent::Learned { .. }) {
                learned_events_for_hook.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .build()
        .unwrap();
    let result = parser.parse_bytes(&message);
    assert!(result.error.is_none(), "{:#?}", result.error);
    let NetflowPacket::IPFix(packet) = &result.packets[0] else {
        panic!("expected IPFIX packet");
    };
    let FlowSetBody::Templates(templates) = &packet.flowsets[0].body else {
        panic!("expected both Template records");
    };
    assert_eq!(
        templates
            .iter()
            .map(|template| template.field_count)
            .collect::<Vec<_>>(),
        [1, 0]
    );
    assert!(matches!(
        packet.flowsets[1].body,
        FlowSetBody::NoTemplate(_)
    ));
    assert_eq!(learned_events.load(Ordering::Relaxed), 1);
}
