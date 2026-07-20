use netflow_parser::variable_versions::ipfix::FlowSetBody;
use netflow_parser::{
    InMemoryTemplateStore, NetflowPacket, NetflowParser, TemplateKind, TemplateStore,
    TemplateStoreKey, TtlConfig,
};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const TEMPLATE_ID: u16 = 256;
const STORE_SCOPE: &str = "ipfix-template-owner";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefinitionKind {
    IpfixData,
    IpfixOptions,
    V9Data,
    V9Options,
}

const DEFINITION_KINDS: [DefinitionKind; 4] = [
    DefinitionKind::IpfixData,
    DefinitionKind::IpfixOptions,
    DefinitionKind::V9Data,
    DefinitionKind::V9Options,
];

impl DefinitionKind {
    fn store_kind(self) -> TemplateKind {
        match self {
            Self::IpfixData => TemplateKind::IpfixData,
            Self::IpfixOptions => TemplateKind::IpfixOptions,
            Self::V9Data => TemplateKind::IpfixV9Data,
            Self::V9Options => TemplateKind::IpfixV9Options,
        }
    }
}

fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn data_template_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body
}

fn ipfix_options_template_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(14);
    body.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body
}

fn v9_options_template_body() -> Vec<u8> {
    let mut body = Vec::with_capacity(14);
    body.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body
}

fn definition(kind: DefinitionKind) -> Vec<u8> {
    match kind {
        DefinitionKind::IpfixData => set(2, &data_template_body()),
        DefinitionKind::IpfixOptions => set(3, &ipfix_options_template_body()),
        DefinitionKind::V9Data => set(0, &data_template_body()),
        DefinitionKind::V9Options => set(1, &v9_options_template_body()),
    }
}

fn data_set() -> Vec<u8> {
    set(TEMPLATE_ID, &[0, 0, 0, 1, 0, 0, 0, 2])
}

fn message(sets: &[&[u8]]) -> Vec<u8> {
    let body_len = sets.iter().map(|set| set.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(16 + body_len);
    bytes.extend_from_slice(&10u16.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(16 + body_len).unwrap().to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&42u32.to_be_bytes());
    for set in sets {
        bytes.extend_from_slice(set);
    }
    bytes
}

fn parsed_ipfix(
    result: &netflow_parser::ParseResult,
) -> &netflow_parser::variable_versions::ipfix::Ipfix {
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.packets.len(), 1);
    let NetflowPacket::IPFix(packet) = &result.packets[0] else {
        panic!("expected IPFIX message");
    };
    packet
}

fn assert_data_kind(body: &FlowSetBody, expected: DefinitionKind) {
    let matches = match expected {
        DefinitionKind::IpfixData => matches!(body, FlowSetBody::Data(_)),
        DefinitionKind::IpfixOptions => matches!(body, FlowSetBody::OptionsData(_)),
        DefinitionKind::V9Data => matches!(body, FlowSetBody::V9Data(_)),
        DefinitionKind::V9Options => matches!(body, FlowSetBody::V9OptionsData(_)),
    };
    assert!(matches, "expected {expected:?}, got {body:?}");
}

#[test]
fn last_definition_owns_the_id_across_all_ipfix_template_kinds() {
    for first in DEFINITION_KINDS {
        for last in DEFINITION_KINDS {
            if first == last {
                continue;
            }

            let first_definition = definition(first);
            let last_definition = definition(last);
            let data = data_set();
            let mut parser = NetflowParser::default();
            let result =
                parser.parse_bytes(&message(&[&first_definition, &last_definition, &data]));
            let packet = parsed_ipfix(&result);
            assert_data_kind(&packet.flowsets[2].body, last);

            let cache = parser.ipfix_cache_info();
            assert_eq!(cache.current_size, 1, "{first:?} -> {last:?}");
            assert_eq!(cache.num_caches, 4);
            assert_eq!(cache.metrics.insertions, 2);
            assert_eq!(cache.metrics.collisions, 1, "{first:?} -> {last:?}");
            assert_eq!(cache.metrics.evictions, 0);
        }
    }
}

#[test]
fn template_store_retains_only_the_last_ipfix_template_kind() {
    for first in DEFINITION_KINDS {
        for last in DEFINITION_KINDS {
            if first == last {
                continue;
            }

            let store = Arc::new(InMemoryTemplateStore::new());
            let builder = NetflowParser::builder()
                .with_template_store(store.clone())
                .with_template_store_scope(STORE_SCOPE);
            let mut writer = builder.clone().build().unwrap();

            let first_definition = definition(first);
            let last_definition = definition(last);
            let result = writer.parse_bytes(&message(&[&first_definition, &last_definition]));
            parsed_ipfix(&result);

            for candidate in DEFINITION_KINDS {
                let key =
                    TemplateStoreKey::new(STORE_SCOPE, candidate.store_kind(), TEMPLATE_ID);
                assert_eq!(
                    store.get(&key).unwrap().is_some(),
                    candidate == last,
                    "{first:?} -> {last:?}: unexpected store state for {candidate:?}"
                );
            }

            let mut reader = builder.build().unwrap();
            let data = data_set();
            let result = reader.parse_bytes(&message(&[&data]));
            let packet = parsed_ipfix(&result);
            assert_data_kind(&packet.flowsets[0].body, last);
            assert_eq!(reader.ipfix_cache_info().current_size, 1);
        }
    }
}

#[test]
fn expired_opposite_ipfix_kind_is_not_counted_as_a_collision() {
    let mut parser = NetflowParser::builder()
        .with_ipfix_ttl(TtlConfig::new(Duration::from_millis(1)))
        .build()
        .unwrap();

    let first_definition = definition(DefinitionKind::IpfixData);
    parsed_ipfix(&parser.parse_bytes(&message(&[&first_definition])));
    thread::sleep(Duration::from_millis(5));

    let last_definition = definition(DefinitionKind::V9Options);
    parsed_ipfix(&parser.parse_bytes(&message(&[&last_definition])));

    let cache = parser.ipfix_cache_info();
    assert_eq!(cache.current_size, 1);
    assert_eq!(cache.metrics.insertions, 2);
    assert_eq!(cache.metrics.expired, 1);
    assert_eq!(cache.metrics.collisions, 0);
    assert_eq!(cache.metrics.evictions, 0);
}
