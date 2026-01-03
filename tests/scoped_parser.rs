use netflow_parser::{AutoScopedParser, RouterScopedParser};
use std::net::SocketAddr;

#[test]
fn test_auto_scoped_parser_creation() {
    let parser = AutoScopedParser::new();

    assert_eq!(parser.source_count(), 0);
    assert_eq!(parser.v9_source_count(), 0);
    assert_eq!(parser.ipfix_source_count(), 0);
}

#[test]
fn test_auto_scoped_parser_with_source() {
    let mut parser = AutoScopedParser::new();
    let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let packets = parser.parse_from_source(source, &v5_packet).unwrap();
    assert_eq!(packets.len(), 1);
}

#[test]
fn test_auto_scoped_parser_multiple_sources() {
    let mut parser = AutoScopedParser::new();
    let source1: SocketAddr = "192.168.1.1:2055".parse().unwrap();
    let source2: SocketAddr = "192.168.1.2:2055".parse().unwrap();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let _ = parser.parse_from_source(source1, &v5_packet);
    let _ = parser.parse_from_source(source2, &v5_packet);

    // V5 packets create sources
    assert!(parser.source_count() >= 2);
}

#[test]
fn test_router_scoped_parser_string_key() {
    let mut parser = RouterScopedParser::<String>::new();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let packets = parser
        .parse_from_source("router-01".to_string(), &v5_packet)
        .unwrap();
    assert_eq!(packets.len(), 1);
}

#[test]
fn test_router_scoped_parser_clear_source() {
    let mut parser = RouterScopedParser::<String>::new();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let _ = parser.parse_from_source("router-01".to_string(), &v5_packet);
    parser.clear_source_templates(&"router-01".to_string());

    // Should still be able to parse after clearing
    let packets = parser
        .parse_from_source("router-01".to_string(), &v5_packet)
        .unwrap();
    assert_eq!(packets.len(), 1);
}

#[test]
fn test_router_scoped_parser_clear_all() {
    let mut parser = RouterScopedParser::<String>::new();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let _ = parser.parse_from_source("router-01".to_string(), &v5_packet);
    let _ = parser.parse_from_source("router-02".to_string(), &v5_packet);

    parser.clear_all_templates();

    // Should still be able to parse after clearing all
    let packets = parser
        .parse_from_source("router-01".to_string(), &v5_packet)
        .unwrap();
    assert_eq!(packets.len(), 1);
}

#[test]
fn test_auto_scoped_parser_with_builder() {
    use netflow_parser::NetflowParser;

    let builder = NetflowParser::builder().with_cache_size(2000);

    let parser = AutoScopedParser::with_builder(builder);

    // Verify parser was created with builder configuration
    assert_eq!(parser.source_count(), 0);
}

#[test]
fn test_router_scoped_parser_with_builder() {
    use netflow_parser::NetflowParser;

    let builder = NetflowParser::builder().with_cache_size(2000);

    let mut parser = RouterScopedParser::<String>::with_builder(builder);

    // Verify parser was created
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let packets = parser
        .parse_from_source("router-01".to_string(), &v5_packet)
        .unwrap();
    assert_eq!(packets.len(), 1);
}
