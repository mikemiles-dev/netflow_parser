use netflow_parser::{AutoScopedParser, NetflowParser};
use std::net::SocketAddr;

#[test]
fn test_auto_scoped_parser_no_collisions() {
    let mut parser = AutoScopedParser::new();

    let source1: SocketAddr = "192.168.1.1:2055".parse().unwrap();
    let source2: SocketAddr = "192.168.1.2:2055".parse().unwrap();

    // V5 packets (simple case)
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    // Parse from different sources
    let packets1 = parser.parse_from_source(source1, &v5_packet).unwrap();
    let packets2 = parser.parse_from_source(source2, &v5_packet).unwrap();

    assert_eq!(packets1.len(), 1);
    assert_eq!(packets2.len(), 1);

    // Should track multiple sources
    assert!(parser.source_count() >= 2);
}

#[test]
fn test_single_parser_multi_source() {
    // This test demonstrates parsing from multiple sources with a single parser
    let mut parser = NetflowParser::default();

    // Simulate parsing from multiple "sources"
    // In real scenario, these would be different routers sending templates
    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    // Parse multiple times (simulating different sources)
    for _ in 0..5 {
        let packets = parser.parse_bytes(&v5_packet).unwrap();
        assert_eq!(packets.len(), 1);
    }
}

#[test]
fn test_collision_rate_calculation() {
    let parser = NetflowParser::default();

    // Get stats
    let v9_stats = parser.v9_cache_stats();
    let ipfix_stats = parser.ipfix_cache_stats();

    // Initial metrics should be zero
    assert_eq!(v9_stats.metrics.collisions, 0);
    assert_eq!(v9_stats.metrics.hits, 0);
    assert_eq!(v9_stats.metrics.misses, 0);

    assert_eq!(ipfix_stats.metrics.collisions, 0);
    assert_eq!(ipfix_stats.metrics.hits, 0);
    assert_eq!(ipfix_stats.metrics.misses, 0);
}

#[test]
fn test_scoped_parser_with_builder() {
    use netflow_parser::NetflowParser;

    let builder = NetflowParser::builder().with_cache_size(2000);

    let mut parser = AutoScopedParser::with_builder(builder);

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
fn test_cache_stats_initial_state() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.current_size, 0);
    assert_eq!(v9_stats.max_size, 1000);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
    assert_eq!(ipfix_stats.max_size, 1000);
}
