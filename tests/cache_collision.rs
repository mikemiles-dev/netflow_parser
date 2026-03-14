//! Tests for template cache collision detection and multi-source isolation
//! via scoped parsers.

use netflow_parser::{AutoScopedParser, NetflowParser};
use std::net::SocketAddr;

// Verify that AutoScopedParser isolates parsing across different source addresses without collisions
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
    let packets1 = parser.parse_from_source(source1, &v5_packet).packets;
    let packets2 = parser.parse_from_source(source2, &v5_packet).packets;

    assert_eq!(packets1.len(), 1);
    assert_eq!(packets2.len(), 1);

    // Should track multiple sources
    assert!(parser.source_count() >= 2);
}

// Verify that a single NetflowParser can parse repeatedly from simulated multiple sources
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
        let packets = parser.parse_bytes(&v5_packet).packets;
        assert_eq!(packets.len(), 1);
    }
}

// Verify that V9 and IPFIX cache metrics start at zero on a fresh parser
#[test]
fn test_initial_metrics_are_zero() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    let ipfix_stats = parser.ipfix_cache_stats();

    assert_eq!(v9_stats.metrics.collisions, 0);
    assert_eq!(v9_stats.metrics.hits, 0);
    assert_eq!(v9_stats.metrics.misses, 0);

    assert_eq!(ipfix_stats.metrics.collisions, 0);
    assert_eq!(ipfix_stats.metrics.hits, 0);
    assert_eq!(ipfix_stats.metrics.misses, 0);
}

// Verify that V9 cache records hits when data uses a cached template
#[test]
fn test_cache_hit_tracking() {
    let mut parser = NetflowParser::default();

    // V9 template packet: template ID 256 with 1 field (IN_BYTES, 4 bytes)
    let v9_template_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12, 1, 0, 0, 1, 0,
        1, 0, 4,
    ];
    let _ = parser.parse_bytes(&v9_template_packet);

    // V9 data packet using template 256
    let v9_data_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1,
        0, // flowset_id = 256
        0, 8, // length = 8 (header(4) + 1 record of 4 bytes)
        0, 0, 0, 42, // IN_BYTES = 42
    ];
    let _ = parser.parse_bytes(&v9_data_packet);

    let v9_stats = parser.v9_cache_stats();
    assert!(
        v9_stats.metrics.hits > 0,
        "V9 cache should record hits after parsing data with a cached template"
    );
}

// Verify that AutoScopedParser can be created with a custom builder configuration
#[test]
fn test_scoped_parser_with_builder() {
    use netflow_parser::NetflowParser;

    let builder = NetflowParser::builder().with_cache_size(2000);

    let mut parser = AutoScopedParser::try_with_builder(builder).expect("valid config");

    let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

    let v5_packet = [
        0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
    ];

    let packets = parser.parse_from_source(source, &v5_packet).packets;
    assert_eq!(packets.len(), 1);
}

// Verify that V9 and IPFIX cache stats report zero size and default max on a new parser
#[test]
fn test_cache_stats_initial_state() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.current_size, 0);
    assert_eq!(v9_stats.max_size_per_cache, 1000);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
    assert_eq!(ipfix_stats.max_size_per_cache, 1000);
}
