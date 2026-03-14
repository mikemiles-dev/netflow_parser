//! Tests for template cache behavior: custom sizes, metrics tracking,
//! template ID listing, and cache clearing.

use netflow_parser::NetflowParser;

// Verify that V9 and IPFIX caches start empty with the default max size
#[test]
fn test_template_cache_initial_state() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.current_size, 0);
    assert_eq!(v9_stats.max_size_per_cache, 1000); // Default cache size

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
    assert_eq!(ipfix_stats.max_size_per_cache, 1000);
}

// Verify that all cache metrics (hits, misses, evictions, collisions, expired) start at zero
#[test]
fn test_cache_metrics_initialization() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    let metrics = &v9_stats.metrics;

    assert_eq!(metrics.hits, 0);
    assert_eq!(metrics.misses, 0);
    assert_eq!(metrics.evictions, 0);
    assert_eq!(metrics.collisions, 0);
    assert_eq!(metrics.expired, 0);
}

// Verify that hit_rate() returns None when no lookups have occurred
#[test]
fn test_cache_hit_rate_calculation() {
    let parser = NetflowParser::default();
    let stats = parser.v9_cache_stats();

    // With no hits or misses, hit_rate should return None
    assert!(stats.metrics.hit_rate().is_none());
}

// Verify that V9 and IPFIX template ID lists are empty on a fresh parser
#[test]
fn test_template_id_listing_empty() {
    let parser = NetflowParser::default();

    let v9_templates = parser.v9_template_ids();
    assert_eq!(v9_templates.len(), 0);

    let ipfix_templates = parser.ipfix_template_ids();
    assert_eq!(ipfix_templates.len(), 0);
}

// Verify that has_v9_template and has_ipfix_template return false on an empty cache
#[test]
fn test_has_template_empty_cache() {
    let parser = NetflowParser::default();

    assert!(!parser.has_v9_template(256));
    assert!(!parser.has_ipfix_template(256));
}

// Verify that clearing V9 and IPFIX templates removes previously cached templates
#[test]
fn test_clear_templates() {
    let mut parser = NetflowParser::default();

    // Insert a V9 template so the cache is non-empty
    let v9_template_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, // Template flowset
        0, 0, 0, 12, 1, 0, // template_id = 256
        0, 1, // field_count = 1
        0, 1, 0, 4, // field: IN_BYTES(1), length 4
    ];
    let _ = parser.parse_bytes(&v9_template_packet);

    let v9_stats = parser.v9_cache_stats();
    assert!(
        v9_stats.current_size > 0,
        "V9 cache should have a template before clearing"
    );

    parser.clear_v9_templates();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(
        v9_stats.current_size, 0,
        "V9 cache should be empty after clearing"
    );

    parser.clear_ipfix_templates();

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
}

// Verify that with_cache_size sets the same max size for both V9 and IPFIX caches
#[test]
fn test_custom_cache_size() {
    let parser = NetflowParser::builder()
        .with_cache_size(500)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size_per_cache, 500);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size_per_cache, 500);
}

// Verify that V9 and IPFIX cache sizes can be configured independently
#[test]
fn test_different_cache_sizes() {
    let parser = NetflowParser::builder()
        .with_v9_cache_size(750)
        .with_ipfix_cache_size(1500)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size_per_cache, 750);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size_per_cache, 1500);
}

// Verify that template_ids() returns cached template IDs after parsing a template
#[test]
fn test_template_ids_after_parsing() {
    let mut parser = NetflowParser::default();

    // V9 template packet: template ID 256 with 1 field (IN_BYTES, 4 bytes)
    let v9_template_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12, 1, 0, 0, 1, 0,
        1, 0, 4,
    ];
    let _ = parser.parse_bytes(&v9_template_packet);

    let v9_templates = parser.v9_template_ids();
    assert!(
        v9_templates.contains(&256),
        "V9 template IDs should include 256 after parsing template"
    );
    assert!(
        parser.has_v9_template(256),
        "has_v9_template(256) should return true after caching"
    );
}

// Verify that hit_rate returns a meaningful value after hits and misses
#[test]
fn test_hit_rate_after_activity() {
    let mut parser = NetflowParser::default();

    // V9 template packet: template ID 256 with 1 field (IN_BYTES, 4 bytes)
    let v9_template_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 12, 1, 0, 0, 1, 0,
        1, 0, 4,
    ];
    let _ = parser.parse_bytes(&v9_template_packet);

    // V9 data packet using template 256 (should hit)
    let v9_data_packet: Vec<u8> = vec![
        0, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1,
        0, // flowset_id = 256
        0, 8, // length = 8
        0, 0, 0, 42, // IN_BYTES = 42
    ];
    let _ = parser.parse_bytes(&v9_data_packet);

    let stats = parser.v9_cache_stats();
    let hit_rate = stats.metrics.hit_rate();
    assert!(
        hit_rate.is_some(),
        "hit_rate should return Some after cache activity"
    );
    assert!(
        hit_rate.unwrap() > 0.0,
        "hit_rate should be positive after a cache hit"
    );
}
