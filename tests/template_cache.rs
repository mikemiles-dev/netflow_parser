use netflow_parser::NetflowParser;

#[test]
fn test_template_cache_initial_state() {
    let parser = NetflowParser::default();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.current_size, 0);
    assert_eq!(v9_stats.max_size, 1000); // Default cache size

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
    assert_eq!(ipfix_stats.max_size, 1000);
}

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

#[test]
fn test_cache_hit_rate_calculation() {
    let parser = NetflowParser::default();
    let stats = parser.v9_cache_stats();

    // With no hits or misses, hit_rate should return None
    assert!(stats.metrics.hit_rate().is_none());
}

#[test]
fn test_template_id_listing_empty() {
    let parser = NetflowParser::default();

    let v9_templates = parser.v9_template_ids();
    assert_eq!(v9_templates.len(), 0);

    let ipfix_templates = parser.ipfix_template_ids();
    assert_eq!(ipfix_templates.len(), 0);
}

#[test]
fn test_has_template_empty_cache() {
    let parser = NetflowParser::default();

    assert!(!parser.has_v9_template(256));
    assert!(!parser.has_ipfix_template(256));
}

#[test]
fn test_clear_templates() {
    let mut parser = NetflowParser::default();

    parser.clear_v9_templates();
    parser.clear_ipfix_templates();

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.current_size, 0);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.current_size, 0);
}

#[test]
fn test_custom_cache_size() {
    let parser = NetflowParser::builder()
        .with_cache_size(500)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size, 500);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size, 500);
}

#[test]
fn test_different_cache_sizes() {
    let parser = NetflowParser::builder()
        .with_v9_cache_size(750)
        .with_ipfix_cache_size(1500)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size, 750);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size, 1500);
}
