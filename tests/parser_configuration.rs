//! Tests for parser builder configuration: cache size, TTL, field count limits,
//! version filtering, and comprehensive builder chaining.

use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ttl::TtlConfig;
use std::time::Duration;

// Verify default parser allows versions 5, 7, 9, and 10 but not version 0
#[test]
fn test_default_parser_creation() {
    let parser = NetflowParser::default();
    // Default allows versions 5, 7, 9, 10
    assert!(parser.allowed_versions[5]);
    assert!(parser.allowed_versions[7]);
    assert!(parser.allowed_versions[9]);
    assert!(parser.allowed_versions[10]);
    assert!(!parser.allowed_versions[0]);
}

// Verify builder sets the same cache size for both V9 and IPFIX caches
#[test]
fn test_parser_builder_with_cache_size() {
    let parser = NetflowParser::builder()
        .with_cache_size(2000)
        .build()
        .expect("Failed to build parser");

    let stats = parser.v9_cache_stats();
    assert_eq!(stats.max_size, 2000);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size, 2000);
}

// Verify builder can set independent cache sizes for V9 and IPFIX
#[test]
fn test_parser_builder_with_different_cache_sizes() {
    let parser = NetflowParser::builder()
        .with_v9_cache_size(1000)
        .with_ipfix_cache_size(3000)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size, 1000);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size, 3000);
}

// Verify builder accepts a TTL configuration and creates a valid parser
#[test]
fn test_parser_builder_with_ttl() {
    let parser = NetflowParser::builder()
        .with_ttl(TtlConfig::new(Duration::from_secs(3600)))
        .build()
        .expect("Failed to build parser");

    // Parser should be created successfully with default allowed versions
    assert!(parser.allowed_versions[5]);
    assert!(parser.allowed_versions[9]);
}

// Verify builder restricts allowed versions to only those specified
#[test]
fn test_parser_builder_with_allowed_versions() {
    let parser = NetflowParser::builder()
        .with_allowed_versions(&[5, 9])
        .build()
        .expect("Failed to build parser");

    assert!(parser.allowed_versions[5]);
    assert!(parser.allowed_versions[9]);
    assert!(!parser.allowed_versions[7]);
}

// Verify builder sets the max error sample size on the parser
#[test]
fn test_parser_builder_with_max_error_sample_size() {
    let parser = NetflowParser::builder()
        .with_max_error_sample_size(512)
        .build()
        .expect("Failed to build parser");

    assert_eq!(parser.max_error_sample_size, 512);
}

// Verify builder accepts a max field count limit and creates a valid parser
#[test]
fn test_parser_builder_with_field_count_limits() {
    let parser = NetflowParser::builder()
        .with_max_field_count(5000)
        .build()
        .expect("Failed to build parser");

    // Parser should be created successfully with field limits and default allowed versions
    assert!(parser.allowed_versions[5]);
    assert!(parser.allowed_versions[9]);
}

// Verify builder chains all options together and produces correct configuration
#[test]
fn test_parser_builder_comprehensive() {
    let parser = NetflowParser::builder()
        .with_v9_cache_size(1500)
        .with_ipfix_cache_size(2500)
        .with_v9_ttl(TtlConfig::new(Duration::from_secs(1800)))
        .with_ipfix_ttl(TtlConfig::new(Duration::from_secs(3600)))
        .with_allowed_versions(&[5, 9, 10])
        .with_max_error_sample_size(512)
        .with_v9_max_field_count(8000)
        .with_ipfix_max_field_count(10000)
        .build()
        .expect("Failed to build parser");

    let v9_stats = parser.v9_cache_stats();
    assert_eq!(v9_stats.max_size, 1500);

    let ipfix_stats = parser.ipfix_cache_stats();
    assert_eq!(ipfix_stats.max_size, 2500);

    assert!(parser.allowed_versions[5]);
    assert!(parser.allowed_versions[9]);
    assert!(parser.allowed_versions[10]);

    assert_eq!(parser.max_error_sample_size, 512);
}
