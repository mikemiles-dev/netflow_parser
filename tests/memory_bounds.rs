//! Tests for memory bounds: cache stats stay within configured limits and
//! error sample size is bounded.

use netflow_parser::NetflowParser;

/// A valid V5 packet for testing.
const V5_PACKET: [u8; 72] = [
    0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
];

/// Verify that parsing many packets does not cause cache stats to exceed configured bounds.
#[test]
fn test_cache_stats_stay_within_bounds() {
    let max_cache = 100;
    let mut parser = NetflowParser::builder()
        .with_cache_size(max_cache)
        .build()
        .expect("valid config");

    for _ in 0..500 {
        let _ = parser.parse_bytes(&V5_PACKET);
    }

    let v9_stats = parser.v9_cache_stats();
    assert!(
        v9_stats.current_size <= max_cache,
        "V9 cache size {} exceeds max {}",
        v9_stats.current_size,
        max_cache
    );

    let ipfix_stats = parser.ipfix_cache_stats();
    assert!(
        ipfix_stats.current_size <= max_cache,
        "IPFIX cache size {} exceeds max {}",
        ipfix_stats.current_size,
        max_cache
    );
}

/// Verify that error samples respect the configured max_error_sample_size.
#[test]
fn test_error_sample_size_bounded() {
    let max_sample = 32;
    let mut parser = NetflowParser::builder()
        .with_max_error_sample_size(max_sample)
        .build()
        .expect("valid config");

    assert_eq!(parser.max_error_sample_size(), max_sample);

    // Feed garbage that triggers UnsupportedVersion error with a sample
    let garbage = vec![0xFFu8; 256];
    let result = parser.parse_bytes(&garbage);

    if let Some(netflow_parser::NetflowError::UnsupportedVersion { sample, .. }) = result.error
    {
        assert!(
            sample.len() <= max_sample,
            "error sample {} bytes exceeds max {}",
            sample.len(),
            max_sample
        );
    }
}

/// Verify that default max_error_sample_size is 256.
#[test]
fn test_default_error_sample_size() {
    let parser = NetflowParser::default();
    assert_eq!(parser.max_error_sample_size(), 256);
}
