//! Tests for concurrent parsing: shared parser behind Arc<Mutex<>> and
//! independent per-thread parsers.

use netflow_parser::{NetflowParser, RouterScopedParser};
use std::sync::{Arc, Mutex};
use std::thread;

/// A valid V5 packet for testing.
const V5_PACKET: [u8; 72] = [
    0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
];

/// Verify that a RouterScopedParser behind Arc<Mutex<>> can be shared across threads.
#[test]
fn test_shared_scoped_parser_across_threads() {
    let parser = Arc::new(Mutex::new(RouterScopedParser::<String>::new()));

    let mut handles = Vec::new();
    for i in 0..4 {
        let parser = Arc::clone(&parser);
        handles.push(thread::spawn(move || {
            let source = format!("router-{}", i);
            for _ in 0..10 {
                let mut p = parser.lock().unwrap();
                let packets = p.parse_from_source(source.clone(), &V5_PACKET).unwrap();
                assert_eq!(packets.len(), 1);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let p = parser.lock().unwrap();
    assert_eq!(p.source_count(), 4);
}

/// Verify that independent NetflowParser instances work correctly in parallel threads.
#[test]
fn test_independent_parsers_per_thread() {
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(thread::spawn(|| {
            let mut parser = NetflowParser::default();
            for _ in 0..20 {
                let result = parser.parse_bytes(&V5_PACKET);
                assert!(result.is_ok());
                assert_eq!(result.packets.len(), 1);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}
