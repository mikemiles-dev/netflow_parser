#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_parser::NetflowParser;

// Use a thread-local parser to preserve template cache state across
// fuzz iterations. This enables the fuzzer to discover bugs in
// template-then-data sequences (V9/IPFIX template caching).
thread_local! {
    static PARSER: std::cell::RefCell<NetflowParser> =
        std::cell::RefCell::new(NetflowParser::default());
}

fuzz_target!(|data: &[u8]| {
    PARSER.with(|p| {
        let _ = p.borrow_mut().parse_bytes(data);
    });
});
