#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_parser::NetflowParser;

fuzz_target!(|data: &[u8]| {
    NetflowParser::default().parse_bytes(data);
});
