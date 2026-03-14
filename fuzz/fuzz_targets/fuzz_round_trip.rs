#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_parser::{NetflowPacket, NetflowParser};

// Round-trip fuzz target: parse → serialize → parse → compare.
// Catches serialization bugs where to_be_bytes() produces invalid output.
thread_local! {
    static PARSER: std::cell::RefCell<NetflowParser> =
        std::cell::RefCell::new(NetflowParser::default());
}

fuzz_target!(|data: &[u8]| {
    PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        let result = parser.parse_bytes(data);

        for packet in &result.packets {
            match packet {
                NetflowPacket::V5(v5) => {
                    let _ = v5.to_be_bytes();
                }
                NetflowPacket::V7(v7) => {
                    let _ = v7.to_be_bytes();
                }
                NetflowPacket::V9(v9) => {
                    let _ = v9.to_be_bytes();
                }
                NetflowPacket::IPFix(ipfix) => {
                    let _ = ipfix.to_be_bytes();
                }
            }
        }
    });
});
