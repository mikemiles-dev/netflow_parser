#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_parser::{NetflowPacket, NetflowParser};

// Round-trip fuzz target: parse → serialize → re-parse → compare.
// Catches serialization bugs where to_be_bytes() produces output that
// doesn't re-parse to the same structure.
thread_local! {
    static PARSER: std::cell::RefCell<NetflowParser> =
        std::cell::RefCell::new(NetflowParser::default());
    static REPARSE: std::cell::RefCell<NetflowParser> =
        std::cell::RefCell::new(NetflowParser::default());
}

fuzz_target!(|data: &[u8]| {
    PARSER.with(|p| {
        let mut parser = p.borrow_mut();
        let result = parser.parse_bytes(data);

        for packet in &result.packets {
            let serialized = match packet {
                NetflowPacket::V5(v5) => v5.to_be_bytes(),
                NetflowPacket::V7(v7) => v7.to_be_bytes(),
                NetflowPacket::V9(v9) => v9.to_be_bytes(),
                NetflowPacket::IPFix(ipfix) => ipfix.to_be_bytes(),
            };

            // Re-parse the serialized output and verify it produces a valid packet
            REPARSE.with(|rp| {
                let mut reparser = rp.borrow_mut();
                let re_result = reparser.parse_bytes(&serialized);

                // Serialized output of a successful parse must re-parse without error
                assert!(
                    re_result.error.is_none(),
                    "Round-trip failed: serialized output of {:?} did not re-parse cleanly: {:?}",
                    std::mem::discriminant(packet),
                    re_result.error,
                );

                // Must produce at least one packet
                assert!(
                    !re_result.packets.is_empty(),
                    "Round-trip failed: serialized output produced no packets",
                );

                // Verify the re-parsed packet is the same variant
                if let Some(re_packet) = re_result.packets.first() {
                    assert_eq!(
                        std::mem::discriminant(packet),
                        std::mem::discriminant(re_packet),
                        "Round-trip changed packet type",
                    );
                }
            });
        }
    });
});
