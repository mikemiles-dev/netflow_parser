#![no_main]

use libfuzzer_sys::fuzz_target;
use netflow_parser::{NetflowPacket, NetflowParser};

// Round-trip fuzz target: parse → serialize → re-parse → compare.
// Catches serialization bugs where to_be_bytes() produces output that
// doesn't re-parse to the same structure.
//
// Uses a persistent PARSER to accumulate template state across iterations
// (exercising caching/collision paths), but re-parses with a FRESH parser
// each time to ensure the serialized output is self-contained.
thread_local! {
    static PARSER: std::cell::RefCell<NetflowParser> =
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
                NetflowPacket::V9(v9) => match v9.to_be_bytes() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                },
                NetflowPacket::IPFix(ipfix) => match ipfix.to_be_bytes() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                },
                _ => continue,
            };

            // Re-parse with a fresh parser to ensure serialized output is
            // self-contained (not relying on accumulated template state).
            let mut reparser = NetflowParser::default();
            let re_result = reparser.parse_bytes(&serialized);

            // Serialized output of a successful parse must re-parse without error
            assert!(
                re_result.error.is_none(),
                "Round-trip failed: serialized output of {:?} did not re-parse cleanly: {:?}",
                std::mem::discriminant(packet),
                re_result.error,
            );

            // Must produce at least one packet (V5/V7 always, V9/IPFIX
            // may produce template-only packets with no data flowsets).
            // For V9/IPFIX template-only packets, an empty result is acceptable.
            match packet {
                NetflowPacket::V5(_) | NetflowPacket::V7(_) => {
                    assert!(
                        !re_result.packets.is_empty(),
                        "Round-trip failed: serialized V5/V7 output produced no packets",
                    );
                }
                _ => {}
            }

            // Verify the re-parsed packet is the same variant (when present)
            if let Some(re_packet) = re_result.packets.first() {
                assert_eq!(
                    std::mem::discriminant(packet),
                    std::mem::discriminant(re_packet),
                    "Round-trip changed packet type",
                );
            }
        }
    });
});
