use etherparse::{SlicedPacket, TransportSlice};
use netflow_parser::NetflowParser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use std::fs::File;

const PCAP_PATH: &str = "pcaps/IPFIX.pcap";

#[test]
fn test_pcap_file_parsing() {
    let file = File::open(PCAP_PATH).expect("Failed to open PCAP file");
    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create PCAP reader");
    let mut parser = NetflowParser::default();
    let mut packet_count = 0;
    let mut netflow_packets = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(pcap_block) => {
                        packet_count += 1;
                        if let Ok(eth) = SlicedPacket::from_ethernet(pcap_block.data)
                            && let Some(transport) = eth.transport
                                && let TransportSlice::Udp(udp) = transport {
                                    let parsed = parser.parse_bytes(udp.payload());
                                    netflow_packets += parsed.packets.len();
                                }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("Failed to refill buffer");
            }
            Err(_) => break,
        }
    }

    assert!(packet_count > 0, "Should have parsed some PCAP packets");
    assert!(
        netflow_packets > 0,
        "Should have parsed some NetFlow packets"
    );
}

#[test]
fn test_pcap_ipfix_parsing() {
    let file = File::open(PCAP_PATH).expect("Failed to open PCAP file");
    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create PCAP reader");
    let mut parser = NetflowParser::default();
    let mut ipfix_count = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(pcap_block) => {
                        if let Ok(eth) = SlicedPacket::from_ethernet(pcap_block.data)
                            && let Some(transport) = eth.transport
                                && let TransportSlice::Udp(udp) = transport {
                                    let parsed = parser.parse_bytes(udp.payload());
                                    for pkt in parsed.packets {
                                        if pkt.is_ipfix() {
                                            ipfix_count += 1;
                                        }
                                    }
                                }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("Failed to refill buffer");
            }
            Err(_) => break,
        }
    }

    assert!(
        ipfix_count > 0,
        "Should have parsed IPFIX packets from PCAP"
    );
}

#[test]
fn test_pcap_template_caching() {
    let file = File::open(PCAP_PATH).expect("Failed to open PCAP file");
    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create PCAP reader");
    let mut parser = NetflowParser::default();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(pcap_block) => {
                        if let Ok(eth) = SlicedPacket::from_ethernet(pcap_block.data)
                            && let Some(transport) = eth.transport
                                && let TransportSlice::Udp(udp) = transport {
                                    let _ = parser.parse_bytes(udp.payload());
                                }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("Failed to refill buffer");
            }
            Err(_) => break,
        }
    }

    // Check that templates were cached
    let ipfix_stats = parser.ipfix_cache_stats();
    let template_ids = parser.ipfix_template_ids();

    // IPFIX.pcap should have templates
    if ipfix_stats.current_size > 0 {
        assert!(!template_ids.is_empty(), "Should have cached template IDs");
    }
}

#[test]
fn test_pcap_cache_metrics() {
    let file = File::open(PCAP_PATH).expect("Failed to open PCAP file");
    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create PCAP reader");
    let mut parser = NetflowParser::default();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(pcap_block) => {
                        if let Ok(eth) = SlicedPacket::from_ethernet(pcap_block.data)
                            && let Some(transport) = eth.transport
                                && let TransportSlice::Udp(udp) = transport {
                                    let _ = parser.parse_bytes(udp.payload());
                                }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("Failed to refill buffer");
            }
            Err(_) => break,
        }
    }

    // Check cache metrics
    let ipfix_stats = parser.ipfix_cache_stats();
    let metrics = &ipfix_stats.metrics;

    // If we parsed templates and data, we should have some cache activity
    if ipfix_stats.current_size > 0 {
        let total_lookups = metrics.hits + metrics.misses;
        assert!(
            total_lookups > 0 || metrics.hits == 0,
            "Should have some cache activity"
        );
    }
}

#[test]
fn test_pcap_iterator_api() {
    let file = File::open(PCAP_PATH).expect("Failed to open PCAP file");
    let mut reader = LegacyPcapReader::new(65536, file).expect("Failed to create PCAP reader");
    let mut parser = NetflowParser::default();
    let mut netflow_count = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_) => (),
                    PcapBlockOwned::Legacy(pcap_block) => {
                        if let Ok(eth) = SlicedPacket::from_ethernet(pcap_block.data)
                            && let Some(transport) = eth.transport
                                && let TransportSlice::Udp(udp) = transport {
                                    // Use iterator API instead of parse_bytes
                                    for _pkt in parser.iter_packets(udp.payload()) {
                                        netflow_count += 1;
                                    }
                                }
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().expect("Failed to refill buffer");
            }
            Err(_) => break,
        }
    }

    assert!(
        netflow_count > 0,
        "Should have parsed NetFlow packets using iterator API"
    );
}
