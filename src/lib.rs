//! # netflow_parser
//!
//! A netflow_parser library for V5, V7, V9, IPFIX written in Rust.
//!
//! # Example:
//!
//! ## V5:
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! match NetflowParser::parse_bytes(&v5_packet).first() {
//!     Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
//!     _ => (),
//! }
//! ```
//!
//! ## Want JSON?
//! ```rust
//! use serde_json::json;
//! use netflow_parser::NetflowParser;
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! println!("{}", json!(NetflowParser::parse_bytes(&v5_packet)).to_string());
//! ```
//!
//! ## Output:
//!
//! ```json
//! [{"V5":{"body":{"d_octets":66051,"d_pkts":101124105,"dst_addr":"4.5.6.7","dst_as":515,"dst_mask":5,"dst_port":1029,"first":67438087,"input":515,"last":134807553,"next_hop":"8.9.0.1","output":1029,"pad1":6,"pad2":1543,"protocol":"EGP","src_addr":"0.1.2.3","src_as":1,"src_mask":4,"src_port":515,"tcp_flags":7,"tos":9},"header":{"count":512,"engine_id":7,"engine_type":6,"flow_sequence":33752069,"sampling_interval":2057,"sys_up_time":50332672,"unix_nsecs":134807553,"unix_secs":83887623,"unix_time":{"nanos_since_epoch":134807553,"secs_since_epoch":83887623},"version":5}}}]
//! ```

pub mod protocol;
pub mod static_versions;
mod time;

use log::*;
use serde::Serialize;
use static_versions::{v5::V5, v7::V7};

use nom_derive::{Nom, Parse};

#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacket {
    V5(V5),
    V7(V7),
}

#[derive(Debug, Clone)]
pub struct ParsedNetflow<'a> {
    remaining_bytes: &'a [u8],
    netflow_packet: NetflowPacket,
}

#[derive(Nom)]
struct NetflowHeader {
    version: u16,
}

enum NetflowVersion {
    V5,
    V7,
    V9,
    Unsupported,
}

impl NetflowHeader {
    fn get_version_from_bytes(packet: &[u8]) -> NetflowVersion {
        match NetflowHeader::parse_be(packet) {
            Ok((_, netflow_header)) if netflow_header.version == 5 => NetflowVersion::V5,
            Ok((_, netflow_header)) if netflow_header.version == 7 => NetflowVersion::V7,
            Ok((_, netflow_header)) if netflow_header.version == 9 => NetflowVersion::V9,
            _ => NetflowVersion::Unsupported,
        }
    }
}

pub trait NetflowByteParser {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>>;
}

pub struct NetflowParser;

impl NetflowParser {
    /// Takes a Netflow packet slice and returns a vector of Parsed Netflows.
    /// If we reach some parse error we return what items be have.
    pub fn parse_bytes(packet: &[u8]) -> Vec<NetflowPacket> {
        let mut packet_to_be_processed = <&[u8]>::clone(&packet);
        let mut netflow_results = vec![];

        // If we have bytes to parse
        while !packet_to_be_processed.is_empty() {
            // Attempt to Parse Bytes
            let parsed_netflow =
                match NetflowHeader::get_version_from_bytes(packet_to_be_processed) {
                    NetflowVersion::V5 => V5::parse_bytes(packet),
                    NetflowVersion::V7 => V7::parse_bytes(packet),
                    _ => Err("Unsupported Version!".to_string().into()),
                };
            // Handle Result of Parsed Bytes
            match parsed_netflow {
                Ok(parsed_netflow) => {
                    packet_to_be_processed = parsed_netflow.remaining_bytes;
                    netflow_results.push(parsed_netflow.netflow_packet);
                }
                Err(parsed_error) => {
                    warn!("{parsed_error}");
                    break;
                }
            }
        }
        netflow_results
    }
}

#[cfg(test)]
mod tests {

    use super::NetflowParser;
    use insta::assert_yaml_snapshot;

    #[test]
    fn it_parses_v5() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v7() {
        let packet = [
            0, 7, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::parse_bytes(&packet));
    }
}
