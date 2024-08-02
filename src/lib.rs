//! # netflow_parser
//!
//! A netflow_parser library for Cisco V5, V7, V9, IPFIX written in Rust.
//! Supports chaining of multple versions in the same stream.  ({v5 packet}, {v7packet}, {v5packet}, {v9packet}, etc.)
//!
//! # References
//! See: <https://en.wikipedia.org/wiki/NetFlow>
//!
//! # Example:
//!
//! ## V5:
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! match NetflowParser::default().parse_bytes(&v5_packet).first() {
//!     Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
//!     Some(NetflowPacket::Error(e)) => println!("{:?}", e),
//!     _ => (),
//! }
//! ```
//!
//! ## Want Serialization such as JSON?
//! Structures fully support serialization.  Below is an example using the serde_json macro:
//! ```rust
//! use serde_json::json;
//! use netflow_parser::NetflowParser;
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet)).to_string());
//! ```
//!
//! ## Output:
//!
//! ```json
//! [{"V5":{"body":{"d_octets":66051,"d_pkts":101124105,"dst_addr":"4.5.6.7","dst_as":515,"dst_mask":5,"dst_port":1029,"first":67438087,"input":515,"last":134807553,"next_hop":"8.9.0.1","output":1029,"pad1":6,"pad2":1543,"protocol":"EGP","src_addr":"0.1.2.3","src_as":1,"src_mask":4,"src_port":515,"tcp_flags":7,"tos":9},"header":{"count":512,"engine_id":7,"engine_type":6,"flow_sequence":33752069,"sampling_interval":2057,"sys_up_time":50332672,"unix_nsecs":134807553,"unix_secs":83887623,"unix_time":{"nanos_since_epoch":134807553,"secs_since_epoch":83887623},"version":5}}}]
//! ```
//!
//! ## Filtering for a specific version
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let parsed = NetflowParser::default().parse_bytes(&v5_packet);
//!
//! let v5_parsed: Vec<NetflowPacket> = parsed.iter().filter(|p| p.is_v5()).map(|p| p.clone()).collect();
//! ```
//!
//! ## Re-Exporting flows
//! Netflow Parser now supports parsed V5, V7, V9, IPFix can be re-exported back into bytes.
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let packet = [
//!     0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
//!     4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
//!     2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
//! ];
//! if let NetflowPacket::V5(v5) = NetflowParser::default()
//!     .parse_bytes(&packet)
//!     .first()
//!     .unwrap()
//! {
//!     assert_eq!(v5.to_be_bytes(), packet);
//! }
//! ```
//!
//! ## V9/IPFix notes:
//!
//! Parse the data (`&[u8]` as any other versions.  The parser (NetflowParser) holds onto already parsed templates, so you can just send a header/data flowset combo and it will use the cached templates.)   To see cached templates simply use the parser for the correct version (v9_parser for v9, ipfix_parser for IPFix.)
//! ```rust
//! use netflow_parser::NetflowParser;
//! let parser = NetflowParser::default();
//! dbg!(parser.v9_parser.templates);
//! dbg!(parser.v9_parser.options_templates);
//! ```
//! To access templates flowset of a processed V9/IPFix flowset you can find the `flowsets` attribute on the Parsed Record.  In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.
//!
//! ## Features
//!
//! * `parse_unknown_fields` - When enabled fields not listed in this library will attempt to be parsed as a Vec of bytes and the field_number listed.  When disabled an error is thrown when attempting to parse those fields.  Enabled by default.
//!
//! ## Examples
//! Some examples has been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.
//!
//! To run:
//!
//! ```cargo run --example netflow_udp_listener_multi_threaded```
//!
//! or
//!
//! ```cargo run --example netflow_udp_listener_single_threaded```
//!
//! or
//!
//! ```cargo run --example netflow_udp_listener_tokio```

pub mod protocol;
pub mod static_versions;
mod tests;
pub mod variable_versions;

use static_versions::{v5::V5, v7::V7};
use variable_versions::ipfix::{IPFix, IPFixParser};
use variable_versions::v9::{V9Parser, V9};

use crate::static_versions::v5;
use crate::static_versions::v7;
use crate::variable_versions::ipfix;
use crate::variable_versions::v9;

use nom_derive::{Nom, Parse};
use serde::Serialize;

/// Enum of supported Netflow Versions
#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacket {
    /// Version 5
    V5(V5),
    /// Version 7
    V7(V7),
    /// Version 9
    V9(V9),
    /// IPFix  
    IPFix(IPFix),
    /// Error
    Error(NetflowPacketError),
}

impl NetflowPacket {
    pub fn is_v5(&self) -> bool {
        matches!(self, Self::V5(_v))
    }
    pub fn is_v7(&self) -> bool {
        matches!(self, Self::V7(_v))
    }
    pub fn is_v9(&self) -> bool {
        matches!(self, Self::V9(_v))
    }
    pub fn is_ipfix(&self) -> bool {
        matches!(self, Self::IPFix(_v))
    }
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_v))
    }
}

#[derive(Nom)]
/// Generic Netflow Header for shared versions
struct GenericNetflowHeader {
    version: u16,
}

#[derive(Default, Debug)]
pub struct NetflowParser {
    pub v9_parser: V9Parser,
    pub ipfix_parser: IPFixParser,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedNetflow {
    pub(crate) remaining: Vec<u8>,
    /// Parsed Netflow Packet
    pub(crate) result: NetflowPacket,
}

impl ParsedNetflow {
    fn new(remaining: &[u8], result: NetflowPacket) -> Self {
        Self {
            remaining: remaining.to_vec(),
            result,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetflowPacketError {
    pub error: NetflowParseError,
    pub remaining: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub enum NetflowParseError {
    V5(String),
    V7(String),
    V9(String),
    IPFix(String),
    Incomplete(String),
    UnknownVersion(Vec<u8>),
}

impl NetflowParser {
    /// Takes a Netflow packet slice and returns a vector of Parsed Netflows.
    /// If we reach some parse error we return what items be have.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use serde_json::json;
    /// use netflow_parser::NetflowParser;
    ///
    /// let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet)).to_string());
    /// ```
    ///
    /// ## Output:
    ///
    /// ```json
    /// [{"V5":{"header":{"count":1,"engine_id":7,"engine_type":6,"flow_sequence":33752069,"sampling_interval":2057,"sys_up_time":{"nanos":672000000,"secs":50332},"unix_nsecs":134807553,"unix_secs":83887623,"version":5},"sets":[{"d_octets":66051,"d_pkts":101124105,"dst_addr":"4.5.6.7","dst_as":515,"dst_mask":5,"dst_port":1029,"first":{"nanos":87000000,"secs":67438},"input":515,"last":{"nanos":553000000,"secs":134807},"next_hop":"8.9.0.1","output":1029,"pad1":6,"pad2":1543,"protocol_number":8,"protocol_type":"Egp","src_addr":"0.1.2.3","src_as":1,"src_mask":4,"src_port":515,"tcp_flags":7,"tos":9}]}}]
    /// ```
    ///
    #[inline]
    pub fn parse_bytes(&mut self, packet: &[u8]) -> Vec<NetflowPacket> {
        if packet.is_empty() {
            return vec![];
        }
        self.parse_packet_by_version(packet)
            .map(|parsed_netflow| {
                let parsed_result = vec![parsed_netflow.result];
                if !parsed_netflow.remaining.is_empty() {
                    let parsed_remaining = self.parse_bytes(&parsed_netflow.remaining);
                    [parsed_result, parsed_remaining].concat()
                } else {
                    parsed_result
                }
            })
            .unwrap_or_else(|e| {
                vec![NetflowPacket::Error(NetflowPacketError {
                    error: e,
                    remaining: packet.to_vec(),
                })]
            })
    }

    /// Checks the first u16 of the packet to determine the version.  Parses the packet based on the version.
    /// If the version is unknown it returns an error.  If the packet is incomplete it returns an error.
    /// If the packet is parsed successfully it returns the parsed Netflow packet and the remaining bytes.
    fn parse_packet_by_version<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, NetflowParseError> {
        let (packet, version) = GenericNetflowHeader::parse(packet)
            .map(|(remaining, header)| (remaining, header.version))
            .map_err(|e| NetflowParseError::Incomplete(e.to_string()))?;

        match version {
            5 => v5::parse_netflow_v5(packet),
            7 => v7::parse_netflow_v7(packet),
            9 => v9::parse_netflow_v9(packet, &mut self.v9_parser),
            10 => ipfix::parse_netflow_ipfix(packet, &mut self.ipfix_parser),
            _ => Err(NetflowParseError::UnknownVersion(packet.to_vec())),
        }
    }
}
