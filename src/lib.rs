//! # netflow_parser
//!
//! ## Description
//!
//! A Netflow Parser library for Cisco V5, V7, V9, IPFIX written in Rust.
//! Supports chaining of multiple versions in the same stream.  ({v5 packet}, {v7 packet}, {v5 packet}, {v9 packet}, etc.)
//!
//! ## References
//! See: <https://en.wikipedia.org/wiki/NetFlow>
//!
//! ## Example
//!
//! ### V5
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
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
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet)).to_string());
//! ```
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
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let parsed = NetflowParser::default().parse_bytes(&v5_packet);
//!
//! let v5_parsed: Vec<NetflowPacket> = parsed.into_iter().filter(|p| p.is_v5()).collect();
//! ```
//!
//! ## Parsing out unneeded versions
//! If you only care about a specific version or versions you can specfic `allowed_version`:
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let mut parser = NetflowParser::default();
//! parser.allowed_versions = [7, 9].into();
//! let parsed = NetflowParser::default().parse_bytes(&v5_packet);
//! ```
//!
// !This code will return an empty Vec as version 5 is not allowed.
//!
//! ## Netflow Common
//!
//! **Note:** This feature requires the `netflow_common` feature flag to be enabled:
//! ```toml
//! netflow_parser = { version = "x.x.x", features = ["netflow_common"] }
//! ```
//!
//! We have included a `NetflowCommon` and `NetflowCommonFlowSet` structure.
//! This will allow you to use common fields without unpacking values from specific versions.
//! If the packet flow does not have the matching field it will simply be left as `None`.
//!
//! ### NetflowCommon and NetflowCommonFlowSet Struct:
//! ```rust
//! use std::net::IpAddr;
//! use netflow_parser::protocol::ProtocolTypes;
//!
//! #[derive(Debug, Default)]
//! pub struct NetflowCommon {
//!     pub version: u16,
//!     pub timestamp: u32,
//!     pub flowsets: Vec<NetflowCommonFlowSet>,
//! }
//!
//! #[derive(Debug, Default)]
//! struct NetflowCommonFlowSet {
//!     src_addr: Option<IpAddr>,
//!     dst_addr: Option<IpAddr>,
//!     src_port: Option<u16>,
//!     dst_port: Option<u16>,
//!     protocol_number: Option<u8>,
//!     protocol_type: Option<ProtocolTypes>,
//!     first_seen: Option<u32>,
//!     last_seen: Option<u32>,
//!     src_mac: Option<String>,
//!     dst_mac: Option<String>,
//! }
//! ```
//!
//! ### Converting NetflowPacket to NetflowCommon
//!
//! ```rust,ignore
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
//!     4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
//!     2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
//! let netflow_common = NetflowParser::default()
//!                      .parse_bytes(&v5_packet)
//!                      .first()
//!                      .unwrap()
//!                      .as_netflow_common()
//!                      .unwrap();
//!
//! for common_flow in netflow_common.flowsets.iter() {
//!     println!("Src Addr: {} Dst Addr: {}", common_flow.src_addr.unwrap(), common_flow.dst_addr.unwrap());
//! }
//! ```
//!
//! ### Alternative if you just want to gather all flowsets from all packets into a flattened vector of NetflowCommonFlowSet:
//!
//! ```rust,ignore
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
//!     4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
//!     2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
//! let netflow_common_flowsets = NetflowParser::default()
//!                     .parse_bytes_as_netflow_common_flowsets(&v5_packet);
//!
//! println!("Flowsets: {:?}", netflow_common_flowsets);
//! ```
//!
//! ## Re-Exporting flows
//! Netflow Parser now supports parsed V5, V7, V9, IPFix can be re-exported back into bytes.  Please note for V9/IPFix
//! we only export the original padding we dissected and DO NOT calculate/align the flowset(s) padding ourselves.  If you
//! do any modifications to an existing V9/IPFix flow or have created your own you must manually adjust the padding yourself.
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
//! Parse the data (`&[u8]` as any other versions.  The parser (NetflowParser) holds onto already parsed templates, so you can just send a header/data flowset combo, and it will use the cached templates.)   To see cached templates simply use the parser for the correct version (v9_parser for v9, ipfix_parser for IPFix.)
//!
//! **IPFIx Note:**  We only parse sequence number and domain id, it is up to you if you wish to validate it.
//!
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
//! * `netflow_common` - When enabled provides `NetflowCommon` and `NetflowCommonFlowSet` structures for working with common fields across different Netflow versions.  Disabled by default.
//!
//! ## Included Examples
//! Examples have been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multithreaded examples in the examples directory.
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
//!
//! or
//!
//! ```cargo run --example netflow_pcap```
//!
//! The pcap example also shows how to cache flows that have not yet discovered a template.
//!
//! ## Support My Work
//!
//! If you find my work helpful, consider supporting me!
//!
//! [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/michaelmileusnich)
//!
//! [![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/mikemiles-dev)

#[cfg(feature = "netflow_common")]
pub mod netflow_common;
pub mod protocol;
pub mod static_versions;
mod tests;
pub mod variable_versions;

#[cfg(feature = "netflow_common")]
use crate::netflow_common::{NetflowCommon, NetflowCommonError, NetflowCommonFlowSet};

use static_versions::{
    v5::{V5, V5Parser},
    v7::{V7, V7Parser},
};
use variable_versions::ipfix::{IPFix, IPFixParser};
use variable_versions::v9::{V9, V9Parser};

use nom_derive::{Nom, Parse};
use serde::Serialize;

use std::collections::HashSet;

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
    #[cfg(feature = "netflow_common")]
    pub fn as_netflow_common(&self) -> Result<NetflowCommon, NetflowCommonError> {
        self.try_into()
    }
}

#[derive(Nom)]
/// Generic Netflow Header for shared versions
struct GenericNetflowHeader {
    version: u16,
}

#[derive(Debug)]
pub struct NetflowParser {
    pub v9_parser: V9Parser,
    pub ipfix_parser: IPFixParser,
    pub allowed_versions: HashSet<u16>,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
}

#[derive(Debug, Clone)]
pub enum ParsedNetflow<'a> {
    Success {
        packet: NetflowPacket,
        remaining: &'a [u8],
    },
    Error {
        error: NetflowParseError,
    },
    UnallowedVersion,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetflowPacketError {
    pub error: NetflowParseError,
    pub remaining: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub enum NetflowParseError {
    Incomplete(String),
    Partial(PartialParse),
    UnknownVersion(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
pub struct PartialParse {
    pub version: u16,
    pub remaining: Vec<u8>,
    pub error: String,
}

/// Iterator that yields NetflowPacket items from a byte buffer without allocating a Vec.
/// Maintains parser state for template caching (V9/IPFIX).
pub struct NetflowPacketIterator<'a> {
    parser: &'a mut NetflowParser,
    remaining: &'a [u8],
    errored: bool,
}

impl<'a> Iterator for NetflowPacketIterator<'a> {
    type Item = NetflowPacket;

    fn next(&mut self) -> Option<Self::Item> {
        // Stop if we've errored or no bytes remain
        if self.errored || self.remaining.is_empty() {
            return None;
        }

        match self.parser.parse_packet_by_version(self.remaining) {
            ParsedNetflow::Success {
                packet,
                remaining: new_remaining,
            } => {
                self.remaining = new_remaining;
                Some(packet)
            }
            ParsedNetflow::UnallowedVersion => {
                self.errored = true;
                None
            }
            ParsedNetflow::Error { error } => {
                self.errored = true;
                // Only include first N bytes of remaining data in error to prevent memory exhaustion
                let remaining_sample = if self.remaining.len() > self.parser.max_error_sample_size {
                    self.remaining[..self.parser.max_error_sample_size].to_vec()
                } else {
                    self.remaining.to_vec()
                };
                Some(NetflowPacket::Error(NetflowPacketError {
                    error,
                    remaining: remaining_sample,
                }))
            }
        }
    }
}

impl Default for NetflowParser {
    fn default() -> Self {
        Self {
            v9_parser: V9Parser::default(),
            ipfix_parser: IPFixParser::default(),
            allowed_versions: [5, 7, 9, 10].iter().cloned().collect(),
            max_error_sample_size: 256,
        }
    }
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

        let mut packets = Vec::new();
        let mut remaining = packet;

        while !remaining.is_empty() {
            match self.parse_packet_by_version(remaining) {
                ParsedNetflow::Success {
                    packet,
                    remaining: new_remaining,
                } => {
                    packets.push(packet);
                    remaining = new_remaining;
                }
                ParsedNetflow::UnallowedVersion => {
                    break;
                }
                ParsedNetflow::Error { error } => {
                    // Only include first N bytes of remaining data in error to prevent memory exhaustion
                    let remaining_sample = if remaining.len() > self.max_error_sample_size {
                        remaining[..self.max_error_sample_size].to_vec()
                    } else {
                        remaining.to_vec()
                    };
                    packets.push(NetflowPacket::Error(NetflowPacketError {
                        error,
                        remaining: remaining_sample,
                    }));
                    break;
                }
            }
        }

        packets
    }

    /// Returns an iterator that yields NetflowPacket items without allocating a Vec.
    /// This is useful for processing large batches of packets without collecting all results in memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::{NetflowParser, NetflowPacket};
    ///
    /// let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let mut parser = NetflowParser::default();
    ///
    /// for packet in parser.parse_bytes_iter(&v5_packet) {
    ///     match packet {
    ///         NetflowPacket::V5(v5) => println!("V5 packet: {:?}", v5.header.version),
    ///         NetflowPacket::Error(e) => println!("Error: {:?}", e),
    ///         _ => (),
    ///     }
    /// }
    /// ```
    #[inline]
    pub fn parse_bytes_iter<'a>(&'a mut self, packet: &'a [u8]) -> NetflowPacketIterator<'a> {
        NetflowPacketIterator {
            parser: self,
            remaining: packet,
            errored: false,
        }
    }

    #[inline]
    fn parse_packet_by_version<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match GenericNetflowHeader::parse(packet) {
            Ok((packet, header)) if self.allowed_versions.contains(&header.version) => {
                match header.version {
                    5 => V5Parser::parse(packet),
                    7 => V7Parser::parse(packet),
                    9 => self.v9_parser.parse(packet),
                    10 => self.ipfix_parser.parse(packet),
                    _ => ParsedNetflow::Error {
                        error: NetflowParseError::UnknownVersion(packet.to_vec()),
                    },
                }
            }
            Ok((_, _)) => ParsedNetflow::UnallowedVersion,
            Err(e) => ParsedNetflow::Error {
                error: NetflowParseError::Incomplete(e.to_string()),
            },
        }
    }

    /// Takes a Netflow packet slice and returns a vector of Parsed NetflowCommonFlowSet
    #[cfg(feature = "netflow_common")]
    #[inline]
    pub fn parse_bytes_as_netflow_common_flowsets(
        &mut self,
        packet: &[u8],
    ) -> Vec<NetflowCommonFlowSet> {
        let netflow_packets = self.parse_bytes(packet);
        netflow_packets
            .iter()
            .flat_map(|n| n.as_netflow_common().unwrap_or_default().flowsets)
            .collect()
    }
}
