//! # netflow_parser
//!
//! A netflow_parser library for V5, V7, V9, IPFIX written in Rust.
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
//! ## Examples
//! Some examples has been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.

pub mod protocol;
pub mod static_versions;
mod time;
pub mod variable_versions;

use log::*;
use serde::Serialize;
use static_versions::{v5::V5, v7::V7};
use variable_versions::v9::{V9Parser, V9};

use nom_derive::{Nom, Parse};

/// Enum of supported Netflow Versions
#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacket {
    /// Version 5
    V5(V5),
    /// Version 7
    V7(V7),
    /// Version 9
    V9(V9),
}

#[derive(Debug, Clone)]
pub struct ParsedNetflow {
    remaining: Vec<u8>,
    /// Parsed Netflow Packet
    pub netflow_packet: NetflowPacket,
}

/// Struct is used simply to match how to handle the result of the packet
#[derive(Nom)]
struct NetflowHeader {
    /// Netflow Version
    version: u16,
}

/// Trait provided for all static parser versions
trait NetflowByteParserStatic {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>>;
}

/// Trait provided for all variable parser versions.  We need a mutable self reference to store things like tempalates.
trait NetflowByteParserVariable {
    fn parse_bytes(
        &mut self,
        packet: &[u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>>;
}

#[derive(Default, Debug)]
pub struct NetflowParser {
    pub v9_parser: V9Parser,
}

impl NetflowParser {
    /// We match versions to parsers.
    fn parse_by_version<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        match NetflowHeader::parse_be(packet) {
            Ok((_, netflow_header)) if netflow_header.version == 5 => V5::parse_bytes(packet),
            Ok((_, netflow_header)) if netflow_header.version == 7 => V7::parse_bytes(packet),
            Ok((_, netflow_header)) if netflow_header.version == 9 => {
                self.v9_parser.parse_bytes(packet)
            }
            _ => Err("Not Supported".to_string().into()),
        }
    }

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
    /// [{"V5":{"body":{"d_octets":66051,"d_pkts":101124105,"dst_addr":"4.5.6.7","dst_as":515,"dst_mask":5,"dst_port":1029,"first":67438087,"input":515,"last":134807553,"next_hop":"8.9.0.1","output":1029,"pad1":6,"pad2":1543,"protocol":"EGP","src_addr":"0.1.2.3","src_as":1,"src_mask":4,"src_port":515,"tcp_flags":7,"tos":9},"header":{"count":512,"engine_id":7,"engine_type":6,"flow_sequence":33752069,"sampling_interval":2057,"sys_up_time":50332672,"unix_nsecs":134807553,"unix_secs":83887623,"unix_time":{"nanos_since_epoch":134807553,"secs_since_epoch":83887623},"version":5}}}]
    /// ```
    ///
    pub fn parse_bytes(&mut self, packet: &[u8]) -> Vec<NetflowPacket> {
        match self.parse_by_version(packet) {
            Ok(parsed_netflow) => {
                let mut parsed = vec![parsed_netflow.netflow_packet];
                parsed.append(&mut self.parse_bytes(parsed_netflow.remaining.as_slice()));
                parsed
            }
            Err(parsed_error) => {
                warn!("{parsed_error}");
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::variable_versions::v9::{Template, TemplateField};

    use super::NetflowParser;
    use insta::assert_yaml_snapshot;

    #[test]
    fn it_parses_v5() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v7() {
        let packet = [
            0, 7, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_options_template() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 22, 1, 19, 0,
            4, 0, 8, 0, 2, 0, 2, 0, 34, 0, 2, 0, 36, 0, 1, 1, 19, 0, 9, 0, 2, 0, 100, 1, 0,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_data_cached_template() {
        let packet = [
            0, 9, 0, 1, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 0, 12, 9, 2, 3,
            4, 9, 9, 9, 8,
        ];
        let fields = vec![
            TemplateField {
                field_type_number: 1,
                field_type: super::variable_versions::v9_lookup::DataFieldType::INBYTES,
                field_length: 4,
            },
            TemplateField {
                field_type_number: 8,
                field_type: super::variable_versions::v9_lookup::DataFieldType::IPV4SRCADDR,
                field_length: 4,
            },
        ];
        let template = Template {
            length: 16,
            field_count: 2,
            template_id: 258,
            fields,
        };
        let mut parser = NetflowParser::default();
        parser.v9_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }
}
