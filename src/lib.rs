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
//! use netflow_parser::{NetflowParser, NetflowPacketResult};
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! match NetflowParser::default().parse_bytes(&v5_packet).first() {
//!     Some(NetflowPacketResult::V5(v5)) => assert_eq!(v5.header.version, 5),
//!     Some(NetflowPacketResult::Error(e)) => println!("{:?}", e),
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
//! use netflow_parser::{NetflowParser, NetflowPacketResult};
//!
//! let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let parsed = NetflowParser::default().parse_bytes(&v5_packet);
//!
//! let v5_parsed: Vec<NetflowPacketResult> = parsed.iter().filter(|p| p.is_v5()).map(|p| p.clone()).collect();
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
//!
//! To run:
//!
//! ```cargo run --example netflow_udp_listener_multi_threaded```
//!
//! or
//!
//! ```cargo run --example netflow_udp_listener_single_threaded```

pub mod netflow_header;
pub mod protocol;
pub mod static_versions;
pub mod variable_versions;

use serde::Serialize;

use netflow_header::{NetflowHeader, NetflowVersion};
use static_versions::{v5::V5, v7::V7};
use variable_versions::ipfix::{IPFix, IPFixParser};
use variable_versions::v9::{V9Parser, V9};

#[derive(Debug, Clone, Serialize)]
pub struct NetflowPacketError {
    pub error_message: String,
    pub bytes: Vec<u8>,
}

/// Enum of supported Netflow Versions
#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacketResult {
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

impl NetflowPacketResult {
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

#[derive(Debug, Clone)]
struct ParsedNetflow {
    remaining: Vec<u8>,
    /// Parsed Netflow Packet
    netflow_packet: NetflowPacketResult,
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
    pub ipfix_parser: IPFixParser,
}

impl NetflowParser {
    /// We match versions to parsers.
    fn parse_by_version<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        match NetflowHeader::parse_header(packet) {
            Ok((i, netflow_header)) if netflow_header.version == NetflowVersion::V5 => {
                V5::parse_bytes(i)
            }
            Ok((i, netflow_header)) if netflow_header.version == NetflowVersion::V7 => {
                V7::parse_bytes(i)
            }
            Ok((i, netflow_header)) if netflow_header.version == NetflowVersion::V9 => {
                self.v9_parser.parse_bytes(i)
            }
            Ok((i, netflow_header)) if netflow_header.version == NetflowVersion::IPFix => {
                self.ipfix_parser.parse_bytes(i)
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
    #[inline]
    pub fn parse_bytes(&mut self, packet: &[u8]) -> Vec<NetflowPacketResult> {
        if packet.is_empty() {
            return vec![];
        }
        self.parse_by_version(packet)
            .map(|parsed_netflow| {
                let mut parsed = vec![parsed_netflow.netflow_packet];
                parsed.append(&mut self.parse_bytes(parsed_netflow.remaining.as_slice()));
                parsed
            })
            .unwrap_or_else(|e| {
                vec![NetflowPacketResult::Error(NetflowPacketError {
                    error_message: e.to_string(),
                    bytes: packet.to_vec(),
                })]
            })
    }
}

#[cfg(test)]
mod tests {

    use crate::variable_versions::ipfix::{
        Template as IPFixTemplate, TemplateField as IPFixTemplateField,
    };
    use crate::variable_versions::v9::{
        Template as V9Template, TemplateField as V9TemplateField,
    };
    use crate::NetflowParser;
    use insta::assert_yaml_snapshot;

    #[test]
    fn it_parses_unix_timestamp_correctly() {
        use nom::number::complete::{be_u32, be_u64};
        use std::time::Duration;

        let packet = [5, 0, 6, 7, 8, 9, 0, 1];
        let (remain, secs1) =
            be_u32::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        let (remain, nsecs1) = be_u32::<&[u8], nom::error::Error<&[u8]>>(remain).unwrap();
        assert_eq!(remain, []);

        let time1 = Duration::from_nanos(nsecs1 as u64) + Duration::from_secs(secs1 as u64);

        let (remain, secs_nsecs) =
            be_u64::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        assert_eq!(remain, []);
        let secs2 = (secs_nsecs >> 32) as u32 as u64;
        let nsecs2 = secs_nsecs as u32;

        let time2 = Duration::new(secs2, nsecs2);

        assert_eq!(secs1 as u64, secs2);
        assert_eq!(nsecs1, nsecs2);
        assert_eq!(time1, time2);
    }

    #[test]
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v5() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(feature = "unix_timestamp")]
    fn it_parses_v5_timestamp() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_creates_error() {
        let packet = [12, 13, 14];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v7() {
        let packet = [
            0, 7, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(feature = "unix_timestamp")]
    fn it_parses_v7_timestamp() {
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
    fn it_parses_v9_many_flows() {
        let packet = [
            0, 9, 0, 3, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8, 9, 2, 3, 4, 9, 9,
            9, 8,
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
            V9TemplateField {
                field_type_number: 1,
                field_type: super::variable_versions::v9_lookup::V9Field::InBytes,
                field_length: 4,
            },
            V9TemplateField {
                field_type_number: 8,
                field_type: super::variable_versions::v9_lookup::V9Field::Ipv4SrcAddr,
                field_length: 4,
            },
        ];
        let template = V9Template {
            length: 16,
            field_count: 2,
            template_id: 258,
            fields,
        };
        let mut parser = NetflowParser::default();
        parser.v9_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix() {
        let packet = [
            0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3, 2, 0, 2,
            0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_panic_with_invalid_options_ipfix_template() {
        let packet = [
            0, 10, 0, 44, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 13, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0,
        ];
        NetflowParser::default().parse_bytes(&packet);
    }

    #[test]
    fn it_parses_ipfix_data_cached_template() {
        let packet = [
            0, 10, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let fields = vec![
            IPFixTemplateField {
                field_type_number: 2,
                field_type:
                    super::variable_versions::ipfix_lookup::IPFixField::PacketDeltaCount,
                field_length: 2,
                enterprise_number: None,
            },
            IPFixTemplateField {
                field_type_number: 8,
                field_type:
                    super::variable_versions::ipfix_lookup::IPFixField::SourceIpv4address,
                field_length: 4,
                enterprise_number: None,
            },
        ];
        let template = IPFixTemplate {
            field_count: 2,
            template_id: 258,
            fields,
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_with_no_template_fields_raises_error() {
        let packet = [
            0, 10, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let template = IPFixTemplate {
            field_count: 2,
            template_id: 258,
            fields: vec![],
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_with_no_template_fields_raises_error() {
        let packet = [
            0, 9, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let template = V9Template {
            length: 10,
            field_count: 2,
            template_id: 258,
            fields: vec![],
        };
        let mut parser = NetflowParser::default();
        parser.v9_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_options_template() {
        let packet = [
            0, 10, 0, 44, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 3, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_options_template_with_data() {
        let packet = [
            0, 10, 0, 64, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 3, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0, 1, 4, 0, 20, 0, 0, 0,
            1, 1, 20, 20, 20, 0, 0, 0, 2, 20, 20, 30, 30,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }
}
