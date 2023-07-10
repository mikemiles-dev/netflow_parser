//! # Netflow V9
//!
//! References:
//! - <https://www.ietf.org/rfc/rfc3954.txt>
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use crate::protocol::ProtocolTypes;
use crate::time::build_unix_time;
use crate::{NetflowByteParserVariable, NetflowPacket, ParsedNetflow};

use nom::error::{Error as NomError, ErrorKind};
use nom::number::complete::{be_u128, be_u32};
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;
use std::time::SystemTime;
use Nom;

use log::error;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

const TEMPLATE_ID: u16 = 0;
const OPTIONS_TEMPLATE_MAX_RANGE: u16 = 255;

type TemplateId = u16;

#[derive(Default)]
pub struct V9Parser {
    pub templates: HashMap<TemplateId, V9Template>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct V9 {
    /// V9 Header
    pub header: V9Header,
    /// Flowsets
    #[nom(Count = "header.count", Parse = "{ |i| FlowSet::parse(i, parser) }")]
    pub flowsets: Vec<FlowSet>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct V9Header {
    /// The version of NetFlow records exported in this packet; for Version 9, this value is 9
    pub version: u16,
    /// Number of FlowSet records (both template and data) contained within this packet
    pub count: u16,
    /// Time in milliseconds since this device was first booted
    pub sys_up_time: u32,
    /// Seconds since 0000 Coordinated Universal Time (UTC) 1970
    pub unix_secs: u32,
    /// SystemTime build from unix_secs
    #[nom(Parse = "{ |i| Ok((i, build_unix_time(unix_secs, 0))) }")]
    pub unix_time: SystemTime,
    /// Incremental sequence counter of all export packets sent by this export device; this value is
    /// cumulative, and it can be used to identify whether any export packets have been missed.
    /// Note: This is a change from the NetFlow Version 5 and Version 8 headers, where this number
    /// represented "total flows."
    pub sequence_number: u32,
    /// The Source ID field is a 32-bit value that is used to guarantee uniqueness for all flows exported
    /// from a particular device. (The Source ID field is the equivalent of the engine type and engine ID
    /// fields found in the NetFlow Version 5 and Version 8 headers). The format of this field is vendor
    /// specific. In the Cisco implementation, the first two bytes are reserved for future expansion, and
    /// will always be zero. Byte 3 provides uniqueness with respect to the routing engine on the exporting
    /// device. Byte 4 provides uniqueness with respect to the particular line card or Versatile Interface
    /// Processor on the exporting device. Collector devices should use the combination of the source IP
    /// address plus the Source ID field to associate an incoming NetFlow export packet with a unique
    /// instance of NetFlow on a particular device.
    pub source_id: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct FlowSet {
    /// The FlowSet ID is used to distinguish template records from data records.
    /// A template record always has a FlowSet ID in the range of 0-255. Currently,
    /// the template record that describes flow fields has a FlowSet ID of zero and
    /// the template record that describes option fields (described below) has a
    /// FlowSet ID of 1. A data record always has a nonzero FlowSet ID greater than 255.
    pub flow_set_id: u16,
    /// Templates
    #[nom(
        Cond = "flow_set_id == TEMPLATE_ID",
        // Save our templates
        PostExec = "if let Some(template) = template.clone() { parser.templates.insert(template.template_id, template); }"
    )]
    // Todo add options template
    pub template: Option<V9Template>,
    #[nom(
        Cond = "flow_set_id > OPTIONS_TEMPLATE_MAX_RANGE",
        Parse = "{ |i| V9Data::parse(i, parser, flow_set_id) }"
    )]
    pub data: Option<V9Data>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct V9Template {
    /// Length refers to the total length of this FlowSet. Because an individual
    /// template FlowSet may contain multiple template IDs (as illustrated above),
    /// the length value should be used to determine the position of the next FlowSet
    /// record, which could be either a template or a data FlowSet.
    /// Length is expressed in Type/Length/Value (TLV) format, meaning that the value
    /// includes the bytes used for the FlowSet ID and the length bytes themselves, as
    /// well as the combined lengths of all template records included in this FlowSet.
    pub length: u16,
    /// As a router generates different template FlowSets to match the type of NetFlow
    /// data it will be exporting, each template is given a unique ID. This uniqueness
    /// is local to the router that generated the template ID.
    /// Templates that define data record formats begin numbering at 256 since 0-255
    /// are reserved for FlowSet IDs.
    pub template_id: u16,
    /// This field gives the number of fields in this template record. Because a template
    /// FlowSet may contain multiple template records, this field allows the parser to
    /// determine the end of the current template record and the start of the next.
    pub field_count: u16,
    /// Template Fields.
    #[nom(Count = "field_count")]
    pub fields: Vec<V9TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct V9TemplateField {
    /// This numeric value represents the type of the field. The possible values of the
    /// field type are vendor specific. Cisco supplied values are consistent across all
    /// platforms that support NetFlow Version 9.
    /// At the time of the initial release of the NetFlow Version 9 code (and after any
    /// subsequent changes that could add new field-type definitions), Cisco provides a file
    /// that defines the known field types and their lengths.
    /// The currently defined field types are detailed in Table 6.
    pub field_type: u16,
    /// This number gives the length of the above-defined field, in bytes.
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct V9Data {
    /// This field gives the length of the data FlowSet.  Length is expressed in TLV format,
    /// meaning that the value includes the bytes used for the FlowSet ID and the length bytes
    /// themselves, as well as the combined lengths of any included data records.
    pub length: u16,
    // Data Fields
    #[nom(Parse = "{ |i| parse_v9_data_fields(i, flow_set_id, parser.templates.clone()) }")]
    pub data_fields: Vec<V9DataField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: V9TemplateField))]
pub struct V9DataField {
    /// Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 1",
        Take = "field.field_length"
    )]
    pub in_bytes: Option<Vec<u8>>,
    /// Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 2",
        Take = "field.field_length"
    )]
    pub in_pkts: Option<Vec<u8>>,
    /// Number of flows that were aggregated; default for N is 4
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 3",
        Take = "field.field_length"
    )]
    pub flows: Option<Vec<u8>>,
    /// IP protocol byte
    #[nom(Cond = "field.field_type == 4")]
    protocol: Option<ProtocolTypes>,
    /// Type of Service byte setting when entering incoming interface
    #[nom(Cond = "field.field_type == 5")]
    src_tos: Option<u8>,
    /// Cumulative of all the TCP flags seen for this flow
    #[nom(Cond = "field.field_type == 6")]
    pub tcp_flags: Option<u8>,
    /// TCP/UDP source port number i.e.: FTP, Telnet, or equivalent
    #[nom(Cond = "field.field_type == 7")]
    pub l4_src_port: Option<u16>,
    /// IPv4 source address
    #[nom(
        Cond = "field.field_type == 8",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    pub ipv4_src_addr: Option<Ipv4Addr>,
    /// The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation
    #[nom(Cond = "field.field_type == 9")]
    pub src_mask: Option<u8>,
    /// Input interface index; default for N is 2 but higher values could be used
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 10",
        Take = "field.field_length"
    )]
    pub input_snmp: Option<Vec<u8>>,
    /// TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent
    #[nom(Cond = "field.field_type == 11")]
    pub l4_dst_port: Option<u16>,
    /// IPv4 destination address
    #[nom(
        Cond = "field.field_type == 12",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    pub ipv4_dst_addr: Option<Ipv4Addr>,
    /// The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation
    #[nom(Cond = "field.field_type == 13")]
    pub dst_mask: Option<u8>,
    /// Output interface index; default for N is 2 but higher values could be used
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 14",
        Take = "field.field_length"
    )]
    pub output_snmp: Option<Vec<u8>>,
    /// IPv4 address of next-hop router
    #[nom(
        Cond = "field.field_type == 15",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    pub ipv4_next_hop: Option<Ipv4Addr>,
    /// Source BGP autonomous system number where N could be 2 or 4
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 16",
        Take = "field.field_length"
    )]
    pub src_as: Option<Vec<u8>>,
    /// Destination BGP autonomous system number where N could be 2 or 4
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 17",
        Take = "field.field_length"
    )]
    pub dst_as: Option<Vec<u8>>,
    /// Next-hop router's IP in the BGP domain
    #[nom(
        Cond = "field.field_type == 18",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    pub bgp_ipv4_next_hop: Option<Ipv4Addr>,
    /// IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 19",
        Take = "field.field_length"
    )]
    pub mul_dst_pkts: Option<Vec<u8>>,
    /// IP multicast outgoing byte counter with length N x 8 bits for bytes associated with the IP Flow
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 20",
        Take = "field.field_length"
    )]
    pub mul_dst_bytes: Option<Vec<u8>>,
    /// System uptime at which the last packet of this flow was switched
    #[nom(Cond = "field.field_type == 21")]
    pub last_switched: Option<u32>,
    /// System uptime at which the first packet of this flow was switched
    #[nom(Cond = "field.field_type == 22")]
    pub first_switched: Option<u32>,
    /// Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 23",
        Take = "field.field_length"
    )]
    pub out_bytes: Option<Vec<u8>>,
    /// Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow.
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 24",
        Take = "field.field_length"
    )]
    pub out_pkts: Option<Vec<u8>>,
    /// Minimum IP packet length on incoming packets of the flow
    #[nom(Cond = "field.field_type == 25")]
    pub min_pkt_lngth: Option<u16>,
    /// Maximum IP packet length on incoming packets of the flow
    #[nom(Cond = "field.field_type == 26")]
    pub max_pkt_lngth: Option<u16>,
    /// IPv6 Source Address
    #[nom(
        Cond = "field.field_type == 27",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    pub ipv6_src_addr: Option<Ipv6Addr>,
    /// IPv6 Destination Address
    #[nom(
        Cond = "field.field_type == 28",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    pub ipv6_dist_addr: Option<Ipv6Addr>,
    /// Length of the IPv6 source mask in contiguous bits
    #[nom(Cond = "field.field_type == 29")]
    pub ipv6_src_mask: Option<u8>,
    /// Length of the IPv6 destination mask in contiguous bits
    #[nom(Cond = "field.field_type == 30")]
    pub ipv6_dst_mask: Option<u8>,
    /// IPv6 flow label as per RFC 2460 definition
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == 31",
        Take = "3"
    )]
    pub ipv6_flow_label: Option<Vec<u8>>,
    /// Internet Control Message Protocol (ICMP) packet type; reported as ((ICMP Type*256) + ICMP code)
    #[nom(Cond = "field.field_type == 32")]
    pub icmp_type: Option<u16>,
}

/// Custom  Field Parse function.
/// Pass all templates and iter through the template fields.
/// Use those fields to parse each FlowSet Data Fields.
fn parse_v9_data_fields(
    i: &[u8],
    flow_set_id: u16,
    templates: HashMap<u16, V9Template>,
) -> IResult<&[u8], Vec<V9DataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        error!("Could not fetch any v9 templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.fields.iter() {
        let (i, v9_data_field) = V9DataField::parse(remaining, field.clone())?;
        remaining = i;
        fields.push(v9_data_field)
    }
    Ok((remaining, fields))
}

impl NetflowByteParserVariable for V9Parser {
    /// Main V9 Parse function.
    fn parse_bytes<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let (remaining, v9_parsed) =
            V9::parse(packet, self).map_err(|_| "Could not parse v9_packet".to_string())?;

        Ok(ParsedNetflow {
            remaining: remaining.to_vec(),
            netflow_packet: NetflowPacket::V9(v9_parsed),
        })
    }
}
