//! # Netflow V9
//!
//! References:
//! - <https://www.ietf.org/rfc/rfc3954.txt>
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use crate::protocol::ProtocolTypes;
use crate::variable_versions::v9_lookup::*;
use crate::{NetflowByteParserVariable, NetflowPacket, ParsedNetflow};

use nom::error::{Error as NomError, ErrorKind};
use nom::number::complete::{be_u128, be_u32, be_u8};
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;
use Nom;

use log::error;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

const TEMPLATE_ID: u16 = 0;
const OPTIONS_TEMPLATE_ID: u16 = 1;
const FLOW_SET_MIN_RANGE: u16 = 255;

type TemplateId = u16;

#[derive(Default, Debug)]
pub struct V9Parser {
    pub templates: HashMap<TemplateId, Template>,
    pub options_templates: HashMap<TemplateId, OptionsTemplate>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct V9 {
    /// V9 Header
    pub header: Header,
    /// Flowsets
    #[nom(Count = "header.count", Parse = "{ |i| FlowSet::parse(i, parser) }")]
    pub flowsets: Vec<FlowSet>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// The version of NetFlow records exported in this packet; for Version 9, this value is 9
    pub version: u16,
    /// Number of FlowSet records (both template and data) contained within this packet
    pub count: u16,
    /// Time in milliseconds since this device was first booted
    pub sys_up_time: u32,
    /// Seconds since 0000 Coordinated Universal Time (UTC) 1970
    pub unix_secs: u32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Template>,
    // Options template
    #[nom(
        Cond = "flow_set_id == OPTIONS_TEMPLATE_ID",
        // Save our options templates
        PostExec = "if let Some(options_template) = options_template.clone() { parser.options_templates.insert(options_template.template_id, options_template); }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_template: Option<OptionsTemplate>,
    // Options Data
    #[nom(
        Cond = "flow_set_id > FLOW_SET_MIN_RANGE && parser.options_templates.get(&flow_set_id).is_some()",
        Parse = "{ |i| OptionsData::parse(i, parser, flow_set_id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_data: Option<OptionsData>,
    // Data
    #[nom(
        Cond = "flow_set_id > FLOW_SET_MIN_RANGE && parser.templates.get(&flow_set_id).is_some()",
        Parse = "{ |i| Data::parse(i, parser, flow_set_id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct Template {
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
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    /// This field gives the total length of this FlowSet. Because an individual template FlowSet might contain multiple template IDs, the length value must be used to determine the position of the next FlowSet record, which might be either a template or a data FlowSet.
    /// Length is expressed in TLV format, meaning that the value includes the bytes used for the FlowSet ID and the length bytes themselves, and the combined lengths of all template records included in this FlowSet.
    pub length: u16,
    /// As a router generates different template FlowSets to match the type of NetFlow data it is exporting, each template is given a unique ID. This uniqueness is local to the router that generated the template ID. The Template ID is greater than 255. Template IDs inferior to 255 are reserved.
    pub template_id: u16,
    /// This field gives the length in bytes of any scope fields that are contained in this options template.
    pub options_scope_length: u16,
    /// This field gives the length (in bytes) of any Options field definitions that are contained in this options template
    pub options_length: u16,
    /// Options Scope Fields
    #[nom(Count = "(options_scope_length / 4) as usize")]
    pub scope_fields: Vec<OptionsTemplateScopeField>,
    /// Options Fields
    #[nom(Count = "(options_length / 4) as usize")]
    pub option_fields: Vec<TemplateField>,
    /// Padding
    #[nom(
        Map = "|i: &[u8]| i.to_vec()",
        Take = "(length - options_scope_length - options_length - 10)  as usize"
    )]
    #[serde(skip_serializing)]
    padding: Vec<u8>,
}

/// Options Scope Fields
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplateScopeField {
    pub field_type_number: u16,
    #[nom(Value(ScopeFieldType::from(field_type_number)))]
    pub field_type: ScopeFieldType,
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct TemplateField {
    /// This numeric value represents the type of the field. The possible values of the
    /// field type are vendor specific. Cisco supplied values are consistent across all
    /// platforms that support NetFlow Version 9.
    /// At the time of the initial release of the NetFlow Version 9 code (and after any
    /// subsequent changes that could add new field-type definitions), Cisco provides a file
    /// that defines the known field types and their lengths.
    /// The currently defined field types are detailed in Table 6.
    pub field_type_number: u16,
    /// Human readable type
    #[nom(Value(DataFieldType::from(field_type_number)))]
    pub field_type: DataFieldType,
    /// This number gives the length of the above-defined field, in bytes.
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct OptionsData {
    // Length
    pub length: u16,
    // Scope Data
    #[nom(
        Parse = "{ |i| parse_scope_data_fields(i, flow_set_id, parser.options_templates.clone()) }"
    )]
    pub scope_fields: Vec<ScopeDataField>,
    // Options Data Fields
    #[nom(
        Parse = "{ |i| parse_options_data_fields(i, flow_set_id, parser.options_templates.clone()) }"
    )]
    pub options_fields: Vec<OptionDataField>,
    #[nom(
        Map = "|i: &[u8]| i.to_vec()",
        Take = "get_total_options_length(flow_set_id, length, parser)"
    )]
    #[serde(skip_serializing)]
    padding: Vec<u8>,
}

fn get_total_options_length(flow_set_id: u16, length: u16, parser: &mut V9Parser) -> usize {
    let options_length = match parser.options_templates.get(&flow_set_id) {
        Some(o) => o
            .option_fields
            .iter()
            .map(|o| o.field_length)
            .collect::<Vec<u16>>()
            .iter()
            .sum(),
        None => 0,
    };
    let scope_length = match parser.options_templates.get(&flow_set_id) {
        Some(s) => s
            .scope_fields
            .iter()
            .map(|o| o.field_length)
            .collect::<Vec<u16>>()
            .iter()
            .sum(),
        None => 0,
    };
    let total_length: usize = (length - 4 - (options_length + scope_length)).into();
    if length % 2 == 0 {
        total_length
    } else {
        total_length + 1
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: OptionsTemplateScopeField))]
pub struct ScopeDataField {
    /// System
    #[nom(
        Cond = "field.field_type == ScopeFieldType::System",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<u8>>,
    /// Interface
    #[nom(
        Cond = "field.field_type == ScopeFieldType::Interface",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<Vec<u8>>,
    /// LineCard
    #[nom(
        Cond = "field.field_type == ScopeFieldType::LineCard",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_card: Option<Vec<u8>>,
    /// NetFlowCache
    #[nom(
        Cond = "field.field_type == ScopeFieldType::NetflowCache",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_flow_cache: Option<Vec<u8>>,
    /// Template
    #[nom(
        Cond = "field.field_type == ScopeFieldType::Template",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct Data {
    /// This field gives the length of the data FlowSet.  Length is expressed in TLV format,
    /// meaning that the value includes the bytes used for the FlowSet ID and the length bytes
    /// themselves, as well as the combined lengths of any included data records.
    pub length: u16,
    // Data Fields
    #[nom(Parse = "{ |i| parse_data_fields(i, flow_set_id, parser.templates.clone()) }")]
    pub data_fields: Vec<DataField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: TemplateField))]
pub struct OptionDataField {
    #[nom(Value(field.field_type))]
    pub field_type: DataFieldType,
    #[nom(Map = "|i: &[u8]| i.to_vec()", Take = "field.field_length")]
    pub field_value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: TemplateField))]
pub struct DataField {
    /// Incoming counter with length N x 8 bits for number of bytes associated with an IP Flow.
    #[nom(
        Cond = "field.field_type == DataFieldType::INBYTES",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_bytes: Option<Vec<u8>>,
    /// Incoming counter with length N x 8 bits for the number of packets associated with an IP Flow
    #[nom(
        Cond = "field.field_type == DataFieldType::INPKTS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_pkts: Option<Vec<u8>>,
    /// Number of flows that were aggregated; default for N is 4
    #[nom(
        Cond = "field.field_type == DataFieldType::FLOWS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flows: Option<Vec<u8>>,
    /// IP protocol byte
    #[nom(Cond = "field.field_type == DataFieldType::PROTOCOL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<ProtocolTypes>,
    /// Type of Service byte setting when entering incoming interface
    #[nom(Cond = "field.field_type == DataFieldType::SRCTOS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    src_tos: Option<u8>,
    /// Cumulative of all the TCP flags seen for this flow
    #[nom(Cond = "field.field_type == DataFieldType::TCPFLAGS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<u8>,
    /// TCP/UDP source port number i.e.: FTP, Telnet, or equivalent
    #[nom(Cond = "field.field_type == DataFieldType::L4SRCPORT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l4_src_port: Option<u16>,
    /// IPv4 source address
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV4SRCADDR",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_src_addr: Option<Ipv4Addr>,
    /// The number of contiguous bits in the source address subnet mask i.e.: the submask in slash notation
    #[nom(Cond = "field.field_type == DataFieldType::SRCMASK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_mask: Option<u8>,
    /// Input interface index; default for N is 2 but higher values could be used
    #[nom(
        Cond = "field.field_type == DataFieldType::INPUTSNMP",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_snmp: Option<Vec<u8>>,
    /// TCP/UDP destination port number i.e.: FTP, Telnet, or equivalent
    #[nom(Cond = "field.field_type == DataFieldType::L4DSTPORT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l4_dst_port: Option<u16>,
    /// IPv4 destination address
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV4DSTADDR",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_dst_addr: Option<Ipv4Addr>,
    /// The number of contiguous bits in the destination address subnet mask i.e.: the submask in slash notation
    #[nom(Cond = "field.field_type == DataFieldType::DSTMASK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_mask: Option<u8>,
    /// Output interface index; default for N is 2 but higher values could be used
    #[nom(
        Cond = "field.field_type == DataFieldType::OUTPUTSNMP",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_snmp: Option<Vec<u8>>,
    /// IPv4 address of next-hop router
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV4NEXTHOP",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_next_hop: Option<Ipv4Addr>,
    /// Source BGP autonomous system number where N could be 2 or 4
    #[nom(
        Cond = "field.field_type == DataFieldType::SRCAS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_as: Option<Vec<u8>>,
    /// Destination BGP autonomous system number where N could be 2 or 4
    #[nom(
        Cond = "field.field_type == DataFieldType::DSTAS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_as: Option<Vec<u8>>,
    /// Next-hop router's IP in the BGP domain
    #[nom(
        Cond = "field.field_type == DataFieldType::BGPIPV4NEXTHOP",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgp_ipv4_next_hop: Option<Ipv4Addr>,
    /// IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow
    #[nom(
        Cond = "field.field_type == DataFieldType::MULDSTPKTS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mul_dst_pkts: Option<Vec<u8>>,
    /// IP multicast outgoing byte counter with length N x 8 bits for bytes associated with the IP Flow
    #[nom(
        Cond = "field.field_type == DataFieldType::MULDSTBYTES",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mul_dst_bytes: Option<Vec<u8>>,
    /// System uptime at which the last packet of this flow was switched
    #[nom(Cond = "field.field_type == DataFieldType::LASTSWITCHED")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_switched: Option<u32>,
    /// System uptime at which the first packet of this flow was switched
    #[nom(Cond = "field.field_type == DataFieldType::FIRSTSWITCHED")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_switched: Option<u32>,
    /// Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow
    #[nom(
        Cond = "field.field_type == DataFieldType::OUTBYTES",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_bytes: Option<Vec<u8>>,
    /// Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow.
    #[nom(
        Cond = "field.field_type == DataFieldType::OUTPKTS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_pkts: Option<Vec<u8>>,
    /// Minimum IP packet length on incoming packets of the flow
    #[nom(Cond = "field.field_type == DataFieldType::MINPKTLNGTH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pkt_lngth: Option<u16>,
    /// Maximum IP packet length on incoming packets of the flow
    #[nom(Cond = "field.field_type == DataFieldType::MAXPKTLNGTH")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pkt_lngth: Option<u16>,
    /// IPv6 Source Address
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV6SRCADDR",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_src_addr: Option<Ipv6Addr>,
    /// IPv6 Destination Address
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV6DSTADDR",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_dst_addr: Option<Ipv6Addr>,
    /// Length of the IPv6 source mask in contiguous bits
    #[nom(Cond = "field.field_type == DataFieldType::IPV6SRCMASK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_src_mask: Option<u8>,
    /// Length of the IPv6 destination mask in contiguous bits
    #[nom(Cond = "field.field_type == DataFieldType::IPV6DSTMASK")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_dst_mask: Option<u8>,
    /// IPv6 flow label as per RFC 2460 definition
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV6FLOWLABEL",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_flow_label: Option<Vec<u8>>,
    /// Internet Control Message Protocol (ICMP) packet type; reported as ((ICMP Type*256) + ICMP code)
    #[nom(Cond = "field.field_type == DataFieldType::ICMPTYPE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u16>,
    /// Internet Group Management Protocol (IGMP) packet type
    #[nom(Cond = "field.field_type == DataFieldType::MULIGMPTYPE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mul_igmp_type: Option<u8>,
    /// When using sampled NetFlow, the rate at which packets are sampled i.e.: a value of 100 indicates that one of every 100 packets is sampled
    #[nom(Cond = "field.field_type == DataFieldType::SAMPLINGINTERVAL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_interval: Option<u32>,
    /// The type of algorithm used for sampled NetFlow: 0x01 Deterministic Sampling ,0x02 Random Sampling
    #[nom(Cond = "field.field_type == DataFieldType::SAMPLINGALGORITHM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_algorithm: Option<u8>,
    /// Timeout value (in seconds) for active flow entries in the NetFlow cache
    #[nom(Cond = "field.field_type == DataFieldType::FLOWACTIVETIMEOUT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_active_timeout: Option<u16>,
    /// Timeout value (in seconds) for inactive flow entries in the NetFlow cache
    #[nom(Cond = "field.field_type == DataFieldType::FLOWINACTIVETIMEOUT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_inactive_timeout: Option<u16>,
    /// Type of flow switching engine: RP = 0, VIP/Linecard = 1
    #[nom(Cond = "field.field_type == DataFieldType::ENGINETYPE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_type: Option<u8>,
    /// ID number of the flow switching engine
    #[nom(Cond = "field.field_type == DataFieldType::ENGINEID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<u8>,
    /// Counter with length N x 8 bits for bytes for the number of bytes exported by the Observation Domain
    #[nom(
        Cond = "field.field_type == DataFieldType::TOTALBYTESEXP",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes_exp: Option<Vec<u8>>,
    /// Counter with length N x 8 bits for bytes for the number of bytes exported by the Observation Domain
    #[nom(
        Cond = "field.field_type == DataFieldType::TOTALPKTSEXP",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_pkts_exp: Option<Vec<u8>>,
    /// Counter with length N x 8 bits for bytes for the number of flows exported by the Observation Domain
    #[nom(
        Cond = "field.field_type == DataFieldType::TOTALFLOWSEXP",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_flows_exp: Option<Vec<u8>>,
    /// IPv4 source address prefix (specific for Catalyst architecture)
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV4SRCPREFIX",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_src_prefix: Option<Ipv4Addr>,
    /// IPv4 destination address prefix (specific for Catalyst architecture)
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV4DSTPREFIX",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_dst_prefix: Option<Ipv4Addr>,
    /// MPLS Top Label Type: 0x00 UNKNOWN 0x01 TE-MIDPT 0x02 ATOM 0x03 VPN 0x04 BGP 0x05 LDP
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    #[nom(Cond = "field.field_type == DataFieldType::MPLSTOPLABELTYPE")]
    pub mpls_top_label_type: Option<u8>,
    /// Forwarding Equivalent Class corresponding to the MPLS Top Label
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSTOPLABELIPADDR",
        Map = "Ipv4Addr::from",
        Parse = "be_u32"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_top_label_ip_addr: Option<Ipv4Addr>,
    /// Identifier shown in "show flow-sampler"
    #[nom(Cond = "field.field_type == DataFieldType::FLOWSAMPLERID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_sampler_id: Option<u8>,
    /// The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE
    #[nom(Cond = "field.field_type == DataFieldType::FLOWSAMPLERMODE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_sampler_mode: Option<u8>,
    /// The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE
    #[nom(Cond = "field.field_type == DataFieldType::FLOWSAMPLERRANDOMINTERVAL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_sampler_random_interval: Option<u32>,
    /// Minimum TTL on incoming packets of the flow
    #[nom(Cond = "field.field_type == DataFieldType::MINTTL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minttl: Option<u8>,
    /// Maximum TTL on incoming packets of the flow
    #[nom(Cond = "field.field_type == DataFieldType::MAXTTL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maxttl: Option<u8>,
    /// The IP v4 identification field
    #[nom(Cond = "field.field_type == DataFieldType::IPV4IDENT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_ident: Option<u16>,
    /// Type of Service byte setting when exiting outgoing interface
    #[nom(Cond = "field.field_type == DataFieldType::DSTTOS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_tos: Option<u8>,
    /// Incoming source MAC address
    #[nom(
        Cond = "field.field_type == DataFieldType::INSRCMAC",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "6"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_src_mac: Option<Vec<u8>>,
    /// Outgoing destination MAC address
    #[nom(
        Cond = "field.field_type == DataFieldType::OUTSRCMAC",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "6"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_dst_mac: Option<Vec<u8>>,
    /// Virtual LAN identifier associated with ingress interface
    #[nom(Cond = "field.field_type == DataFieldType::SRCVLAN")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_vlan: Option<u16>,
    /// Virtual LAN identifier associated with egress interface
    #[nom(Cond = "field.field_type == DataFieldType::DSTVLAN")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_vlan: Option<u16>,
    /// Internet Protocol Version Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed.
    #[nom(Cond = "field.field_type == DataFieldType::IPPROTOCOLVERSION")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol_version: Option<u8>,
    /// Flow direction: 0 - ingress flow, 1 - egress flow
    #[nom(
        Cond = "field.field_type == DataFieldType::DIRECTION",
        Map = "FlowDirectionType::from",
        Parse = "be_u8"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<FlowDirectionType>,
    /// IPv6 address of the next-hop router
    #[nom(
        Cond = "field.field_type == DataFieldType::IPV6NEXTHOP",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_next_hop: Option<Ipv6Addr>,
    /// Next-hop router in the BGP domain
    #[nom(
        Cond = "field.field_type == DataFieldType::BPGIPV6NEXTHOP",
        Map = "Ipv6Addr::from",
        Parse = "be_u128"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bgp_ipv6_next_hop: Option<Ipv6Addr>,
    /// Bit-encoded field identifying IPv6 option headers found in the flow
    #[nom(Cond = "field.field_type == DataFieldType::IPV6OPTIONHEADERS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_option_headers: Option<u32>,
    /// MPLS label at position 1 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL1",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_1: Option<Vec<u8>>,
    /// MPLS label at position 2 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL2",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_2: Option<Vec<u8>>,
    /// MPLS label at position 3 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL3",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_3: Option<Vec<u8>>,
    /// MPLS label at position 4 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL4",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_4: Option<Vec<u8>>,
    /// MPLS label at position 5 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL5",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_5: Option<Vec<u8>>,
    /// MPLS label at position 6 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL6",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_6: Option<Vec<u8>>,
    /// MPLS label at position 7 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL7",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_7: Option<Vec<u8>>,
    /// MPLS label at position 8 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL8",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_8: Option<Vec<u8>>,
    /// MPLS label at position 9 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL9",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_9: Option<Vec<u8>>,
    /// MPLS label at position 10 in the stack. This comprises 20 bits of MPLS label, 3 EXP (experimental) bits and 1 S (end-of-stack) bit.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSLABEL10",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "3"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_label_10: Option<Vec<u8>>,
    /// Incoming destination MAC address
    #[nom(
        Cond = "field.field_type == DataFieldType::INDSTMAC",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "6"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_dst_mac: Option<Vec<u8>>,
    /// Outgoing source MAC address
    #[nom(
        Cond = "field.field_type == DataFieldType::OUTSRCMAC",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "6"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_src_mac: Option<Vec<u8>>,
    /// Shortened interface name i.e.: "FE1/0"
    #[nom(
        Cond = "field.field_type == DataFieldType::IFNAME",
        Map = "|i| String::from_utf8_lossy(i).to_string()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_name: Option<String>,
    /// Full interface name i.e.: "'FastEthernet 1/0"
    #[nom(
        Cond = "field.field_type == DataFieldType::IFDESC",
        Map = "|i| String::from_utf8_lossy(i).to_string()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_desc: Option<String>,
    /// Name of the flow sampler
    #[nom(
        Cond = "field.field_type == DataFieldType::SAMPLERNAME",
        Map = "|i| String::from_utf8_lossy(i).to_string()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampler_name: Option<String>,
    /// Running byte counter for a permanent flow
    #[nom(
        Cond = "field.field_type == DataFieldType::INPERMANENTBYTES",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_permanent_bytes: Option<Vec<u8>>,
    /// Running packet counter for a permanent flow
    #[nom(
        Cond = "field.field_type == DataFieldType::INPERMANENTPKTS",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_permanent_pkts: Option<Vec<u8>>,
    /// The fragment-offset value from fragmented IP packets
    #[nom(Cond = "field.field_type == DataFieldType::FRAGMENTOFFSET")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_offset: Option<u16>,
    /// Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
    #[nom(
        Cond = "field.field_type == DataFieldType::FORWARDINGSTATUS",
        Map = "ForwardStatusType::new",
        Parse = "be_u8"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarding_status: Option<ForwardStatusType>,
    /// MPLS PAL Route Distinguisher.
    #[nom(
        Cond = "field.field_type == DataFieldType::MPLSPALRD",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "8"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_pal_rd: Option<Vec<u8>>,
    /// Number of consecutive bits in the MPLS prefix length.
    #[nom(Cond = "field.field_type == DataFieldType::MPLSPREFIXLEN")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpls_prefix_len: Option<u8>,
    /// BGP Policy Accounting Source Traffic Index
    #[nom(Cond = "field.field_type == DataFieldType::SRCTRAFFICINDEX")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_traffic_index: Option<u32>,
    /// BGP Policy Accounting Destination Traffic Index
    #[nom(Cond = "field.field_type == DataFieldType::DSTTRAFFICINDEX")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_traffic_index: Option<u32>,
    /// Application description.
    #[nom(
        Cond = "field.field_type == DataFieldType::APPLICATIONDESCRIPTION",
        Map = "|i| String::from_utf8_lossy(i).to_string()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_description: Option<String>,
    /// 8 bits of engine ID, followed by n bits of classification.
    #[nom(
        Cond = "field.field_type == DataFieldType::APPLICATIONTAG",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length as usize + 1"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_tag: Option<Vec<u8>>,
    /// Name associated with a classification.
    #[nom(
        Cond = "field.field_type == DataFieldType::APPLICATIONNAME",
        Map = "|i| String::from_utf8_lossy(i).to_string()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    /// The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification.
    #[nom(Cond = "field.field_type == DataFieldType::PostipDiffServCodePoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_ip_diff_serv_code_point: Option<u8>,
    /// Multicast replication factor.
    #[nom(Cond = "field.field_type == DataFieldType::ReplicationFactor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replication_factor: Option<u32>,
    /// Layer 2 packet section offset. Potentially a generic offset.
    #[nom(
        Cond = "field.field_type == DataFieldType::Layer2packetSectionOffset",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer2_packet_section_offset: Option<Vec<u8>>,
    /// Layer 2 packet section size. Potentially a generic size.
    #[nom(
        Cond = "field.field_type == DataFieldType::Layer2packetSectionSize",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer2_packet_section_size: Option<Vec<u8>>,
    /// Layer 2 packet section data.
    #[nom(
        Cond = "field.field_type == DataFieldType::Layer2packetSectionData",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer2_packet_section_data: Option<Vec<u8>>,
    /// Unknown/Vendor Specific
    #[nom(
        Cond = "field.field_type == DataFieldType::Unknown",
        Value(field.field_type_number),
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_field_type_number: Option<u16>,
    #[nom(
        Map = "|i: Option<&[u8]>| match i {
        Some(n) => Some(n.to_vec()),
        None => None,
    }",
        Cond = "field.field_type == DataFieldType::Unknown",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown: Option<Vec<u8>>,
}

fn parse_data_fields(
    i: &[u8],
    flow_set_id: u16,
    templates: HashMap<u16, Template>,
) -> IResult<&[u8], Vec<DataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        error!("Could not fetch any v9 templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.fields.iter() {
        let (i, v9_data_field) = DataField::parse(remaining, field.clone())?;
        remaining = i;
        fields.push(v9_data_field)
    }
    Ok((remaining, fields))
}

fn parse_options_data_fields(
    i: &[u8],
    flow_set_id: u16,
    templates: HashMap<u16, OptionsTemplate>,
) -> IResult<&[u8], Vec<OptionDataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        error!("Could not fetch any v9 options templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.option_fields.iter() {
        let (i, v9_data_field) = OptionDataField::parse(remaining, field.clone())?;
        remaining = i;
        fields.push(v9_data_field)
    }
    Ok((remaining, fields))
}

fn parse_scope_data_fields(
    i: &[u8],
    flow_set_id: u16,
    templates: HashMap<u16, OptionsTemplate>,
) -> IResult<&[u8], Vec<ScopeDataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        error!("Could not fetch any v9 options templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.scope_fields.iter() {
        let (i, v9_data_field) = ScopeDataField::parse(remaining, field.clone())?;
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
