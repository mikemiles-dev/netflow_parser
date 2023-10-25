//! # Netflow V7
//!
//! References:
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use crate::protocol::ProtocolTypes;
use crate::{NetflowByteParserStatic, NetflowPacketResult, ParsedNetflow};

use nom::number::complete::be_u32;
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Nom, Clone, Serialize)]
pub struct V7 {
    /// V7 Header
    pub header: Header,
    /// V7 Body
    pub body: Body,
}

impl NetflowByteParserStatic for V7 {
    #[inline]
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let parsed_packet = V7::parse_be(packet).map_err(|e| format!("{e}"))?;
        Ok(ParsedNetflow {
            remaining: parsed_packet.0.to_vec(),
            netflow_packet: NetflowPacketResult::V7(parsed_packet.1),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom, Serialize)]
pub struct Header {
    /// NetFlow export format version number
    pub version: u16,
    /// Number of flows exported in this flow frame (protocol data unit, or PDU)
    pub count: u16,
    /// Current time in milliseconds since the export device booted
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    pub sys_up_time: Duration,
    /// Current seconds since 0000 UTC 1970
    #[nom(Map = "|i| Duration::from_secs(i.into())", Parse = "be_u32")]
    pub unix_secs: Duration,
    /// Residual nanoseconds since 0000 UTC 1970
    #[nom(Map = "|i| Duration::from_nanos(i.into())", Parse = "be_u32")]
    pub unix_nsecs: Duration,
    /// Sequence counter of total flows seen
    pub flow_sequence: u32,
    /// Unused (zero) bytes
    pub reserved: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Nom, Serialize)]
pub struct Body {
    /// Source IP address; in case of destination-only flows, set to zero.
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub src_addr: Ipv4Addr,
    /// Destination IP address.
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub dst_addr: Ipv4Addr,
    /// Next hop router; always set to zero.
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub next_hop: Ipv4Addr,
    /// SNMP index of input interface; always set to zero.
    pub input: u16,
    /// SNMP index of output interface.
    pub output: u16,
    /// Packets in the flow.
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow.
    pub d_octets: u32,
    /// SysUptime, in milliseconds, at start of flow.
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    pub first: Duration,
    /// SysUptime, in milliseconds, at the time the last packet of the flow was received.
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    pub last: Duration,
    /// TCP/UDP source port number; set to zero if flow mask is destination-only or source-destination.
    pub src_port: u16,
    /// TCP/UDP destination port number; set to zero if flow mask is destination-only or source-destination.
    pub dst_port: u16,
    /// Flags indicating, among other things, what flow fields are invalid.
    pub flags_fields_valid: u8,
    /// TCP flags; always set to zero.
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17); set to zero if flow mask is destination-only or source-destination.
    pub protocol_number: u8,
    #[nom(Value(ProtocolTypes::from(protocol_number)))]
    pub protocol_type: ProtocolTypes,
    /// IP type of service; switch sets it to the ToS of the first packet of the flow.
    pub tos: u8,
    /// Source autonomous system number, either origin or peer; always set to zero.
    pub src_as: u16,
    /// Destination autonomous system number, either origin or peer; always set to zero.
    pub dst_as: u16,
    /// Source address prefix mask; always set to zero.
    pub src_mask: u8,
    /// Destination address prefix mask; always set to zero.
    pub dst_mask: u8,
    /// Flags indicating, among other things, what flows are invalid.
    pub flags_fields_invalid: u16,
    /// IP address of the router that is bypassed by the Catalyst 5000 series switch. This is the same address the router uses when it sends NetFlow export packets. This IP address is propagated to all switches bypassing the router through the FCP protocol.
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub router_src: Ipv4Addr,
}
