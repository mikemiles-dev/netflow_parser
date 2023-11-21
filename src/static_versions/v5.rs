//! # Netflow V5
//!
//! References:
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use crate::protocol::ProtocolTypes;
use crate::{NetflowByteParserStatic, NetflowPacketResult, ParsedNetflow};

use nom::number::complete::be_u32;
#[cfg(feature = "unix_timestamp")]
use nom::number::complete::be_u64;
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Nom, Clone, Serialize)]
pub struct V5 {
    /// V5 Header
    pub header: Header,
    /// V5 Body
    pub body: Body,
}

impl NetflowByteParserStatic for V5 {
    #[inline]
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let parsed_packet = V5::parse_be(packet).map_err(|e| format!("{e}"))?;
        Ok(ParsedNetflow {
            remaining: parsed_packet.0.to_vec(),
            netflow_packet: NetflowPacketResult::V5(parsed_packet.1),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// NetFlow export format version number
    pub version: u16,
    /// Number of flows exported in this packet (1-30)
    pub count: u16,
    /// Current time in milliseconds since the export device booted
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    pub sys_up_time: Duration,

    /// Current count since 0000 UTC 1970
    #[cfg(feature = "unix_timestamp")]
    #[nom(
        Map = "|i| Duration::new((i >> 32) as u32 as u64, (i as u32))",
        Parse = "be_u64"
    )]
    pub unix_time: Duration,

    /// Current count of seconds since 0000 UTC 1970
    #[cfg(not(feature = "unix_timestamp"))]
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970
    #[cfg(not(feature = "unix_timestamp"))]
    pub unix_nsecs: u32,

    /// Sequence counter of total flows seen
    pub flow_sequence: u32,
    /// Type of flow-switching engine
    pub engine_type: u8,
    /// Slot number of the flow-switching engine
    pub engine_id: u8,
    /// First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
    pub sampling_interval: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct Body {
    /// Source IP address
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub src_addr: Ipv4Addr,
    /// Destination IP address
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub dst_addr: Ipv4Addr,
    /// IP address of next hop router
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub next_hop: Ipv4Addr,
    /// SNMP index of input interface
    pub input: u16,
    /// SNMP index of output interface
    pub output: u16,
    /// Packets in the flow
    pub d_pkts: u32,
    /// Total number of Layer 3 bytes in the packets of the flow
    pub d_octets: u32,
    /// SysUptime at start of flow
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    pub first: Duration,
    #[nom(Map = "|i| Duration::from_millis(i.into())", Parse = "be_u32")]
    /// SysUptime at the time the last packet of the flow was received
    pub last: Duration,
    /// TCP/UDP source port number or equivalent
    pub src_port: u16,
    /// TCP/UDP destination port number or equivalent
    pub dst_port: u16,
    /// Unused (zero) bytes
    pub pad1: u8,
    /// Cumulative OR of TCP flags
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17)
    pub protocol_number: u8,
    #[nom(Value(ProtocolTypes::from(protocol_number)))]
    pub protocol_type: ProtocolTypes,
    /// IP type of service (ToS)
    pub tos: u8,
    /// Autonomous system number of the source, either origin or peer
    pub src_as: u16,
    /// Autonomous system number of the destination, either origin or pee
    pub dst_as: u16,
    /// Source address prefix mask bits
    pub src_mask: u8,
    /// Destination address prefix mask bits
    pub dst_mask: u8,
    /// Unused (zero) bytes
    pub pad2: u16,
}
