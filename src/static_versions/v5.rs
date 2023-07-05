use crate::protocol::ProtocolTypes;
use crate::time::build_unix_time;
use crate::{NetflowByteParser, NetflowPacket, ParsedNetflow};

use nom::number::complete::be_u32;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::SystemTime;
use Nom;

#[derive(Debug, Nom, Clone, Serialize)]
pub struct V5 {
    /// V5 Header
    #[nom(Parse = "{ parse_v5_header }")]
    pub header: V5Header,
    /// V5 Body
    #[nom(Parse = "{ V5Body::parse }")]
    pub body: V5Body,
}

impl NetflowByteParser for V5 {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let parsed_packet = V5::parse_be(packet).map_err(|e| format!("{e}"))?;
        Ok(ParsedNetflow {
            remaining_bytes: parsed_packet.0,
            netflow_packet: NetflowPacket::V5(parsed_packet.1),
        })
    }
}

/// Custom V5 Header Parser to set unix_time as a SystemTime from parsed unix_secs and unix_nsecs fields.
fn parse_v5_header(i: &[u8]) -> IResult<&[u8], V5Header> {
    match V5Header::parse(i) {
        Ok((i, mut v5_header)) => {
            v5_header.unix_time = Some(build_unix_time(v5_header.unix_secs, v5_header.unix_nsecs));
            Ok((i, v5_header))
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct V5Header {
    /// NetFlow export format version number
    pub version: u16,
    /// Number of flows exported in this packet (1-30)
    pub count: u16,
    /// Current time in milliseconds since the export device booted
    pub sys_up_time: u32,
    /// Current count of seconds since 0000 UTC 1970
    unix_secs: u32,
    /// Residual nanoseconds since 0000 UTC 1970
    unix_nsecs: u32,
    /// SystemTime build from unix_secs and unix_nsecs
    #[nom(Ignore)]
    pub unix_time: Option<SystemTime>,
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
pub struct V5Body {
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
    pub first: u32,
    /// SysUptime at the time the last packet of the flow was received
    pub last: u32,
    /// TCP/UDP source port number or equivalent
    pub src_port: u16,
    /// TCP/UDP destination port number or equivalent
    pub dst_port: u16,
    /// Unused (zero) bytes
    pub pad1: u8,
    /// Cumulative OR of TCP flags
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6; UDP = 17)
    #[nom(Parse = "{ ProtocolTypes::parse }")]
    pub protocol: ProtocolTypes,
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
