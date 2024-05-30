//! # Netflow V5
//!
//! References:
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use crate::protocol::ProtocolTypes;

use nom::number::complete::be_u32;
#[cfg(feature = "unix_timestamp")]
use nom::number::complete::be_u64;
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Nom, Debug, Clone, Serialize)]
pub struct V5 {
    /// V5 Header
    pub header: Header,
    /// V5 Sets
    #[nom(Count = "header.count")]
    pub sets: Vec<FlowSet>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// NetFlow export format version number
    #[nom(Value = "5")]
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
pub struct FlowSet {
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

impl V5 {
    /// Convert the V5 struct to a Vec<u8> of bytes in big-endian order for exporting
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let header_version = self.header.version.to_be_bytes();
        let header_count = self.header.count.to_be_bytes();
        let header_sys_up_time = (self.header.sys_up_time.as_millis() as u32).to_be_bytes();
        #[cfg(feature = "unix_timestamp")]
        let header_unix_timestamp = self.header.unix_time.as_millis().to_be_bytes();
        #[cfg(not(feature = "unix_timestamp"))]
        let mut header_unix_timestamp = self.header.unix_secs.to_be_bytes().to_vec();
        #[cfg(not(feature = "unix_timestamp"))]
        let header_unix_nsecs = self.header.unix_nsecs.to_be_bytes().to_vec();
        #[cfg(not(feature = "unix_timestamp"))]
        header_unix_timestamp.extend_from_slice(&header_unix_nsecs);
        let header_flow_seq = self.header.flow_sequence.to_be_bytes();
        let header_engine_type = self.header.engine_type.to_be_bytes();
        let header_engine_id = self.header.engine_id.to_be_bytes();
        let header_sampling_interval = self.header.sampling_interval.to_be_bytes();

        let mut result = vec![];

        result.extend_from_slice(&header_version);
        result.extend_from_slice(&header_count);
        result.extend_from_slice(&header_sys_up_time);
        result.extend_from_slice(&header_unix_timestamp);
        result.extend_from_slice(&header_flow_seq);
        result.extend_from_slice(&header_engine_type);
        result.extend_from_slice(&header_engine_id);
        result.extend_from_slice(&header_sampling_interval);

        let mut flows = vec![];

        for set in &self.sets {
            let src_addr = set.src_addr.octets();
            let dst_addr = set.dst_addr.octets();
            let next_hop = set.next_hop.octets();
            let input = set.input.to_be_bytes();
            let output = set.output.to_be_bytes();
            let d_pkts = set.d_pkts.to_be_bytes();
            let d_octets = set.d_octets.to_be_bytes();
            let first = (set.first.as_millis() as u32).to_be_bytes();
            let last = (set.last.as_millis() as u32).to_be_bytes();
            let src_port = set.src_port.to_be_bytes();
            let dst_ports = set.dst_port.to_be_bytes();
            let pad1 = set.pad1.to_be_bytes();
            let tcp_flags = set.tcp_flags.to_be_bytes();
            let proto = set.protocol_number.to_be_bytes();
            let tos = set.tos.to_be_bytes();
            let src_as = set.src_as.to_be_bytes();
            let dst_as = set.dst_as.to_be_bytes();
            let src_mask = set.src_mask.to_be_bytes();
            let dst_mask = set.dst_mask.to_be_bytes();
            let pad2 = set.pad2.to_be_bytes();

            flows.extend_from_slice(&src_addr);
            flows.extend_from_slice(&dst_addr);
            flows.extend_from_slice(&next_hop);
            flows.extend_from_slice(&input);
            flows.extend_from_slice(&output);
            flows.extend_from_slice(&d_pkts);
            flows.extend_from_slice(&d_octets);
            flows.extend_from_slice(&first);
            flows.extend_from_slice(&last);
            flows.extend_from_slice(&src_port);
            flows.extend_from_slice(&dst_ports);
            flows.extend_from_slice(&pad1);
            flows.extend_from_slice(&tcp_flags);
            flows.extend_from_slice(&proto);
            flows.extend_from_slice(&tos);
            flows.extend_from_slice(&src_as);
            flows.extend_from_slice(&dst_as);
            flows.extend_from_slice(&src_mask);
            flows.extend_from_slice(&dst_mask);
            flows.extend_from_slice(&pad2);
        }

        result.extend_from_slice(&flows);

        result
    }
}
