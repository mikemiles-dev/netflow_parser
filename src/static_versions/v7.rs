//! # Netflow V7
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

#[derive(Debug, Nom, Clone, Serialize)]
pub struct V7 {
    /// V7 Header
    pub header: Header,
    /// V7 Sets
    #[nom(Count = "header.count")]
    pub sets: Vec<FlowSet>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom, Serialize)]
pub struct Header {
    /// NetFlow export format version number
    #[nom(Value = "7")]
    pub version: u16,
    /// Number of flows exported in this flow frame (protocol data unit, or PDU)
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
    /// Unused (zero) bytes
    pub reserved: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Nom, Serialize)]
pub struct FlowSet {
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

impl V7 {
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
        let reserved = self.header.reserved.to_be_bytes();

        let mut result = vec![];

        result.extend_from_slice(&header_version);
        result.extend_from_slice(&header_count);
        result.extend_from_slice(&header_sys_up_time);
        result.extend_from_slice(&header_unix_timestamp);
        result.extend_from_slice(&header_flow_seq);
        result.extend_from_slice(&reserved);

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
            let flag_field_valid = set.flags_fields_valid.to_be_bytes();
            let tcp_flags = set.tcp_flags.to_be_bytes();
            let proto = set.protocol_number.to_be_bytes();
            let tos = set.tos.to_be_bytes();
            let src_as = set.src_as.to_be_bytes();
            let dst_as = set.dst_as.to_be_bytes();
            let src_mask = set.src_mask.to_be_bytes();
            let dst_mask = set.dst_mask.to_be_bytes();
            let flag_field_invalid = set.flags_fields_invalid.to_be_bytes();
            let router_src = set.router_src.octets();

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
            flows.extend_from_slice(&flag_field_valid);
            flows.extend_from_slice(&tcp_flags);
            flows.extend_from_slice(&proto);
            flows.extend_from_slice(&tos);
            flows.extend_from_slice(&src_as);
            flows.extend_from_slice(&dst_as);
            flows.extend_from_slice(&src_mask);
            flows.extend_from_slice(&dst_mask);
            flows.extend_from_slice(&flag_field_invalid);
            flows.extend_from_slice(&router_src);
        }

        result.extend_from_slice(&flows);

        result
    }
}
