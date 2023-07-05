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
pub struct V9 {
    /// V9 Header
    #[nom(Parse = "{ parse_v9_header }")]
    pub header: V9Header,
}

impl NetflowByteParser for V9 {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let parsed_packet = V9::parse_be(packet).map_err(|e| format!("{e}"))?;
        Ok(ParsedNetflow {
            remaining_bytes: parsed_packet.0,
            netflow_packet: NetflowPacket::V9(parsed_packet.1),
        })
    }
}

/// Custom V9 Header Parser to set unix_time as a SystemTime from parsed unix_secs fields.
fn parse_v9_header(i: &[u8]) -> IResult<&[u8], V9Header> {
    match V9Header::parse(i) {
        Ok((i, mut v9_header)) => {
            v9_header.unix_time = Some(build_unix_time(v9_header.unix_secs, 0));
            Ok((i, v9_header))
        }
        Err(e) => Err(e),
    }
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
    #[nom(Ignore)]
    pub unix_time: Option<SystemTime>,
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
