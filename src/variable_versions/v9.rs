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

/// Custom V9 Header Parser to set unix_time as a SystemTime from parsed unix_secs and unix_nsecs fields.
fn parse_v9_header(i: &[u8]) -> IResult<&[u8], V9Header> {
    match V9Header::parse(i) {
        Ok((i, mut v9_header)) => {
            // v9_header.unix_time =
            //     Some(build_unix_time(v9_header.unix_secs, v9_header.unix_nsecs));
            Ok((i, v9_header))
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct V9Header {
    /// NetFlow export format version number
    pub version: u16,
}
