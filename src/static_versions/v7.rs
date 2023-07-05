use crate::proto::Protocol;
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
pub struct V7 {
    /// V7 Header
    #[nom(Parse = "{ parse_v7_header }")]
    pub header: V7Header,
    /// V7 Body
    #[nom(Parse = "{ V7Body::parse }")]
    pub body: V7Body,
}

impl NetflowByteParser for V7 {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let parsed_packet = V7::parse_be(packet).map_err(|e| format!("{e}"))?;
        Ok(ParsedNetflow {
            remaining_bytes: parsed_packet.0,
            netflow_packet: NetflowPacket::V7(parsed_packet.1),
        })
    }
}

/// Custom V7 Header Parser to set unix_time as a SystemTime from parsed unix_secs and unix_nsecs fields.
fn parse_v7_header(i: &[u8]) -> IResult<&[u8], V7Header> {
    match V7Header::parse(i) {
        Ok((i, mut v7_header)) => {
            v7_header.unix_time = Some(build_unix_time(v7_header.unix_secs, v7_header.unix_nsecs));
            Ok((i, v7_header))
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom, Serialize)]
pub struct V7Header {
    pub version: u16,
    pub count: u16,
    pub sys_up_time: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    /// SystemTime build from unix_secs and unix_nsecs
    #[nom(Ignore)]
    pub unix_time: Option<SystemTime>,
    pub flow_sequence: u32,
    pub reserved: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Nom, Serialize)]
pub struct V7Body {
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub src_addr: Ipv4Addr,
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub dst_addr: Ipv4Addr,
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub next_hop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32,
    pub last: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags_fields_valid: u8,
    pub tcp_flags: u8,
    #[nom(Parse = "{ Protocol::parse }")]
    pub protocol: Protocol,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub flags_fields_invalid: u16,
    #[nom(Map = "Ipv4Addr::from", Parse = "be_u32")]
    pub router_src: Ipv4Addr,
}
