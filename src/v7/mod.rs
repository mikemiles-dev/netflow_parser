use crate::proto::Protocol;
use crate::{NetflowByteParser, NetflowPacket, ParsedNetflow};

use nom::number::complete::be_u32;
use nom_derive::*;
use std::net::Ipv4Addr;
use Nom;

#[derive(Debug, Nom, Clone)]
pub struct V7 {
    #[nom(Parse = "{ V7Header::parse }")]
    pub header: V7Header,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom)]
pub struct V7Header {
    pub version: u16,
    pub count: u16,
    pub sys_up_time: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub reserved: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Nom)]
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
    pub pad1: u8,
    pub tcp_flags: u8,
    #[nom(Parse = "{ Protocol::parse }")]
    pub protocol: Protocol,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}
