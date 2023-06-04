use crate::{NetflowByteParser, ParsedNetflow};

use nom::number::complete::be_u32;
use nom_derive::*;
use std::net::Ipv4Addr;
use Nom;

#[derive(Debug, Nom, Clone)]
pub struct V5 {
    #[nom(Parse = "{ V5Header::parse }")]
    pub header: V5Header,
    #[nom(Parse = "{ V5Body::parse }")]
    pub body: V5Body,
}

impl NetflowByteParser for V5 {
    fn parse_bytes(packet: &[u8]) -> (Option<&[u8]>, ParsedNetflow) {
        match V5::parse_be(packet) {
            Ok((remaining, v5)) => (Some(remaining), ParsedNetflow::V5(v5)),
            Err(error) => (None, ParsedNetflow::ParseError(error.to_string())),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom)]
pub struct V5Header {
    pub version: u8,
    pub count: u8,
    pub sys_up_time: u16,
    pub unix_secs: u16,
    pub unix_nsecs: u16,
    pub flow_sequence: u16,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u8,
}

#[derive(Debug, PartialEq, Eq, Clone, Nom)]
pub struct V5Body {
    #[nom(Map = "|i| Ipv4Addr::from(i)", Parse = "be_u32")]
    pub src_addr: Ipv4Addr,
    #[nom(Map = "|i| Ipv4Addr::from(i)", Parse = "be_u32")]
    pub dst_addr: Ipv4Addr,
    #[nom(Map = "|i| Ipv4Addr::from(i)", Parse = "be_u32")]
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
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}
