//! # IPFix
//!
//! References:
//! - https://datatracker.ietf.org/doc/html/rfc7011
//! - https://en.wikipedia.org/wiki/IP_Flow_Information_Export

use crate::{NetflowByteParserVariable, NetflowPacket, ParsedNetflow};
use nom_derive::*;
use serde::Serialize;
use Nom;

#[derive(Default, Debug)]
pub struct IPFixParser {}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(_parser: &mut IPFixParser))]
pub struct IPFix {
    /// IPFix Header
    pub header: Header,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    observation_domain_id: u32,
}

impl NetflowByteParserVariable for IPFixParser {
    /// Main IPFix Parse function.
    fn parse_bytes<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let (remaining, v10_parsed) =
            IPFix::parse(packet, self).map_err(|_| "Could not parse v10_packet".to_string())?;

        Ok(ParsedNetflow {
            remaining: remaining.to_vec(),
            netflow_packet: NetflowPacket::IPFix(v10_parsed),
        })
    }
}
