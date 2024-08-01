use nom_derive::{Nom, Parse};

use crate::static_versions::{v5::V5, v7::V7};
use crate::variable_versions::ipfix::IPFix;
use crate::variable_versions::v9::V9;
use crate::{NetflowPacket, NetflowParser};

use serde::Serialize;

#[derive(Nom)]
/// Generic Netflow Header for shared versions
pub struct GenericNetflowHeader {
    pub version: u16,
}

#[derive(Debug, Clone)]
pub struct ParsedNetflow {
    pub remaining: Vec<u8>,
    /// Parsed Netflow Packet
    pub result: NetflowPacket,
}

impl ParsedNetflow {
    fn new(remaining: &[u8], result: NetflowPacket) -> Self {
        Self {
            remaining: remaining.to_vec(),
            result,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum NetflowParseError {
    V5(String),
    V7(String),
    V9(String),
    IPFix(String),
    Incomplete(String),
    UnknownVersion(Vec<u8>),
}

impl NetflowParser {
    /// Parses a Netflow by version packet and returns a Parsed Netflow.
    pub fn parse<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, NetflowParseError> {
        let (packet, version) = GenericNetflowHeader::parse(packet)
            .map(|(remaining, header)| (remaining, header.version))
            .map_err(|e| NetflowParseError::Incomplete(e.to_string()))?;

        match version {
            5 => V5::parse(packet)
                .map(|(remaining, v5)| ParsedNetflow::new(remaining, NetflowPacket::V5(v5)))
                .map_err(|e| NetflowParseError::V5(e.to_string())),
            7 => V7::parse(packet)
                .map(|(remaining, v7)| ParsedNetflow::new(remaining, NetflowPacket::V7(v7)))
                .map_err(|e| NetflowParseError::V7(e.to_string())),
            9 => V9::parse(packet, &mut self.v9_parser)
                .map(|(remaining, v9)| ParsedNetflow::new(remaining, NetflowPacket::V9(v9)))
                .map_err(|e| NetflowParseError::V9(e.to_string())),
            10 => IPFix::parse(packet, &mut self.ipfix_parser)
                .map(|(remaining, ipfix)| {
                    ParsedNetflow::new(remaining, NetflowPacket::IPFix(ipfix))
                })
                .map_err(|e| NetflowParseError::IPFix(e.to_string())),
            _ => Err(NetflowParseError::UnknownVersion(packet.to_vec())),
        }
    }
}
