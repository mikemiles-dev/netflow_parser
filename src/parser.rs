use nom_derive::{Nom, Parse};

use crate::static_versions::v5;
use crate::static_versions::v7;
use crate::variable_versions::ipfix;
use crate::variable_versions::v9;
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
    pub fn new(remaining: &[u8], result: NetflowPacket) -> Self {
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
            5 => v5::parse_as_netflow(packet),
            7 => v7::parse_as_netflow(packet),
            9 => v9::parse_as_netflow(packet, &mut self.v9_parser),
            10 => ipfix::parse_as_netflow(packet, &mut self.ipfix_parser),
            _ => Err(NetflowParseError::UnknownVersion(packet.to_vec())),
        }
    }
}
