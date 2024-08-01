use nom_derive::{Nom, Parse};

use crate::static_versions::{v5::V5, v7::V7};
use crate::variable_versions::ipfix::IPFix;
use crate::variable_versions::v9::V9;
use crate::{NetflowPacket, NetflowParser};

use serde::Serialize;

/// Struct is used simply to match how to handle the result of the packet
#[derive(Nom)]
pub struct NetflowHeader {
    /// Netflow Version
    pub version: u16,
}

/// Enum of supported Netflow Versions
pub enum NetflowVersion<'a> {
    V5(&'a [u8]),
    V7(&'a [u8]),
    V9(&'a [u8]),
    IPFix(&'a [u8]),
    Unknown(Vec<u8>),
}

/// Implementing From for NetflowVersion
impl<'a> From<&'a [u8]> for NetflowVersion<'a> {
    fn from(packet: &[u8]) -> NetflowVersion {
        match NetflowHeader::parse_be(packet) {
            Ok((i, header)) if header.version == 5 => NetflowVersion::V5(i),
            Ok((i, header)) if header.version == 7 => NetflowVersion::V7(i),
            Ok((i, header)) if header.version == 9 => NetflowVersion::V9(i),
            Ok((i, header)) if header.version == 10 => NetflowVersion::IPFix(i),
            _ => NetflowVersion::Unknown(packet.to_vec()),
        }
    }
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
    UnknownVersion(Vec<u8>),
}

impl NetflowParser {
    /// Parses a Netflow by version packet and returns a Parsed Netflow.
    pub fn parse<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, NetflowParseError> {
        match NetflowVersion::from(packet) {
            NetflowVersion::V5(v5_packet) => V5::parse(v5_packet)
                .map(|(remaining, v5)| ParsedNetflow::new(remaining, NetflowPacket::V5(v5)))
                .map_err(|e| NetflowParseError::V5(e.to_string())),
            NetflowVersion::V7(v7_packet) => V7::parse(v7_packet)
                .map(|(remaining, v7)| ParsedNetflow::new(remaining, NetflowPacket::V7(v7)))
                .map_err(|e| NetflowParseError::V7(e.to_string())),
            NetflowVersion::V9(v9_packet) => V9::parse(v9_packet, &mut self.v9_parser)
                .map(|(remaining, v9)| ParsedNetflow::new(remaining, NetflowPacket::V9(v9)))
                .map_err(|e| NetflowParseError::V9(e.to_string())),
            NetflowVersion::IPFix(ipfix_packet) => {
                IPFix::parse(ipfix_packet, &mut self.ipfix_parser)
                    .map(|(remaining, ipfix)| {
                        ParsedNetflow::new(remaining, NetflowPacket::IPFix(ipfix))
                    })
                    .map_err(|e| NetflowParseError::IPFix(e.to_string()))
            }
            NetflowVersion::Unknown(e) => Err(NetflowParseError::UnknownVersion(e)),
        }
    }
}
