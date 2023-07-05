pub mod protocol;
pub mod static_versions;
mod time;

use log::*;
use serde::Serialize;
use static_versions::{v5::V5, v7::V7};

use nom_derive::{Nom, Parse};

#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacket {
    V5(V5),
    V7(V7),
}

#[derive(Debug, Clone)]
pub struct ParsedNetflow<'a> {
    remaining_bytes: &'a [u8],
    netflow_packet: NetflowPacket,
}

#[derive(Nom)]
pub struct NetflowHeader {
    version: u16,
}

pub enum NetflowVersion {
    V5,
    V7,
    V9,
    Unsupported,
}

impl NetflowHeader {
    fn get_version_from_bytes(packet: &[u8]) -> NetflowVersion {
        match NetflowHeader::parse_be(packet) {
            Ok((_, netflow_header)) if netflow_header.version == 5 => NetflowVersion::V5,
            Ok((_, netflow_header)) if netflow_header.version == 7 => NetflowVersion::V7,
            Ok((_, netflow_header)) if netflow_header.version == 9 => NetflowVersion::V9,
            _ => NetflowVersion::Unsupported,
        }
    }
}

pub trait NetflowByteParser {
    fn parse_bytes(packet: &[u8]) -> Result<ParsedNetflow, Box<dyn std::error::Error>>;
}

pub struct NetflowParser;

impl NetflowParser {
    /// Takes a Netflow packet slice and returns a vector of Parsed Netflows.
    /// If we reach some parse error we return what items be have.
    pub fn parse_bytes(packet: &[u8]) -> Vec<NetflowPacket> {
        let mut packet_to_be_processed = <&[u8]>::clone(&packet);
        let mut netflow_results = vec![];

        // If we have bytes to parse
        while !packet_to_be_processed.is_empty() {
            // Attempt to Parse Bytes
            let parsed_netflow = match NetflowHeader::get_version_from_bytes(packet_to_be_processed)
            {
                NetflowVersion::V5 => V5::parse_bytes(packet),
                NetflowVersion::V7 => V7::parse_bytes(packet),
                _ => Err("Unsupported Version!".to_string().into()),
            };
            // Handle Result of Parsed Bytes
            match parsed_netflow {
                Ok(parsed_netflow) => {
                    packet_to_be_processed = parsed_netflow.remaining_bytes;
                    netflow_results.push(parsed_netflow.netflow_packet);
                }
                Err(parsed_error) => {
                    warn!("{parsed_error}");
                    break;
                }
            }
        }
        netflow_results
    }
}

#[cfg(test)]
mod tests {

    use super::NetflowParser;
    use insta::assert_yaml_snapshot;

    #[test]
    fn it_parses_v5() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
            5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v7() {
        let packet = [
            0, 7, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
            5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::parse_bytes(&packet));
    }
}
