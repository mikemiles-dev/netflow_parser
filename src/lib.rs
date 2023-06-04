pub mod proto;
pub mod v5;
use log::*;
use v5::V5;

use nom_derive::{Nom, Parse};

#[derive(Debug, Clone)]
pub enum ParsedNetflow {
    V5(V5),
    ParseError(String),
}

#[derive(Nom)]
pub struct NetflowHeader {
    version: u8,
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
    fn parse_bytes(packet: &[u8]) -> (Option<&[u8]>, ParsedNetflow);
}

pub struct NetflowParser;

impl NetflowParser {
    /// Takes a Netflow packet slice and returns a vector of Parsed Netflows.
    /// If we reach some parse error we return what items be have.
    pub fn parse_bytes(packet: &[u8]) -> Vec<ParsedNetflow> {
        let mut packet_to_be_processed = <&[u8]>::clone(&packet);
        let mut netflow_results = vec![];

        // If we have bytes to parse
        while !packet_to_be_processed.is_empty() {
            let (remaining, parsed_result) =
                match NetflowHeader::get_version_from_bytes(packet_to_be_processed) {
                    NetflowVersion::V5 => V5::parse_bytes(packet),
                    _ => (
                        None,
                        ParsedNetflow::ParseError(
                            format!(
                                "Unsupported Version for packet: {:?}",
                                packet_to_be_processed
                            )
                            .to_string(),
                        ),
                    ),
                };
            if let Some(remaining) = remaining {
                packet_to_be_processed = remaining;
            }
            // Either output error or add result to result Vector.
            if let ParsedNetflow::ParseError(parsed_error) = parsed_result {
                warn!("{parsed_error}");
                break;
            } else {
                debug!("Parsed: {:?}", parsed_result);
                netflow_results.push(parsed_result)
            }
        }
        netflow_results
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proto::Protocol;

    #[test]
    fn it_parses_v5() {
        let packet = [
            5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
            6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4,
            5, 6, 7,
        ];
        match NetflowParser::parse_bytes(&packet).first() {
            Some(ParsedNetflow::V5(v5)) => {
                assert_eq!(v5.header.version, 5);
                assert_eq!(v5.body.protocol, Protocol::EGP);
            }
            _ => panic!("V5 Parse Error!"),
        }
    }
}
