pub mod v5;
use v5::V5;

use nom_derive::nom::error::Error as NomError;
use nom_derive::nom::Err as NomErr;
use nom_derive::{Nom, Parse};

#[derive(Debug)]
pub enum NetflowError<'a> {
    ByteParseError(NomErr<NomError<&'a [u8]>>),
    NotSupported,
    UnknownError,
}

#[derive(Debug, Clone)]
pub enum NetflowParser {
    V5(V5),
}

#[derive(Nom)]
pub struct NetflowMessage {
    version: u8,
}

impl NetflowParser {
    pub fn try_from_bytes(packet: &[u8]) -> Vec<Result<NetflowParser, NetflowError>> {
        let mut processed_packet = <&[u8]>::clone(&packet);
        let mut netflow_results = vec![];
        while !processed_packet.is_empty() {
            let netflow_result = match NetflowMessage::parse_be(processed_packet) {
                Ok((_, netflow_version)) => match netflow_version.version {
                    5 => match V5::parse_be(processed_packet) {
                        Ok((remaining, v5)) => {
                            processed_packet = remaining;
                            Ok(NetflowParser::V5(v5))
                        }
                        Err(e) => Err(NetflowError::ByteParseError(e)),
                    },
                    _ => {
                        // Unsupported protocted
                        return netflow_results;
                    }
                },
                Err(_e) => {
                    // Unsupported protocted
                    return netflow_results;
                }
            };
            netflow_results.push(netflow_result);
        }
        netflow_results
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_parses_v5() {
        let packet = [5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 10];
        match NetflowParser::try_from_bytes(&packet).first() {
            Some(item) => match item {
                Ok(NetflowParser::V5(v5)) => assert_eq!(v5.header.version, 5),
                Err(e) => panic!("{:?}", e),
            },
            None => panic!("Did not parse v5"),
        }
    }
}
