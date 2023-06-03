pub mod v5;
use v5::V5;

use nom_derive::{Nom, Parse};

#[derive(Debug, Clone)]
pub enum NetflowParser {
    V5(V5),
}

#[derive(Nom)]
pub struct NetflowMessage {
    version: u8,
}

impl NetflowParser {
    /// Takes a Netflow packet slice and returns a vector of Reuslts of type NetflowParser.
    /// If we reach some parse error we return what items be have.
    pub fn parse_bytes(packet: &[u8]) -> Vec<NetflowParser> {
        let mut processed_packet = <&[u8]>::clone(&packet);
        let mut netflow_results = vec![];
        while !processed_packet.is_empty() {
            let netflow_result = match NetflowMessage::parse_be(processed_packet) {
                Ok((_, netflow_version)) => match netflow_version.version {
                    5 => match V5::parse_be(processed_packet) {
                        Ok((remaining, v5)) => {
                            processed_packet = remaining;
                            NetflowParser::V5(v5)
                        }
                        Err(_e) => {
                            // Parse Error
                            return netflow_results;
                        }
                    },
                    _ => {
                        // Unsupported protocol
                        return netflow_results;
                    }
                },
                Err(_e) => {
                    // Unsupported protocol
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
        match NetflowParser::parse_bytes(&packet).first() {
            Some(NetflowParser::V5(v5)) => assert_eq!(v5.header.version, 5),
            None => panic!("V5 Parse Error!"),
        }
    }
}
