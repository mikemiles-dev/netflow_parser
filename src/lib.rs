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

pub enum NetflowParser {
    V5(V5),
}

#[derive(Nom)]
pub struct NetflowMessage {
    version: u16,
}

impl NetflowParser {
    pub fn try_from_bytes(packet: &[u8]) -> Result<NetflowParser, NetflowError> {
        let (packet, netflow_version) = match NetflowMessage::parse_be(packet) {
            Ok((packet, netflow_version)) => (packet, netflow_version),
            Err(_e) => return Err(NetflowError::NotSupported),
        };
        match netflow_version.version {
            5 => V5::try_from_bytes(packet),
            _ => Err(NetflowError::NotSupported),
        }
    }
}

pub trait ParseNetflow {
    fn try_from_bytes(packet: &[u8]) -> Result<NetflowParser, NetflowError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_parses_v5() {
        let packet = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let _v5 = V5::try_from_bytes(&packet).unwrap();
    }
}
