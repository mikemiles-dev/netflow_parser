use crate::{NetflowError, NetflowParser};

use nom_derive::*;
use Nom;

impl NetflowParser for V5 {
    fn try_from_bytes(packet: &[u8]) -> Result<V5, NetflowError> {
        match V5::parse_be(packet) {
            Ok(v5) => Ok(v5.1),
            Err(nom_error) => Err(NetflowError::ByteParseError(nom_error)),
        }
    }
}

#[derive(Nom)]
pub struct V5 {
    header: V5Header,
}

#[derive(Nom)]
pub struct V5Header {
    version: u8,
}

pub struct V5Body {}
