use crate::{NetflowError, NetflowParser, ParseNetflow};

use nom_derive::*;
use Nom;

impl ParseNetflow for V5 {
    fn try_from_bytes(packet: &[u8]) -> Result<NetflowParser, NetflowError> {
        match V5::parse(packet) {
            Ok(v5) => Ok(NetflowParser::V5(v5.1)),
            Err(nom_error) => Err(NetflowError::ByteParseError(nom_error)),
        }
    }
}

#[derive(Nom)]
pub struct V5 {
    #[nom(Parse = "{ V5Header::parse }")]
    pub header: V5Header,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom)]
pub struct V5Header {
    pub version: u16,
    pub count: u16,
    pub sys_up_time: u32,
    pub unix_secs: u16,
    pub unix_nsecs: u16,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}

pub struct V5Body {}
