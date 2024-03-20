use nom::number::complete::be_u16;
use nom::IResult;
use nom_derive::{Nom, Parse};

/// Struct is used simply to match how to handle the result of the packet
#[derive(Nom)]
pub struct NetflowHeader {
    /// Netflow Version
    #[nom(Map = "NetflowVersion::from", Parse = "be_u16")]
    pub version: NetflowVersion,
}

impl NetflowHeader {
    pub fn parse_header(packet: &[u8]) -> IResult<&[u8], NetflowHeader> {
        NetflowHeader::parse_be(packet)
    }
}

#[derive(PartialEq)]
pub enum NetflowVersion {
    V5,
    V7,
    V9,
    IPFix,
    Unsupported,
}

impl NetflowVersion {
    pub fn is_v5(&self) -> bool {
        *self == NetflowVersion::V5
    }
    pub fn is_v7(&self) -> bool {
        *self == NetflowVersion::V7
    }
    pub fn is_v9(&self) -> bool {
        *self == NetflowVersion::V9
    }
    pub fn is_ipfix(&self) -> bool {
        *self == NetflowVersion::IPFix
    }
}

impl From<u16> for NetflowVersion {
    fn from(version: u16) -> Self {
        match version {
            5 => NetflowVersion::V5,
            7 => NetflowVersion::V7,
            9 => NetflowVersion::V9,
            10 => NetflowVersion::IPFix,
            _ => NetflowVersion::Unsupported,
        }
    }
}
