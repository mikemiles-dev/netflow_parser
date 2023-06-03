pub mod v5;

use nom_derive::nom::error::Error as NomError;
use nom_derive::nom::Err as NomErr;

pub enum NetflowError<'a> {
    ByteParseError(NomErr<NomError<&'a [u8]>>),
}

pub trait NetflowParser {
    fn try_from_bytes(packet: &[u8]) -> Result<Self, NetflowError>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
