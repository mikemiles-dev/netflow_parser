use crate::protocol::ProtocolTypes;

use nom::error::{Error as NomError, ErrorKind};
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Parse bytes into DataNumber Type
pub fn parse_data_number(
    i: &[u8],
    field_length: u16,
    signed: bool,
) -> IResult<&[u8], DataNumber> {
    match field_length {
        1 if !signed => Ok(u8::parse(i)?).map(|(i, j)| (i, DataNumber::U8(j))),
        2 if !signed => Ok(u16::parse(i)?).map(|(i, j)| (i, DataNumber::U16(j))),
        4 if signed => Ok(i32::parse(i)?).map(|(i, j)| (i, DataNumber::I32(j))),
        4 if !signed => Ok(u32::parse(i)?).map(|(i, j)| (i, DataNumber::U32(j))),
        8 if !signed => Ok(u64::parse(i)?).map(|(i, j)| (i, DataNumber::U64(j))),
        16 if !signed => Ok(u128::parse(i)?).map(|(i, j)| (i, DataNumber::U128(j))),
        _ => Err(NomErr::Error(NomError::new(i, ErrorKind::Fail))),
    }
}

/// Holds our datatypes and values post parsing
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize)]
#[serde(untagged)]
pub enum DataNumber {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I32(i32),
}

/// Convert into usize, mainly for serialization purposes
impl DataNumber {
    pub fn get_value(self) -> usize {
        let result: usize = self.into();
        result
    }
}
/// Convert into usize, mainly for serialization purposes
impl From<DataNumber> for usize {
    fn from(val: DataNumber) -> Self {
        match val {
            DataNumber::U8(i) => i as usize,
            DataNumber::U32(i) => i as usize,
            DataNumber::I32(i) => i as usize,
            DataNumber::U16(i) => i as usize,
            DataNumber::U64(i) => i as usize,
            DataNumber::U128(i) => i as usize,
        }
    }
}

/// Holds the post parsed field with its relvant datatype
#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize)]
pub enum FieldValue {
    String(String),
    DataNumber(DataNumber),
    Float64(f64),
    Duration(Duration),
    Ip4Addr(Ipv4Addr),
    Ip6Addr(Ipv6Addr),
    Vec(Vec<u8>),
    ProtocolType(ProtocolTypes),
    Unknown,
}

/// Helps the parser indefiy the data type to parse the field as
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum FieldDataType {
    String,
    SignedDataNumber,
    UnsignedDataNumber,
    Float64,
    DurationSeconds,
    DurationMillis,
    DurationMicros,
    DurationNanos,
    Ip4Addr,
    Ip6Addr,
    Vec,
    ProtocolType,
    Unknown,
}
