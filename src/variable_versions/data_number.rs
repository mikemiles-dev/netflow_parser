use crate::protocol::ProtocolTypes;

use byteorder::{BigEndian, WriteBytesExt};
use nom::Err as NomErr;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom::number::complete::{be_i24, be_u24, be_u32, be_u128};
use nom_derive::*;
use serde::Serialize;

use std::convert::Into;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

macro_rules! impl_try_from {
    ($($t:ty => $v:ident),*; $($s:ty => $sv:ident),*) => {
        $(
            impl TryFrom<&DataNumber> for $t {
                type Error = DataNumberError;

                fn try_from(val: &DataNumber) -> Result<Self, Self::Error> {
                    match val {
                        DataNumber::$v(i) => Ok(*i),
                        _ => Err(DataNumberError::InvalidDataType),
                    }
                }
            }

            impl TryFrom<&FieldValue> for $t {
                type Error = FieldValueError;

                fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
                    match value {
                        FieldValue::DataNumber(d) => {
                            let d: $t = d.try_into().map_err(|_| FieldValueError::InvalidDataType)?;
                            Ok(d)
                        }
                        _ => Err(FieldValueError::InvalidDataType),
                    }
                }
            }
        )*


    };
}

/// Holds our datatypes and values post parsing
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize)]
#[serde(untagged)]
pub enum DataNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    I24(i32),
    U32(u32),
    U64(u64),
    U128(u128),
    I32(i32),
}

#[derive(Debug)]
pub enum DataNumberError {
    InvalidDataType,
}

impl_try_from!(
    u8 => U8,
    u16 => U16,
    u32 => U32,
    i32 => I32,
    u64 => U64,
    u128 => U128;
);

impl TryFrom<&FieldValue> for String {
    type Error = FieldValueError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::String(s) => Ok(s.clone()),
            FieldValue::MacAddr(s) => Ok(s.to_string()),
            _ => Err(FieldValueError::InvalidDataType),
        }
    }
}

impl TryFrom<&FieldValue> for IpAddr {
    type Error = FieldValueError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::Ip4Addr(ip) => Ok(IpAddr::V4(*ip)),
            FieldValue::Ip6Addr(ip) => Ok(IpAddr::V6(*ip)),
            _ => Err(FieldValueError::InvalidDataType),
        }
    }
}

#[cfg(feature = "parse_unknown_fields")]
fn parse_unknown_fields(remaining: &[u8], field_length: u16) -> IResult<&[u8], FieldValue> {
    let (i, taken) = take(field_length)(remaining)?;
    Ok((i, FieldValue::Vec(taken.to_vec())))
}

#[cfg(not(feature = "parse_unknown_fields"))]
fn parse_unknown_fields(
    remaining: &[u8],
    field_type: FieldDataType,
    field_length: u16,
) -> IResult<&[u8], FieldValue> {
    Err(NomErr::Error(NomError::new(remaining, ErrorKind::Fail)))
}

/// Convert into usize, mainly for serialization purposes
impl DataNumber {
    /// Parse bytes into DataNumber Type
    pub fn parse(i: &[u8], field_length: u16, signed: bool) -> IResult<&[u8], DataNumber> {
        match (field_length, signed) {
            (1, false) => Ok(u8::parse(i)?).map(|(i, j)| (i, Self::U8(j))),
            (2, false) => Ok(u16::parse(i)?).map(|(i, j)| (i, Self::U16(j))),
            (3, false) => Ok(be_u24(i).map(|(i, j)| (i, Self::U24(j)))?),
            (3, true) => Ok(be_i24(i).map(|(i, j)| (i, Self::I24(j)))?),
            (4, true) => Ok(i32::parse(i)?).map(|(i, j)| (i, Self::I32(j))),
            (4, false) => Ok(u32::parse(i)?).map(|(i, j)| (i, Self::U32(j))),
            (8, false) => Ok(u64::parse(i)?).map(|(i, j)| (i, Self::U64(j))),
            (16, false) => Ok(u128::parse(i)?).map(|(i, j)| (i, Self::U128(j))),
            _ => Err(NomErr::Error(NomError::new(i, ErrorKind::Fail))),
        }
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        match self {
            DataNumber::U8(n) => n.to_be_bytes().to_vec(),
            DataNumber::U16(n) => n.to_be_bytes().to_vec(),
            DataNumber::U24(n) => {
                let mut wtr = Vec::new();
                wtr.write_u24::<BigEndian>(*n).unwrap();
                wtr
            }
            DataNumber::I24(n) => {
                let mut wtr = Vec::new();
                wtr.write_i24::<BigEndian>(*n).unwrap();
                wtr
            }
            DataNumber::U32(n) => n.to_be_bytes().to_vec(),
            DataNumber::U64(n) => n.to_be_bytes().to_vec(),
            DataNumber::U128(n) => n.to_be_bytes().to_vec(),
            DataNumber::I32(n) => n.to_be_bytes().to_vec(),
        }
    }
}

/// Convert into usize, mainly for serialization purposes
impl From<DataNumber> for usize {
    fn from(val: DataNumber) -> Self {
        match val {
            DataNumber::U8(i) => i as usize,
            DataNumber::I24(i) => i as usize,
            DataNumber::U24(i) => i as usize,
            DataNumber::U32(i) => i as usize,
            DataNumber::I32(i) => i as usize,
            DataNumber::U16(i) => i as usize,
            DataNumber::U64(i) => i as usize,
            DataNumber::U128(i) => i as usize,
        }
    }
}

/// Holds the post parsed field with its relevant datatype
#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize)]
pub enum FieldValue {
    String(String),
    DataNumber(DataNumber),
    Float64(f64),
    Duration(Duration),
    Ip4Addr(Ipv4Addr),
    Ip6Addr(Ipv6Addr),
    MacAddr(String),
    Vec(Vec<u8>),
    ProtocolType(ProtocolTypes),
    Unknown,
}

#[derive(Debug)]
pub enum FieldValueError {
    InvalidDataType,
}

impl FieldValue {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        match self {
            FieldValue::String(s) => s.as_bytes().to_vec(),
            FieldValue::DataNumber(d) => d.to_be_bytes(),
            FieldValue::Float64(f) => f.to_be_bytes().to_vec(),
            FieldValue::Duration(d) => (d.as_secs() as u32).to_be_bytes().to_vec(),
            FieldValue::Ip4Addr(ip) => ip.octets().to_vec(),
            _ => vec![],
        }
    }
    pub fn from_field_type(
        remaining: &[u8],
        field_type: FieldDataType,
        field_length: u16,
    ) -> IResult<&[u8], FieldValue> {
        let (remaining, field_value) = match field_type {
            FieldDataType::UnsignedDataNumber => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (i, FieldValue::DataNumber(data_number))
            }
            FieldDataType::SignedDataNumber => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, true)?;
                (i, FieldValue::DataNumber(data_number))
            }
            FieldDataType::String => {
                let (i, taken) = take(field_length)(remaining)?;
                (
                    i,
                    FieldValue::String(String::from_utf8_lossy(taken).to_string()),
                )
            }
            FieldDataType::Ip4Addr => {
                let (i, taken) = be_u32(remaining)?;
                let ip_addr = Ipv4Addr::from(taken);
                (i, FieldValue::Ip4Addr(ip_addr))
            }
            FieldDataType::Ip6Addr => {
                let (i, taken) = be_u128(remaining)?;
                let ip_addr = Ipv6Addr::from(taken);
                (i, FieldValue::Ip6Addr(ip_addr))
            }
            FieldDataType::MacAddr => {
                let (i, taken) = take(6_usize)(remaining)?;
                let taken: &[u8; 6] = taken
                    .try_into()
                    .map_err(|_| NomErr::Error(NomError::new(remaining, ErrorKind::Fail)))?;

                let mac_addr = mac_address::MacAddress::from(*taken).to_string();
                (i, FieldValue::MacAddr(mac_addr))
            }
            FieldDataType::DurationSeconds => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_secs(
                        <DataNumber as Into<usize>>::into(data_number) as u64,
                    )),
                )
            }
            FieldDataType::DurationMillis => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_millis(
                        <DataNumber as Into<usize>>::into(data_number) as u64,
                    )),
                )
            }
            FieldDataType::DurationMicros => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_micros(
                        <DataNumber as Into<usize>>::into(data_number) as u64,
                    )),
                )
            }
            FieldDataType::DurationNanos => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_nanos(
                        <DataNumber as Into<usize>>::into(data_number) as u64,
                    )),
                )
            }
            FieldDataType::ProtocolType => {
                let (i, protocol) = ProtocolTypes::parse(remaining)?;
                (i, FieldValue::ProtocolType(protocol))
            }
            FieldDataType::Float64 => {
                let (i, f) = f64::parse(remaining)?;
                (i, FieldValue::Float64(f))
            }
            FieldDataType::Vec => {
                let (i, taken) = take(field_length)(remaining)?;
                (i, FieldValue::Vec(taken.to_vec()))
            }
            FieldDataType::Unknown => parse_unknown_fields(remaining, field_length)?,
        };
        Ok((remaining, field_value))
    }
}

/// Helps the parser indent the data type to parse the field as
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
    MacAddr,
    Vec,
    ProtocolType,
    Unknown,
}

#[cfg(test)]
mod data_number_tests {
    #[test]
    fn it_tests_3_byte_data_number_exports() {
        use super::DataNumber;
        let data = DataNumber::parse(&[1, 246, 118], 3, false).unwrap().1;
        assert_eq!(data.to_be_bytes(), vec![1, 246, 118]);
    }
}
