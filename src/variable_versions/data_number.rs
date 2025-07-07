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
    I64(i64),
    U128(u128),
    I128(i128),
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
    i64 => I64,
    u128 => U128,
    i128 => I128;
);

#[derive(Debug)]
pub enum FieldValueError {
    InvalidDataType,
}

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
            (1, true) => Ok(i8::parse(i)?).map(|(i, j)| (i, Self::I32(i32::from(j)))),
            (2, false) => Ok(u16::parse(i)?).map(|(i, j)| (i, Self::U16(j))),
            (2, true) => Ok(i16::parse(i)?).map(|(i, j)| (i, Self::I32(i32::from(j)))),
            (3, false) => Ok(be_u24(i).map(|(i, j)| (i, Self::U24(j)))?),
            (3, true) => Ok(be_i24(i).map(|(i, j)| (i, Self::I24(j)))?),
            (4, true) => Ok(i32::parse(i)?).map(|(i, j)| (i, Self::I32(j))),
            (4, false) => Ok(u32::parse(i)?).map(|(i, j)| (i, Self::U32(j))),
            (8, false) => Ok(u64::parse(i)?).map(|(i, j)| (i, Self::U64(j))),
            (8, true) => Ok(i64::parse(i)?).map(|(i, j)| (i, Self::I64(j))),
            (16, false) => Ok(u128::parse(i)?).map(|(i, j)| (i, Self::U128(j))),
            (16, true) => Ok(i128::parse(i)?).map(|(i, j)| (i, Self::I128(j))),
            _ => Err(NomErr::Error(NomError::new(i, ErrorKind::Fail))),
        }
    }

    fn to_be_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        match self {
            DataNumber::U8(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::U16(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::U24(n) => {
                let mut wtr = Vec::new();
                wtr.write_u24::<BigEndian>(*n)?;
                Ok(wtr)
            }
            DataNumber::I24(n) => {
                let mut wtr = Vec::new();
                wtr.write_i24::<BigEndian>(*n)?;
                Ok(wtr)
            }
            DataNumber::U32(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::U64(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::I64(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::U128(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::I32(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::I128(n) => Ok(n.to_be_bytes().to_vec()),
        }
    }
}

/// Convert into usize, mainly for serialization purposes
impl From<DataNumber> for usize {
    fn from(val: DataNumber) -> Self {
        match val {
            DataNumber::U8(i) => usize::from(i),
            DataNumber::I24(i) => i as usize,
            DataNumber::U24(i) => i as usize,
            DataNumber::U32(i) => i as usize,
            DataNumber::I32(i) => i as usize,
            DataNumber::U16(i) => i as usize,
            DataNumber::U64(i) => i as usize,
            DataNumber::I64(i) => i as usize,
            DataNumber::U128(i) => i as usize,
            DataNumber::I128(i) => i as usize,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize)]
pub struct ApplicationId {
    pub classification_engine_id: u8,
    pub selector_id: DataNumber,
}

/// Holds the post parsed field with its relevant datatype
#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize)]
pub enum FieldValue {
    ApplicationId(ApplicationId),
    String(String),
    DataNumber(DataNumber),
    Float64(f64),
    Duration(Duration),
    Ip4Addr(Ipv4Addr),
    Ip6Addr(Ipv6Addr),
    MacAddr(String),
    Vec(Vec<u8>),
    ProtocolType(ProtocolTypes),
    Unknown(Vec<u8>),
}

impl FieldValue {
    pub fn to_be_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        match self {
            FieldValue::ApplicationId(app_id) => {
                let mut wtr = Vec::new();
                wtr.write_u8(app_id.classification_engine_id)?;
                wtr.extend(app_id.selector_id.to_be_bytes()?);
                Ok(wtr)
            }
            FieldValue::String(s) => Ok(s.as_bytes().to_vec()),
            FieldValue::DataNumber(d) => d.to_be_bytes(),
            FieldValue::Float64(f) => Ok(f.to_be_bytes().to_vec()),
            FieldValue::Duration(d) => Ok((u32::try_from(d.as_secs())
                .map_err(std::io::Error::other)?)
            .to_be_bytes()
            .to_vec()),
            FieldValue::Ip4Addr(ip) => Ok(ip.octets().to_vec()),
            FieldValue::Ip6Addr(ip) => Ok(ip.octets().to_vec()),
            FieldValue::MacAddr(mac) => Ok(mac.as_bytes().to_vec()),
            FieldValue::ProtocolType(p) => Ok(u8::from(*p).to_be_bytes().to_vec()),
            FieldValue::Vec(v) => Ok(v.clone()),
            FieldValue::Unknown(v) => Ok(v.clone()),
        }
    }

    pub fn from_field_type(
        remaining: &[u8],
        field_type: FieldDataType,
        field_length: u16,
    ) -> IResult<&[u8], FieldValue> {
        let (remaining, field_value) = match field_type {
            FieldDataType::ApplicationId => {
                let (i, id) = u8::parse(remaining)?;
                let (i, selector_id) =
                    DataNumber::parse(i, field_length.saturating_sub(1), false)?;
                (
                    i,
                    FieldValue::ApplicationId(ApplicationId {
                        classification_engine_id: id,
                        selector_id,
                    }),
                )
            }
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
                let s = String::from_utf8_lossy(taken).to_string();
                let s: String = s.chars().filter(|&c| !c.is_control()).collect();
                let s = if s.starts_with("P4") {
                    s.trim_start_matches("P4").to_string()
                } else {
                    s
                };
                (i, FieldValue::String(s))
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
    ApplicationId,
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
    use super::{DataNumber, FieldDataType, FieldValue, ProtocolTypes};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn it_tests_3_byte_data_number_exports() {
        let data = DataNumber::parse(&[1, 246, 118], 3, false).unwrap().1;
        assert_eq!(data.to_be_bytes().unwrap(), vec![1, 246, 118]);
    }

    #[test]
    fn it_tests_field_value_to_be_bytes() {
        let field_value = FieldValue::String("test".to_string());
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![116, 101, 115, 116]);

        let field_value = FieldValue::DataNumber(DataNumber::U16(12345));
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![48, 57]);

        let field_value = FieldValue::Float64(123.456);
        assert_eq!(
            field_value.to_be_bytes().unwrap(),
            123.456f64.to_be_bytes().to_vec()
        );

        let field_value = FieldValue::Duration(Duration::from_secs(12345));
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![0, 0, 48, 57]);

        let field_value = FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![192, 168, 0, 1]);

        let field_value = FieldValue::Ip6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            field_value.to_be_bytes().unwrap(),
            vec![32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let field_value = FieldValue::MacAddr("00:1B:44:11:3A:B7".to_string());
        assert_eq!(
            field_value.to_be_bytes().unwrap(),
            vec![
                48, 48, 58, 49, 66, 58, 52, 52, 58, 49, 49, 58, 51, 65, 58, 66, 55
            ]
        );

        let field_value = FieldValue::ProtocolType(ProtocolTypes::Tcp);
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![6]);

        let field_value = FieldValue::Vec(vec![1, 2, 3, 4]);
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![1, 2, 3, 4]);

        let field_value = FieldValue::Unknown(vec![255, 254, 253]);
        assert_eq!(field_value.to_be_bytes().unwrap(), vec![255, 254, 253]);
    }

    #[test]
    fn it_tests_field_value_from_field_type() {
        let data = &[1, 2, 3, 4];
        let field_value =
            FieldValue::from_field_type(data, FieldDataType::UnsignedDataNumber, 4)
                .unwrap()
                .1;
        assert_eq!(
            field_value,
            FieldValue::DataNumber(DataNumber::U32(16909060))
        );

        let data = &[192, 168, 0, 1];
        let field_value = FieldValue::from_field_type(data, FieldDataType::Ip4Addr, 4)
            .unwrap()
            .1;
        assert_eq!(
            field_value,
            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 0, 1))
        );

        let data = &[32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let field_value = FieldValue::from_field_type(data, FieldDataType::Ip6Addr, 16)
            .unwrap()
            .1;
        assert_eq!(
            field_value,
            FieldValue::Ip6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }
}
