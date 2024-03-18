use crate::protocol::ProtocolTypes;

use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom::number::complete::{be_u128, be_u32};
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

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

    /// Parse bytes into DataNumber Type
    pub fn parse(i: &[u8], field_length: u16, signed: bool) -> IResult<&[u8], DataNumber> {
        match field_length {
            1 if !signed => Ok(u8::parse(i)?).map(|(i, j)| (i, Self::U8(j))),
            2 if !signed => Ok(u16::parse(i)?).map(|(i, j)| (i, Self::U16(j))),
            4 if signed => Ok(i32::parse(i)?).map(|(i, j)| (i, Self::I32(j))),
            4 if !signed => Ok(u32::parse(i)?).map(|(i, j)| (i, Self::U32(j))),
            8 if !signed => Ok(u64::parse(i)?).map(|(i, j)| (i, Self::U64(j))),
            16 if !signed => Ok(u128::parse(i)?).map(|(i, j)| (i, Self::U128(j))),
            _ => Err(NomErr::Error(NomError::new(i, ErrorKind::Fail))),
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
            FieldDataType::DurationSeconds => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_secs(data_number.get_value() as u64)),
                )
            }
            FieldDataType::DurationMillis => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_millis(data_number.get_value() as u64)),
                )
            }
            FieldDataType::DurationMicros => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_micros(data_number.get_value() as u64)),
                )
            }
            FieldDataType::DurationNanos => {
                let (i, data_number) = DataNumber::parse(remaining, field_length, false)?;
                (
                    i,
                    FieldValue::Duration(Duration::from_nanos(data_number.get_value() as u64)),
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
            FieldDataType::Unknown => {
                let (i, taken) = take(field_length)(remaining)?;
                (i, FieldValue::Vec(taken.to_vec()))
            }
        };
        Ok((remaining, field_value))
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
