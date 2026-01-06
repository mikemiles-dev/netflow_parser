use crate::protocol::ProtocolTypes;
use byteorder::{BigEndian, WriteBytesExt};
use nom::{
    Err as NomErr, IResult,
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    number::complete::{be_i24, be_u24, be_u32, be_u128},
};
use nom_derive::Parse;
use serde::Serialize;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

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
    I8(i8),
    U16(u16),
    I16(i16),
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
    i8 => I8,
    u16 => U16,
    i16 => I16,
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

/// Helper function to parse duration fields that can be either 4 or 8 bytes
fn parse_duration<F>(
    remaining: &[u8],
    field_length: u16,
    from_fn: F,
) -> IResult<&[u8], FieldValue>
where
    F: Fn(u64) -> Duration,
{
    match field_length {
        4 => {
            let (i, value) = u32::parse_be(remaining)?;
            Ok((i, FieldValue::Duration(from_fn(value.into()))))
        }
        8 => {
            let (i, value) = u64::parse_be(remaining)?;
            Ok((i, FieldValue::Duration(from_fn(value))))
        }
        _ => Err(NomErr::Error(NomError::new(remaining, ErrorKind::Fail))),
    }
}

/// Convert into usize, mainly for serialization purposes
impl DataNumber {
    /// Parse bytes into DataNumber Type
    pub fn parse(i: &[u8], field_length: u16, signed: bool) -> IResult<&[u8], DataNumber> {
        match (field_length, signed) {
            (1, false) => Ok(u8::parse(i)?).map(|(i, j)| (i, Self::U8(j))),
            (1, true) => Ok(i8::parse(i)?).map(|(i, j)| (i, Self::I8(j))),
            (2, false) => Ok(u16::parse(i)?).map(|(i, j)| (i, Self::U16(j))),
            (2, true) => Ok(i16::parse(i)?).map(|(i, j)| (i, Self::I16(j))),
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
            DataNumber::U8(n) => Ok(vec![*n]),
            DataNumber::I8(n) => Ok(vec![u8::try_from(*n).map_err(std::io::Error::other)?]),
            DataNumber::U16(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::I16(n) => Ok(n.to_be_bytes().to_vec()),
            DataNumber::U24(n) => {
                let mut wtr = Vec::with_capacity(3);
                wtr.write_u24::<BigEndian>(*n)?;
                Ok(wtr)
            }
            DataNumber::I24(n) => {
                let mut wtr = Vec::with_capacity(3);
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

    fn make_ntp_time_with_unit(seconds: u32, fraction: u32, unit: u64) -> Duration {
        Duration::from_secs(u64::from(seconds)).saturating_add(Duration::from_micros(
            ((u64::from(fraction)).saturating_mul(unit)) >> 32,
        ))
    }

    #[inline]
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
                // Filter control chars first, then strip P4 prefix (original logic)
                let s: String = String::from_utf8_lossy(taken)
                    .chars()
                    .filter(|&c| !c.is_control())
                    .collect();
                let s = s.strip_prefix("P4").unwrap_or(&s).to_string();
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
                parse_duration(remaining, field_length, Duration::from_secs)?
            }
            FieldDataType::DurationMillis => {
                parse_duration(remaining, field_length, Duration::from_millis)?
            }
            FieldDataType::DurationMicrosNTP => {
                let (i, seconds) = u32::parse_be(remaining)?;
                let (i, fraction) = u32::parse_be(i)?;
                let dur = Self::make_ntp_time_with_unit(seconds, fraction, 1_000_000);
                (i, FieldValue::Duration(dur))
            }
            FieldDataType::DurationNanosNTP => {
                let (i, seconds) = u32::parse_be(remaining)?;
                let (i, fraction) = u32::parse_be(i)?;
                let dur = Self::make_ntp_time_with_unit(seconds, fraction, 1_000_000_000);
                (i, FieldValue::Duration(dur))
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

/// Specifies the data type for IPFIX/NetFlow field values.
///
/// Each IPFIX field has an associated `FieldDataType` that determines how
/// its raw bytes should be parsed and interpreted. This enum represents all
/// supported data types in the parser.
///
/// # Type Categories
///
/// ## Network Types
/// - [`Ip4Addr`](Self::Ip4Addr) - IPv4 address (4 bytes)
/// - [`Ip6Addr`](Self::Ip6Addr) - IPv6 address (16 bytes)
/// - [`MacAddr`](Self::MacAddr) - MAC address (6 bytes)
///
/// ## Numeric Types
/// - [`UnsignedDataNumber`](Self::UnsignedDataNumber) - Unsigned integers (1-16 bytes)
/// - [`SignedDataNumber`](Self::SignedDataNumber) - Signed integers (1-16 bytes)
/// - [`Float64`](Self::Float64) - 64-bit floating point
///
/// ## Time/Duration Types
/// - [`DurationSeconds`](Self::DurationSeconds) - Duration in seconds
/// - [`DurationMillis`](Self::DurationMillis) - Duration in milliseconds
/// - [`DurationMicrosNTP`](Self::DurationMicrosNTP) - Duration in microseconds (NTP format)
/// - [`DurationNanosNTP`](Self::DurationNanosNTP) - Duration in nanoseconds (NTP format)
///
/// ## Text and Binary Types
/// - [`String`](Self::String) - UTF-8 string data
/// - [`Vec`](Self::Vec) - Raw byte vector
///
/// ## Special Types
/// - [`ApplicationId`](Self::ApplicationId) - Application identifier field
/// - [`ProtocolType`](Self::ProtocolType) - IP protocol number (maps to [`ProtocolTypes`])
/// - [`Unknown`](Self::Unknown) - Unknown or unsupported type
///
/// # Examples
///
/// ```
/// use netflow_parser::variable_versions::data_number::FieldDataType;
/// use netflow_parser::variable_versions::ipfix_lookup::IANAIPFixField;
///
/// // Get the data type for a specific field
/// let field = IANAIPFixField::SourceIpv4address;
/// let data_type: FieldDataType = field.into();
/// assert_eq!(data_type, FieldDataType::Ip4Addr);
///
/// // Different fields have different types
/// let proto_field = IANAIPFixField::ProtocolIdentifier;
/// let proto_type: FieldDataType = proto_field.into();
/// assert_eq!(proto_type, FieldDataType::ProtocolType);
/// ```
///
/// [`ProtocolTypes`]: crate::protocol::ProtocolTypes
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum FieldDataType {
    /// Application identifier field
    ApplicationId,
    /// UTF-8 string data
    String,
    /// Signed integer (can be i8, i16, i24, i32, i64, i128)
    SignedDataNumber,
    /// Unsigned integer (can be u8, u16, u24, u32, u64, u128)
    UnsignedDataNumber,
    /// 64-bit floating point number
    Float64,
    /// Duration in seconds
    DurationSeconds,
    /// Duration in milliseconds
    DurationMillis,
    /// Duration in microseconds (NTP timestamp format)
    DurationMicrosNTP,
    /// Duration in nanoseconds (NTP timestamp format)
    DurationNanosNTP,
    /// IPv4 address (4 bytes)
    Ip4Addr,
    /// IPv6 address (16 bytes)
    Ip6Addr,
    /// MAC address (6 bytes)
    MacAddr,
    /// Raw byte vector for variable-length fields
    Vec,
    /// IP protocol number (see [`ProtocolTypes`])
    ProtocolType,
    /// Unknown or unsupported field type
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
