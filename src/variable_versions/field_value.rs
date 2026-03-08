use crate::field_types::{
    FirewallEvent, FlowEndReason, ForwardingStatus, FragmentFlags, Ipv4Options,
    Ipv6ExtensionHeaders, IsMulticast, MplsLabelExp, MplsTopLabelType, NatEvent,
    NatOriginatingAddressRealm, TcpControlBits, TcpOptions,
};
use crate::protocol::ProtocolTypes;
use nom::{
    Err as NomErr, IResult,
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    number::complete::{be_i24, be_u24, be_u32, be_u128},
};
use nom_derive::Parse;
use serde::Serialize;
use serde::ser::Serializer;
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

/// Error returned when converting a [`DataNumber`] to a concrete numeric type fails
/// because the variant does not match the requested type.
#[derive(Debug)]
pub enum DataNumberError {
    /// The [`DataNumber`] variant does not match the requested numeric type.
    InvalidDataType,
}

impl std::fmt::Display for DataNumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataNumberError::InvalidDataType => {
                write!(f, "DataNumber variant does not match the requested type")
            }
        }
    }
}

impl std::error::Error for DataNumberError {}

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

/// Error returned when converting a [`FieldValue`] to a concrete Rust type fails
/// because the variant does not match the requested type.
#[derive(Debug)]
pub enum FieldValueError {
    /// The [`FieldValue`] variant does not match the requested type.
    InvalidDataType,
}

impl std::fmt::Display for FieldValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValueError::InvalidDataType => {
                write!(f, "FieldValue variant does not match the requested type")
            }
        }
    }
}

impl std::error::Error for FieldValueError {}

impl TryFrom<&FieldValue> for String {
    type Error = FieldValueError;

    fn try_from(value: &FieldValue) -> Result<Self, Self::Error> {
        match value {
            FieldValue::String(s) => Ok(s.clone()),
            FieldValue::MacAddr(bytes) => Ok(format_mac_addr(bytes)),
            _ => Err(FieldValueError::InvalidDataType),
        }
    }
}

/// Format a 6-byte MAC address as "aa:bb:cc:dd:ee:ff" (lowercase hex, colon-separated)
fn format_mac_addr(bytes: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
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

    /// Write big-endian bytes into a caller-provided buffer.
    pub fn write_be_bytes(&self, buf: &mut Vec<u8>) -> Result<(), std::io::Error> {
        match self {
            DataNumber::U8(n) => buf.push(*n),
            DataNumber::I8(n) => buf.push(*n as u8),
            DataNumber::U16(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::I16(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::U24(n) => {
                buf.push((*n >> 16) as u8);
                buf.push((*n >> 8) as u8);
                buf.push(*n as u8);
            }
            DataNumber::I24(n) => {
                buf.push((*n >> 16) as u8);
                buf.push((*n >> 8) as u8);
                buf.push(*n as u8);
            }
            DataNumber::U32(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::U64(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::I64(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::U128(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::I32(n) => buf.extend_from_slice(&n.to_be_bytes()),
            DataNumber::I128(n) => buf.extend_from_slice(&n.to_be_bytes()),
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Serialize)]
pub struct ApplicationId {
    pub classification_engine_id: u8,
    pub selector_id: DataNumber,
}

/// Holds the post parsed field with its relevant datatype
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub enum FieldValue {
    ApplicationId(ApplicationId),
    String(String),
    DataNumber(DataNumber),
    Float64(f64),
    Duration(Duration),
    Ip4Addr(Ipv4Addr),
    Ip6Addr(Ipv6Addr),
    MacAddr([u8; 6]),
    Vec(Vec<u8>),
    ProtocolType(ProtocolTypes),
    ForwardingStatus(ForwardingStatus),
    FragmentFlags(FragmentFlags),
    TcpControlBits(TcpControlBits),
    Ipv6ExtensionHeaders(Ipv6ExtensionHeaders),
    Ipv4Options(Ipv4Options),
    TcpOptions(TcpOptions),
    IsMulticast(IsMulticast),
    MplsLabelExp(MplsLabelExp),
    FlowEndReason(FlowEndReason),
    NatEvent(NatEvent),
    FirewallEvent(FirewallEvent),
    MplsTopLabelType(MplsTopLabelType),
    NatOriginatingAddressRealm(NatOriginatingAddressRealm),
    Unknown(Vec<u8>),
}

impl Serialize for FieldValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FieldValue::ApplicationId(v) => {
                serializer.serialize_newtype_variant("FieldValue", 0, "ApplicationId", v)
            }
            FieldValue::String(v) => {
                serializer.serialize_newtype_variant("FieldValue", 1, "String", v)
            }
            FieldValue::DataNumber(v) => {
                serializer.serialize_newtype_variant("FieldValue", 2, "DataNumber", v)
            }
            FieldValue::Float64(v) => {
                serializer.serialize_newtype_variant("FieldValue", 3, "Float64", v)
            }
            FieldValue::Duration(v) => {
                serializer.serialize_newtype_variant("FieldValue", 4, "Duration", v)
            }
            FieldValue::Ip4Addr(v) => {
                serializer.serialize_newtype_variant("FieldValue", 5, "Ip4Addr", v)
            }
            FieldValue::Ip6Addr(v) => {
                serializer.serialize_newtype_variant("FieldValue", 6, "Ip6Addr", v)
            }
            FieldValue::MacAddr(bytes) => {
                let formatted = format_mac_addr(bytes);
                serializer.serialize_newtype_variant("FieldValue", 7, "MacAddr", &formatted)
            }
            FieldValue::Vec(v) => {
                serializer.serialize_newtype_variant("FieldValue", 8, "Vec", v)
            }
            FieldValue::ProtocolType(v) => {
                serializer.serialize_newtype_variant("FieldValue", 9, "ProtocolType", v)
            }
            FieldValue::ForwardingStatus(v) => {
                serializer.serialize_newtype_variant("FieldValue", 10, "ForwardingStatus", v)
            }
            FieldValue::FragmentFlags(v) => {
                serializer.serialize_newtype_variant("FieldValue", 11, "FragmentFlags", v)
            }
            FieldValue::TcpControlBits(v) => {
                serializer.serialize_newtype_variant("FieldValue", 12, "TcpControlBits", v)
            }
            FieldValue::Ipv6ExtensionHeaders(v) => serializer.serialize_newtype_variant(
                "FieldValue",
                13,
                "Ipv6ExtensionHeaders",
                v,
            ),
            FieldValue::Ipv4Options(v) => {
                serializer.serialize_newtype_variant("FieldValue", 14, "Ipv4Options", v)
            }
            FieldValue::TcpOptions(v) => {
                serializer.serialize_newtype_variant("FieldValue", 15, "TcpOptions", v)
            }
            FieldValue::IsMulticast(v) => {
                serializer.serialize_newtype_variant("FieldValue", 16, "IsMulticast", v)
            }
            FieldValue::MplsLabelExp(v) => {
                serializer.serialize_newtype_variant("FieldValue", 17, "MplsLabelExp", v)
            }
            FieldValue::FlowEndReason(v) => {
                serializer.serialize_newtype_variant("FieldValue", 18, "FlowEndReason", v)
            }
            FieldValue::NatEvent(v) => {
                serializer.serialize_newtype_variant("FieldValue", 19, "NatEvent", v)
            }
            FieldValue::FirewallEvent(v) => {
                serializer.serialize_newtype_variant("FieldValue", 20, "FirewallEvent", v)
            }
            FieldValue::MplsTopLabelType(v) => {
                serializer.serialize_newtype_variant("FieldValue", 21, "MplsTopLabelType", v)
            }
            FieldValue::NatOriginatingAddressRealm(v) => serializer.serialize_newtype_variant(
                "FieldValue",
                22,
                "NatOriginatingAddressRealm",
                v,
            ),
            FieldValue::Unknown(v) => {
                serializer.serialize_newtype_variant("FieldValue", 23, "Unknown", v)
            }
        }
    }
}

impl FieldValue {
    /// Write big-endian bytes into a caller-provided buffer.
    pub fn write_be_bytes(&self, buf: &mut Vec<u8>) -> Result<(), std::io::Error> {
        match self {
            FieldValue::ApplicationId(app_id) => {
                buf.push(app_id.classification_engine_id);
                app_id.selector_id.write_be_bytes(buf)?;
            }
            FieldValue::String(s) => buf.extend_from_slice(s.as_bytes()),
            FieldValue::DataNumber(d) => d.write_be_bytes(buf)?,
            FieldValue::Float64(f) => buf.extend_from_slice(&f.to_be_bytes()),
            FieldValue::Duration(d) => {
                let secs = u32::try_from(d.as_secs()).map_err(std::io::Error::other)?;
                buf.extend_from_slice(&secs.to_be_bytes());
            }
            FieldValue::Ip4Addr(ip) => buf.extend_from_slice(&ip.octets()),
            FieldValue::Ip6Addr(ip) => buf.extend_from_slice(&ip.octets()),
            FieldValue::MacAddr(mac) => buf.extend_from_slice(mac),
            FieldValue::ProtocolType(p) => buf.push(u8::from(*p)),
            FieldValue::ForwardingStatus(f) => buf.push(u8::from(*f)),
            FieldValue::FragmentFlags(f) => buf.push(u8::from(*f)),
            FieldValue::TcpControlBits(t) => {
                buf.extend_from_slice(&u16::from(*t).to_be_bytes())
            }
            FieldValue::Ipv6ExtensionHeaders(h) => {
                buf.extend_from_slice(&u32::from(*h).to_be_bytes())
            }
            FieldValue::Ipv4Options(o) => buf.extend_from_slice(&u32::from(*o).to_be_bytes()),
            FieldValue::TcpOptions(o) => buf.extend_from_slice(&u64::from(*o).to_be_bytes()),
            FieldValue::IsMulticast(m) => buf.push(u8::from(*m)),
            FieldValue::MplsLabelExp(e) => buf.push(u8::from(*e)),
            FieldValue::FlowEndReason(r) => buf.push(u8::from(*r)),
            FieldValue::NatEvent(e) => buf.push(u8::from(*e)),
            FieldValue::FirewallEvent(e) => buf.push(u8::from(*e)),
            FieldValue::MplsTopLabelType(t) => buf.push(u8::from(*t)),
            FieldValue::NatOriginatingAddressRealm(r) => buf.push(u8::from(*r)),
            FieldValue::Vec(v) => buf.extend_from_slice(v),
            FieldValue::Unknown(v) => buf.extend_from_slice(v),
        }
        Ok(())
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
                let s: String = String::from_utf8_lossy(taken)
                    .chars()
                    .filter(|&c| !c.is_control())
                    .collect();
                let s = if let Some(stripped) = s.strip_prefix("P4") {
                    stripped.to_owned()
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
                (i, FieldValue::MacAddr(*taken))
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
            FieldDataType::ForwardingStatus => {
                let (i, status) = ForwardingStatus::parse(remaining)?;
                (i, FieldValue::ForwardingStatus(status))
            }
            FieldDataType::FragmentFlags => {
                let (i, flags) = FragmentFlags::parse(remaining)?;
                (i, FieldValue::FragmentFlags(flags))
            }
            FieldDataType::TcpControlBits => {
                let (i, bits) = TcpControlBits::parse(remaining)?;
                (i, FieldValue::TcpControlBits(bits))
            }
            FieldDataType::Ipv6ExtensionHeaders => {
                let (i, headers) = Ipv6ExtensionHeaders::parse(remaining)?;
                (i, FieldValue::Ipv6ExtensionHeaders(headers))
            }
            FieldDataType::Ipv4Options => {
                let (i, opts) = Ipv4Options::parse(remaining)?;
                (i, FieldValue::Ipv4Options(opts))
            }
            FieldDataType::TcpOptions => {
                let (i, opts) = TcpOptions::parse(remaining)?;
                (i, FieldValue::TcpOptions(opts))
            }
            FieldDataType::IsMulticast => {
                let (i, m) = IsMulticast::parse(remaining)?;
                (i, FieldValue::IsMulticast(m))
            }
            FieldDataType::MplsLabelExp => {
                let (i, exp) = MplsLabelExp::parse(remaining)?;
                (i, FieldValue::MplsLabelExp(exp))
            }
            FieldDataType::FlowEndReason => {
                let (i, reason) = FlowEndReason::parse(remaining)?;
                (i, FieldValue::FlowEndReason(reason))
            }
            FieldDataType::NatEvent => {
                let (i, event) = NatEvent::parse(remaining)?;
                (i, FieldValue::NatEvent(event))
            }
            FieldDataType::FirewallEvent => {
                let (i, event) = FirewallEvent::parse(remaining)?;
                (i, FieldValue::FirewallEvent(event))
            }
            FieldDataType::MplsTopLabelType => {
                let (i, lt) = MplsTopLabelType::parse(remaining)?;
                (i, FieldValue::MplsTopLabelType(lt))
            }
            FieldDataType::NatOriginatingAddressRealm => {
                let (i, realm) = NatOriginatingAddressRealm::parse(remaining)?;
                (i, FieldValue::NatOriginatingAddressRealm(realm))
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
/// use netflow_parser::variable_versions::field_value::FieldDataType;
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
    /// Forwarding status (see [`ForwardingStatus`](crate::field_types::ForwardingStatus))
    ForwardingStatus,
    /// Fragment flags bitmask (field 197)
    FragmentFlags,
    /// TCP control bits / header flags (field 6)
    TcpControlBits,
    /// IPv6 extension headers bitmask (field 64)
    Ipv6ExtensionHeaders,
    /// IPv4 options bitmask (field 208)
    Ipv4Options,
    /// TCP options bitmask (field 209)
    TcpOptions,
    /// Multicast indicator (field 206)
    IsMulticast,
    /// MPLS label experimental bits (fields 203, 237)
    MplsLabelExp,
    /// Flow end reason (field 136)
    FlowEndReason,
    /// NAT event type (field 230)
    NatEvent,
    /// Firewall event (field 233)
    FirewallEvent,
    /// MPLS top label type (field 46)
    MplsTopLabelType,
    /// NAT originating address realm (field 229)
    NatOriginatingAddressRealm,
    /// Unknown or unsupported field type
    Unknown,
}

#[cfg(test)]
mod field_value_tests {
    use super::{DataNumber, FieldDataType, FieldValue, ProtocolTypes};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn it_tests_3_byte_data_number_exports() {
        let data = DataNumber::parse(&[1, 246, 118], 3, false).unwrap().1;
        let mut buf = Vec::new();
        data.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 246, 118]);
    }

    #[test]
    fn it_tests_field_value_to_be_bytes() {
        let mut buf = Vec::new();

        let field_value = FieldValue::String("test".to_string());
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![116, 101, 115, 116]);

        let field_value = FieldValue::DataNumber(DataNumber::U16(12345));
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![48, 57]);

        let field_value = FieldValue::Float64(123.456);
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, 123.456f64.to_be_bytes().to_vec());

        let field_value = FieldValue::Duration(Duration::from_secs(12345));
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![0, 0, 48, 57]);

        let field_value = FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 0, 1));
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![192, 168, 0, 1]);

        let field_value = FieldValue::Ip6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(
            buf,
            vec![32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let field_value = FieldValue::MacAddr([0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]);
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7]);

        let field_value = FieldValue::ProtocolType(ProtocolTypes::Tcp);
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![6]);

        let field_value = FieldValue::Vec(vec![1, 2, 3, 4]);
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4]);

        let field_value = FieldValue::Unknown(vec![255, 254, 253]);
        buf.clear();
        field_value.write_be_bytes(&mut buf).unwrap();
        assert_eq!(buf, vec![255, 254, 253]);
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
