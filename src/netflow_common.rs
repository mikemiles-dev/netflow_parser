use std::net::IpAddr;

use crate::NetflowPacket;
use crate::protocol::ProtocolTypes;
use crate::static_versions::{v5::V5, v7::V7};
use crate::variable_versions::data_number::FieldValue;
use crate::variable_versions::ipfix_lookup::{IANAIPFixField, IPFixField};
use crate::variable_versions::v9_lookup::V9Field;
use crate::variable_versions::{
    ipfix::{FlowSetBody as IPFixFlowSetBody, IPFix},
    v9::{FlowSetBody as V9FlowSetBody, V9},
};

#[derive(Debug)]
pub enum NetflowCommonError {
    UnknownVersion(NetflowPacket),
}

/// Generic configuration for mapping fields to NetflowCommonFlowSet fields.
/// Each field can have a primary and optional fallback field type.
#[derive(Debug, Clone)]
pub struct FieldMapping<T> {
    /// Primary field to search for
    pub primary: T,
    /// Optional fallback field if primary is not found
    pub fallback: Option<T>,
}

impl<T> FieldMapping<T> {
    /// Create a new field mapping with only a primary field
    pub fn new(primary: T) -> Self {
        Self {
            primary,
            fallback: None,
        }
    }

    /// Create a new field mapping with a primary and fallback field
    pub fn with_fallback(primary: T, fallback: T) -> Self {
        Self {
            primary,
            fallback: Some(fallback),
        }
    }
}

/// Type alias for V9 field mapping configuration
pub type V9FieldMapping = FieldMapping<V9Field>;

/// Type alias for IPFix field mapping configuration
pub type IPFixFieldMapping = FieldMapping<IPFixField>;

/// Configuration for V9 field mappings used when converting V9 to NetflowCommon.
///
/// This allows customization of which V9 fields map to which NetflowCommonFlowSet fields.
/// By default, standard IANA field mappings are used.
///
/// # Example
///
/// ```rust
/// use netflow_parser::netflow_common::V9FieldMappingConfig;
/// use netflow_parser::variable_versions::v9_lookup::V9Field;
///
/// // Use default mappings
/// let config = V9FieldMappingConfig::default();
///
/// // Or customize specific fields
/// let mut config = V9FieldMappingConfig::default();
/// config.src_addr.primary = V9Field::Ipv6SrcAddr;  // Prefer IPv6
/// config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);  // Fall back to IPv4
/// ```
#[derive(Debug, Clone)]
pub struct V9FieldMappingConfig {
    /// Mapping for source address field
    pub src_addr: V9FieldMapping,
    /// Mapping for destination address field
    pub dst_addr: V9FieldMapping,
    /// Mapping for source port field
    pub src_port: V9FieldMapping,
    /// Mapping for destination port field
    pub dst_port: V9FieldMapping,
    /// Mapping for protocol field
    pub protocol: V9FieldMapping,
    /// Mapping for first seen timestamp field
    pub first_seen: V9FieldMapping,
    /// Mapping for last seen timestamp field
    pub last_seen: V9FieldMapping,
    /// Mapping for source MAC address field
    pub src_mac: V9FieldMapping,
    /// Mapping for destination MAC address field
    pub dst_mac: V9FieldMapping,
}

impl Default for V9FieldMappingConfig {
    fn default() -> Self {
        Self {
            src_addr: V9FieldMapping::with_fallback(V9Field::Ipv4SrcAddr, V9Field::Ipv6SrcAddr),
            dst_addr: V9FieldMapping::with_fallback(V9Field::Ipv4DstAddr, V9Field::Ipv6DstAddr),
            src_port: V9FieldMapping::new(V9Field::L4SrcPort),
            dst_port: V9FieldMapping::new(V9Field::L4DstPort),
            protocol: V9FieldMapping::new(V9Field::Protocol),
            first_seen: V9FieldMapping::new(V9Field::FirstSwitched),
            last_seen: V9FieldMapping::new(V9Field::LastSwitched),
            src_mac: V9FieldMapping::new(V9Field::InSrcMac),
            dst_mac: V9FieldMapping::new(V9Field::InDstMac),
        }
    }
}

/// Configuration for IPFIX field mappings used when converting IPFIX to NetflowCommon.
///
/// This allows customization of which IPFIX fields map to which NetflowCommonFlowSet fields.
/// By default, standard IANA field mappings are used.
///
/// # Example
///
/// ```rust
/// use netflow_parser::netflow_common::IPFixFieldMappingConfig;
/// use netflow_parser::variable_versions::ipfix_lookup::{IPFixField, IANAIPFixField};
///
/// // Use default mappings
/// let config = IPFixFieldMappingConfig::default();
///
/// // Or customize specific fields
/// let mut config = IPFixFieldMappingConfig::default();
/// config.src_addr.primary = IPFixField::IANA(IANAIPFixField::SourceIpv6address);  // Prefer IPv6
/// config.src_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::SourceIpv4address));  // Fall back to IPv4
/// ```
#[derive(Debug, Clone)]
pub struct IPFixFieldMappingConfig {
    /// Mapping for source address field
    pub src_addr: IPFixFieldMapping,
    /// Mapping for destination address field
    pub dst_addr: IPFixFieldMapping,
    /// Mapping for source port field
    pub src_port: IPFixFieldMapping,
    /// Mapping for destination port field
    pub dst_port: IPFixFieldMapping,
    /// Mapping for protocol field
    pub protocol: IPFixFieldMapping,
    /// Mapping for first seen timestamp field
    pub first_seen: IPFixFieldMapping,
    /// Mapping for last seen timestamp field
    pub last_seen: IPFixFieldMapping,
    /// Mapping for source MAC address field
    pub src_mac: IPFixFieldMapping,
    /// Mapping for destination MAC address field
    pub dst_mac: IPFixFieldMapping,
}

impl Default for IPFixFieldMappingConfig {
    fn default() -> Self {
        Self {
            src_addr: IPFixFieldMapping::with_fallback(
                IPFixField::IANA(IANAIPFixField::SourceIpv4address),
                IPFixField::IANA(IANAIPFixField::SourceIpv6address),
            ),
            dst_addr: IPFixFieldMapping::with_fallback(
                IPFixField::IANA(IANAIPFixField::DestinationIpv4address),
                IPFixField::IANA(IANAIPFixField::DestinationIpv6address),
            ),
            src_port: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::SourceTransportPort,
            )),
            dst_port: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::DestinationTransportPort,
            )),
            protocol: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::ProtocolIdentifier,
            )),
            first_seen: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::FlowStartSysUpTime,
            )),
            last_seen: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::FlowEndSysUpTime,
            )),
            src_mac: IPFixFieldMapping::new(IPFixField::IANA(IANAIPFixField::SourceMacaddress)),
            dst_mac: IPFixFieldMapping::new(IPFixField::IANA(
                IANAIPFixField::DestinationMacaddress,
            )),
        }
    }
}

#[derive(Debug, Default)]
/// Common structure for Netflow
pub struct NetflowCommon {
    pub version: u16,
    pub timestamp: u32,
    pub flowsets: Vec<NetflowCommonFlowSet>,
}

impl TryFrom<&NetflowPacket> for NetflowCommon {
    type Error = NetflowCommonError;

    fn try_from(value: &NetflowPacket) -> Result<Self, NetflowCommonError> {
        match value {
            NetflowPacket::V5(v5) => Ok(v5.into()),
            NetflowPacket::V7(v7) => Ok(v7.into()),
            NetflowPacket::V9(v9) => Ok(v9.into()),
            NetflowPacket::IPFix(ipfix) => Ok(ipfix.into()),
        }
    }
}

#[derive(Debug, Default)]
/// Common flow set structure for Netflow
pub struct NetflowCommonFlowSet {
    /// Source IP address
    pub src_addr: Option<IpAddr>,
    /// Destination IP address
    pub dst_addr: Option<IpAddr>,
    /// TCP/UDP source port number or equivalent
    pub src_port: Option<u16>,
    /// TCP/UDP destination port number or equivalent
    pub dst_port: Option<u16>,
    /// Number of IP protocol type (for example, TCP = 6; UDP = 17)
    pub protocol_number: Option<u8>,
    /// IP protocol type itself
    pub protocol_type: Option<ProtocolTypes>,
    /// Duration of the flow first
    pub first_seen: Option<u32>,
    /// Duration of the flow last
    pub last_seen: Option<u32>,
    /// Source MAC address
    pub src_mac: Option<String>,
    /// Destination MAC address
    pub dst_mac: Option<String>,
}

impl From<&V5> for NetflowCommon {
    fn from(value: &V5) -> Self {
        // Convert V5 to NetflowCommon
        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.sys_up_time,
            flowsets: value
                .flowsets
                .iter()
                .map(|set| NetflowCommonFlowSet {
                    src_addr: Some(set.src_addr.into()),
                    dst_addr: Some(set.dst_addr.into()),
                    src_port: Some(set.src_port),
                    dst_port: Some(set.dst_port),
                    protocol_number: Some(set.protocol_number),
                    protocol_type: Some(set.protocol_type),
                    first_seen: Some(set.first),
                    last_seen: Some(set.last),
                    src_mac: None,
                    dst_mac: None,
                })
                .collect(),
        }
    }
}

impl From<&V7> for NetflowCommon {
    fn from(value: &V7) -> Self {
        // Convert V7 to NetflowCommon
        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.sys_up_time,
            flowsets: value
                .flowsets
                .iter()
                .map(|set| NetflowCommonFlowSet {
                    src_addr: Some(set.src_addr.into()),
                    dst_addr: Some(set.dst_addr.into()),
                    src_port: Some(set.src_port),
                    dst_port: Some(set.dst_port),
                    protocol_number: Some(set.protocol_number),
                    protocol_type: Some(set.protocol_type),
                    first_seen: Some(set.first),
                    last_seen: Some(set.last),
                    src_mac: None,
                    dst_mac: None,
                })
                .collect(),
        }
    }
}

/// Helper structure to store all found V9 fields in a single pass
#[derive(Copy, Clone)]
struct V9FieldCache<'a> {
    src_addr_v4: Option<&'a FieldValue>,
    src_addr_v6: Option<&'a FieldValue>,
    dst_addr_v4: Option<&'a FieldValue>,
    dst_addr_v6: Option<&'a FieldValue>,
    src_port: Option<&'a FieldValue>,
    dst_port: Option<&'a FieldValue>,
    protocol: Option<&'a FieldValue>,
    first_seen: Option<&'a FieldValue>,
    last_seen: Option<&'a FieldValue>,
    src_mac: Option<&'a FieldValue>,
    dst_mac: Option<&'a FieldValue>,
}

impl<'a> V9FieldCache<'a> {
    fn from_fields(fields: &'a [(V9Field, FieldValue)]) -> Self {
        let mut cache = Self {
            src_addr_v4: None,
            src_addr_v6: None,
            dst_addr_v4: None,
            dst_addr_v6: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            first_seen: None,
            last_seen: None,
            src_mac: None,
            dst_mac: None,
        };

        // Single pass through all fields
        for (field_type, field_value) in fields {
            match field_type {
                V9Field::Ipv4SrcAddr => cache.src_addr_v4 = Some(field_value),
                V9Field::Ipv6SrcAddr => cache.src_addr_v6 = Some(field_value),
                V9Field::Ipv4DstAddr => cache.dst_addr_v4 = Some(field_value),
                V9Field::Ipv6DstAddr => cache.dst_addr_v6 = Some(field_value),
                V9Field::L4SrcPort => cache.src_port = Some(field_value),
                V9Field::L4DstPort => cache.dst_port = Some(field_value),
                V9Field::Protocol => cache.protocol = Some(field_value),
                V9Field::FirstSwitched => cache.first_seen = Some(field_value),
                V9Field::LastSwitched => cache.last_seen = Some(field_value),
                V9Field::InSrcMac => cache.src_mac = Some(field_value),
                V9Field::InDstMac => cache.dst_mac = Some(field_value),
                _ => {} // Ignore other fields
            }
        }

        cache
    }
}

/// Macro to create NetflowCommonFlowSet from a cache structure with separate v4/v6 fields
macro_rules! create_common_flowset_with_ip_versions {
    ($cache:expr, $src_v4:ident, $src_v6:ident, $dst_v4:ident, $dst_v6:ident) => {
        NetflowCommonFlowSet {
            src_addr: $cache
                .$src_v4
                .or($cache.$src_v6)
                .and_then(|v| v.try_into().ok()),
            dst_addr: $cache
                .$dst_v4
                .or($cache.$dst_v6)
                .and_then(|v| v.try_into().ok()),
            src_port: $cache.src_port.and_then(|v| v.try_into().ok()),
            dst_port: $cache.dst_port.and_then(|v| v.try_into().ok()),
            protocol_number: $cache.protocol.and_then(|v| v.try_into().ok()),
            protocol_type: $cache.protocol.and_then(|v| {
                v.try_into()
                    .ok()
                    .map(|proto: u8| ProtocolTypes::from(proto))
            }),
            first_seen: $cache.first_seen.and_then(|v| v.try_into().ok()),
            last_seen: $cache.last_seen.and_then(|v| v.try_into().ok()),
            src_mac: $cache.src_mac.and_then(|v| v.try_into().ok()),
            dst_mac: $cache.dst_mac.and_then(|v| v.try_into().ok()),
        }
    };
}

/// Macro to create NetflowCommonFlowSet from a cache structure
macro_rules! create_common_flowset {
    ($cache:expr) => {
        NetflowCommonFlowSet {
            src_addr: $cache.src_addr.and_then(|v| v.try_into().ok()),
            dst_addr: $cache.dst_addr.and_then(|v| v.try_into().ok()),
            src_port: $cache.src_port.and_then(|v| v.try_into().ok()),
            dst_port: $cache.dst_port.and_then(|v| v.try_into().ok()),
            protocol_number: $cache.protocol.and_then(|v| v.try_into().ok()),
            protocol_type: $cache.protocol.and_then(|v| {
                v.try_into()
                    .ok()
                    .map(|proto: u8| ProtocolTypes::from(proto))
            }),
            first_seen: $cache.first_seen.and_then(|v| v.try_into().ok()),
            last_seen: $cache.last_seen.and_then(|v| v.try_into().ok()),
            src_mac: $cache.src_mac.and_then(|v| v.try_into().ok()),
            dst_mac: $cache.dst_mac.and_then(|v| v.try_into().ok()),
        }
    };
}

/// Macro to generate field cache checking logic for config-based caches
macro_rules! check_field_mapping {
    ($field_type:expr, $field_value:expr, $cache:expr, $config:expr, $field_name:ident) => {
        if *$field_type == $config.$field_name.primary {
            $cache.$field_name = Some($field_value);
        } else if Some(*$field_type) == $config.$field_name.fallback
            && $cache.$field_name.is_none()
        {
            $cache.$field_name = Some($field_value);
        }
    };
}

/// Helper structure to cache V9 field lookups with custom mapping in a single pass
#[derive(Copy, Clone)]
struct V9ConfigFieldCache<'a> {
    src_addr: Option<&'a FieldValue>,
    dst_addr: Option<&'a FieldValue>,
    src_port: Option<&'a FieldValue>,
    dst_port: Option<&'a FieldValue>,
    protocol: Option<&'a FieldValue>,
    first_seen: Option<&'a FieldValue>,
    last_seen: Option<&'a FieldValue>,
    src_mac: Option<&'a FieldValue>,
    dst_mac: Option<&'a FieldValue>,
}

impl<'a> V9ConfigFieldCache<'a> {
    fn from_fields_with_config(
        fields: &'a [(V9Field, FieldValue)],
        config: &V9FieldMappingConfig,
    ) -> Self {
        let mut cache = Self {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            first_seen: None,
            last_seen: None,
            src_mac: None,
            dst_mac: None,
        };

        // Single pass through all fields, collecting based on config
        for (field_type, field_value) in fields {
            check_field_mapping!(field_type, field_value, cache, config, src_addr);
            check_field_mapping!(field_type, field_value, cache, config, dst_addr);
            check_field_mapping!(field_type, field_value, cache, config, src_port);
            check_field_mapping!(field_type, field_value, cache, config, dst_port);
            check_field_mapping!(field_type, field_value, cache, config, protocol);
            check_field_mapping!(field_type, field_value, cache, config, first_seen);
            check_field_mapping!(field_type, field_value, cache, config, last_seen);
            check_field_mapping!(field_type, field_value, cache, config, src_mac);
            check_field_mapping!(field_type, field_value, cache, config, dst_mac);
        }

        cache
    }
}

impl NetflowCommon {
    /// Convert a V9 packet to NetflowCommon using a custom field mapping configuration.
    ///
    /// This allows you to specify which V9 fields should be used for each
    /// NetflowCommonFlowSet field, including fallback fields.
    ///
    /// # Example
    ///
    /// ```rust
    /// use netflow_parser::netflow_common::V9FieldMappingConfig;
    /// use netflow_parser::variable_versions::v9_lookup::V9Field;
    ///
    /// // Use custom configuration that prefers IPv6
    /// let mut config = V9FieldMappingConfig::default();
    /// config.src_addr.primary = V9Field::Ipv6SrcAddr;
    /// config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);
    ///
    /// // Then use: NetflowCommon::from_v9_with_config(&v9, &config);
    /// ```
    pub fn from_v9_with_config(value: &V9, config: &V9FieldMappingConfig) -> Self {
        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let V9FlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    // Single pass through fields to collect all values with config
                    let cache = V9ConfigFieldCache::from_fields_with_config(data_field, config);
                    flowsets.push(create_common_flowset!(cache));
                }
            }
        }

        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.sys_up_time,
            flowsets,
        }
    }
}

impl From<&V9> for NetflowCommon {
    fn from(value: &V9) -> Self {
        // Convert V9 to NetflowCommon using default configuration with single-pass field lookup
        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let V9FlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    // Single pass through fields to collect all values
                    let cache = V9FieldCache::from_fields(data_field);
                    flowsets.push(create_common_flowset_with_ip_versions!(
                        cache,
                        src_addr_v4,
                        src_addr_v6,
                        dst_addr_v4,
                        dst_addr_v6
                    ));
                }
            }
        }

        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.sys_up_time,
            flowsets,
        }
    }
}

/// Helper structure to store all found IPFIX fields in a single pass
#[derive(Copy, Clone)]
struct IPFixFieldCache<'a> {
    src_addr_v4: Option<&'a FieldValue>,
    src_addr_v6: Option<&'a FieldValue>,
    dst_addr_v4: Option<&'a FieldValue>,
    dst_addr_v6: Option<&'a FieldValue>,
    src_port: Option<&'a FieldValue>,
    dst_port: Option<&'a FieldValue>,
    protocol: Option<&'a FieldValue>,
    first_seen: Option<&'a FieldValue>,
    last_seen: Option<&'a FieldValue>,
    src_mac: Option<&'a FieldValue>,
    dst_mac: Option<&'a FieldValue>,
}

impl<'a> IPFixFieldCache<'a> {
    fn from_fields(fields: &'a [(IPFixField, FieldValue)]) -> Self {
        let mut cache = Self {
            src_addr_v4: None,
            src_addr_v6: None,
            dst_addr_v4: None,
            dst_addr_v6: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            first_seen: None,
            last_seen: None,
            src_mac: None,
            dst_mac: None,
        };

        // Single pass through all fields
        for (field_type, field_value) in fields {
            match field_type {
                IPFixField::IANA(IANAIPFixField::SourceIpv4address) => {
                    cache.src_addr_v4 = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::SourceIpv6address) => {
                    cache.src_addr_v6 = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::DestinationIpv4address) => {
                    cache.dst_addr_v4 = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::DestinationIpv6address) => {
                    cache.dst_addr_v6 = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::SourceTransportPort) => {
                    cache.src_port = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::DestinationTransportPort) => {
                    cache.dst_port = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::ProtocolIdentifier) => {
                    cache.protocol = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::FlowStartSysUpTime) => {
                    cache.first_seen = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::FlowEndSysUpTime) => {
                    cache.last_seen = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::SourceMacaddress) => {
                    cache.src_mac = Some(field_value)
                }
                IPFixField::IANA(IANAIPFixField::DestinationMacaddress) => {
                    cache.dst_mac = Some(field_value)
                }
                _ => {} // Ignore other fields
            }
        }

        cache
    }
}

/// Macro to check field mapping for types that need as_ref() for fallback comparison
macro_rules! check_field_mapping_ref {
    ($field_type:expr, $field_value:expr, $cache:expr, $config:expr, $field_name:ident) => {
        if *$field_type == $config.$field_name.primary {
            $cache.$field_name = Some($field_value);
        } else if $config.$field_name.fallback.as_ref() == Some($field_type)
            && $cache.$field_name.is_none()
        {
            $cache.$field_name = Some($field_value);
        }
    };
}

/// Helper structure to cache IPFIX field lookups with custom mapping in a single pass
#[derive(Copy, Clone)]
struct IPFixConfigFieldCache<'a> {
    src_addr: Option<&'a FieldValue>,
    dst_addr: Option<&'a FieldValue>,
    src_port: Option<&'a FieldValue>,
    dst_port: Option<&'a FieldValue>,
    protocol: Option<&'a FieldValue>,
    first_seen: Option<&'a FieldValue>,
    last_seen: Option<&'a FieldValue>,
    src_mac: Option<&'a FieldValue>,
    dst_mac: Option<&'a FieldValue>,
}

impl<'a> IPFixConfigFieldCache<'a> {
    fn from_fields_with_config(
        fields: &'a [(IPFixField, FieldValue)],
        config: &IPFixFieldMappingConfig,
    ) -> Self {
        let mut cache = Self {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            first_seen: None,
            last_seen: None,
            src_mac: None,
            dst_mac: None,
        };

        // Single pass through all fields, collecting based on config
        for (field_type, field_value) in fields {
            check_field_mapping_ref!(field_type, field_value, cache, config, src_addr);
            check_field_mapping_ref!(field_type, field_value, cache, config, dst_addr);
            check_field_mapping_ref!(field_type, field_value, cache, config, src_port);
            check_field_mapping_ref!(field_type, field_value, cache, config, dst_port);
            check_field_mapping_ref!(field_type, field_value, cache, config, protocol);
            check_field_mapping_ref!(field_type, field_value, cache, config, first_seen);
            check_field_mapping_ref!(field_type, field_value, cache, config, last_seen);
            check_field_mapping_ref!(field_type, field_value, cache, config, src_mac);
            check_field_mapping_ref!(field_type, field_value, cache, config, dst_mac);
        }

        cache
    }
}

impl NetflowCommon {
    /// Convert an IPFIX packet to NetflowCommon using a custom field mapping configuration.
    ///
    /// This allows you to specify which IPFIX fields should be used for each
    /// NetflowCommonFlowSet field, including fallback fields.
    ///
    /// # Example
    ///
    /// ```rust
    /// use netflow_parser::netflow_common::IPFixFieldMappingConfig;
    /// use netflow_parser::variable_versions::ipfix_lookup::{IPFixField, IANAIPFixField};
    ///
    /// // Use custom configuration that prefers IPv6
    /// let mut config = IPFixFieldMappingConfig::default();
    /// config.src_addr.primary = IPFixField::IANA(IANAIPFixField::SourceIpv6address);
    /// config.src_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::SourceIpv4address));
    ///
    /// // Then use: NetflowCommon::from_ipfix_with_config(&ipfix, &config);
    /// ```
    pub fn from_ipfix_with_config(value: &IPFix, config: &IPFixFieldMappingConfig) -> Self {
        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let IPFixFlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    // Single pass through fields to collect all values with config
                    let cache =
                        IPFixConfigFieldCache::from_fields_with_config(data_field, config);
                    flowsets.push(create_common_flowset!(cache));
                }
            }
        }

        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.export_time,
            flowsets,
        }
    }
}

impl From<&IPFix> for NetflowCommon {
    fn from(value: &IPFix) -> Self {
        // Convert IPFix to NetflowCommon with single-pass field lookup
        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let IPFixFlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    // Single pass through fields to collect all values
                    let cache = IPFixFieldCache::from_fields(data_field);
                    flowsets.push(create_common_flowset_with_ip_versions!(
                        cache,
                        src_addr_v4,
                        src_addr_v6,
                        dst_addr_v4,
                        dst_addr_v6
                    ));
                }
            }
        }

        NetflowCommon {
            version: value.header.version,
            timestamp: value.header.export_time,
            flowsets,
        }
    }
}

#[cfg(test)]
mod common_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::netflow_common::NetflowCommon;
    use crate::static_versions::v5::{FlowSet as V5FlowSet, Header as V5Header, V5};
    use crate::static_versions::v7::{FlowSet as V7FlowSet, Header as V7Header, V7};
    use crate::variable_versions::data_number::{DataNumber, FieldValue};
    use crate::variable_versions::ipfix::{
        Data as IPFixData, FlowSet as IPFixFlowSet, FlowSetBody as IPFixFlowSetBody,
        FlowSetHeader as IPFixFlowSetHeader, Header as IPFixHeader, IPFix,
    };
    use crate::variable_versions::ipfix_lookup::{IANAIPFixField, IPFixField};
    use crate::variable_versions::v9::{
        Data as V9Data, FlowSet as V9FlowSet, FlowSetBody as V9FlowSetBody,
        FlowSetHeader as V9FlowSetHeader, Header as V9Header, V9,
    };
    use crate::variable_versions::v9_lookup::V9Field;

    #[test]
    fn it_converts_v5_to_common() {
        let v5 = V5 {
            header: V5Header {
                version: 5,
                count: 1,
                sys_up_time: 100,
                unix_secs: 1609459200,
                unix_nsecs: 0,
                flow_sequence: 1,
                engine_type: 0,
                engine_id: 0,
                sampling_interval: 0,
            },
            flowsets: vec![V5FlowSet {
                src_addr: Ipv4Addr::new(192, 168, 1, 1),
                dst_addr: Ipv4Addr::new(192, 168, 1, 2),
                src_port: 1234,
                dst_port: 80,
                protocol_number: 6,
                protocol_type: crate::protocol::ProtocolTypes::Tcp,
                next_hop: Ipv4Addr::new(192, 168, 1, 254),
                input: 0,
                output: 0,
                d_pkts: 10,
                d_octets: 1000,
                first: 100,
                last: 200,
                pad1: 0,
                tcp_flags: 0,
                tos: 0,
                src_as: 0,
                dst_as: 0,
                src_mask: 0,
                dst_mask: 0,
                pad2: 0,
            }],
        };

        let common: NetflowCommon = NetflowCommon::from(&v5);

        assert_eq!(common.version, 5);
        assert_eq!(common.timestamp, 100);
        assert_eq!(common.flowsets.len(), 1);
        let flowset = &common.flowsets[0];
        assert_eq!(
            flowset.src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            flowset.dst_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(flowset.src_port.unwrap(), 1234);
        assert_eq!(flowset.dst_port.unwrap(), 80);
        assert_eq!(flowset.protocol_number.unwrap(), 6);
        assert_eq!(
            flowset.protocol_type.unwrap(),
            crate::protocol::ProtocolTypes::Tcp
        );
        assert_eq!(flowset.first_seen.unwrap(), 100);
        assert_eq!(flowset.last_seen.unwrap(), 200);
    }

    #[test]
    fn it_converts_v7_to_common() {
        let v7 = V7 {
            header: V7Header {
                version: 7,
                count: 1,
                sys_up_time: 100,
                unix_secs: 1609459200,
                unix_nsecs: 0,
                flow_sequence: 1,
                reserved: 0,
            },
            flowsets: vec![V7FlowSet {
                src_addr: Ipv4Addr::new(192, 168, 1, 1),
                dst_addr: Ipv4Addr::new(192, 168, 1, 2),
                src_port: 1234,
                dst_port: 80,
                protocol_number: 6,
                protocol_type: crate::protocol::ProtocolTypes::Tcp,
                next_hop: Ipv4Addr::new(192, 168, 1, 254),
                input: 0,
                output: 0,
                d_pkts: 10,
                d_octets: 1000,
                first: 100,
                last: 200,
                tcp_flags: 0,
                tos: 0,
                src_as: 0,
                dst_as: 0,
                src_mask: 0,
                dst_mask: 0,
                flags_fields_invalid: 0,
                flags_fields_valid: 0,
                router_src: Ipv4Addr::new(192, 168, 1, 254),
            }],
        };

        let common: NetflowCommon = NetflowCommon::from(&v7);

        assert_eq!(common.version, 7);
        assert_eq!(common.timestamp, 100);
        assert_eq!(common.flowsets.len(), 1);
        let flowset = &common.flowsets[0];
        assert_eq!(
            flowset.src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            flowset.dst_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(flowset.src_port.unwrap(), 1234);
        assert_eq!(flowset.dst_port.unwrap(), 80);
        assert_eq!(flowset.protocol_number.unwrap(), 6);
        assert_eq!(
            flowset.protocol_type.unwrap(),
            crate::protocol::ProtocolTypes::Tcp
        );
        assert_eq!(flowset.first_seen.unwrap(), 100);
        assert_eq!(flowset.last_seen.unwrap(), 200);
    }

    #[test]
    fn it_converts_v9_to_common() {
        // Test for V9 conversion
        let v9 = V9 {
            header: V9Header {
                version: 9,
                count: 1,
                sys_up_time: 100,
                unix_secs: 1609459200,
                sequence_number: 1,
                source_id: 0,
            },
            flowsets: vec![V9FlowSet {
                header: V9FlowSetHeader {
                    flowset_id: 0,
                    length: 0,
                },
                body: V9FlowSetBody::Data(V9Data {
                    padding: vec![],
                    fields: vec![Vec::from([
                        (
                            V9Field::Ipv4SrcAddr,
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                        ),
                        (
                            V9Field::Ipv4DstAddr,
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 2)),
                        ),
                        (
                            V9Field::L4SrcPort,
                            FieldValue::DataNumber(DataNumber::U16(1234)),
                        ),
                        (
                            V9Field::L4DstPort,
                            FieldValue::DataNumber(DataNumber::U16(80)),
                        ),
                        (V9Field::Protocol, FieldValue::DataNumber(DataNumber::U8(6))),
                        (
                            V9Field::FirstSwitched,
                            FieldValue::DataNumber(DataNumber::U32(100)),
                        ),
                        (
                            V9Field::LastSwitched,
                            FieldValue::DataNumber(DataNumber::U32(200)),
                        ),
                        (
                            V9Field::InSrcMac,
                            FieldValue::MacAddr("00:00:00:00:00:01".to_string()),
                        ),
                        (
                            V9Field::InDstMac,
                            FieldValue::MacAddr("00:00:00:00:00:02".to_string()),
                        ),
                    ])],
                }),
            }],
        };

        let common: NetflowCommon = NetflowCommon::from(&v9);
        assert_eq!(common.version, 9);
        assert_eq!(common.timestamp, 100);
        assert_eq!(common.flowsets.len(), 1);
        let flowset = &common.flowsets[0];
        assert_eq!(
            flowset.src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            flowset.dst_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(flowset.src_port.unwrap(), 1234);
        assert_eq!(flowset.dst_port.unwrap(), 80);
        assert_eq!(flowset.protocol_number.unwrap(), 6);
        assert_eq!(
            flowset.protocol_type.unwrap(),
            crate::protocol::ProtocolTypes::Tcp
        );
        assert_eq!(flowset.first_seen.unwrap(), 100);
        assert_eq!(flowset.last_seen.unwrap(), 200);
        assert_eq!(flowset.src_mac.as_ref().unwrap(), "00:00:00:00:00:01");
        assert_eq!(flowset.dst_mac.as_ref().unwrap(), "00:00:00:00:00:02");
    }

    #[test]
    fn it_converts_ipfix_to_common() {
        // Test for IPFix conversion
        let ipfix = IPFix {
            header: IPFixHeader {
                version: 10,
                length: 0,
                export_time: 100,
                sequence_number: 1,
                observation_domain_id: 0,
            },
            flowsets: vec![IPFixFlowSet {
                header: IPFixFlowSetHeader {
                    header_id: 0,
                    length: 0,
                },
                body: IPFixFlowSetBody::Data(IPFixData {
                    fields: vec![Vec::from([
                        (
                            IPFixField::IANA(IANAIPFixField::SourceIpv4address),
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::DestinationIpv4address),
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 2)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::SourceTransportPort),
                            FieldValue::DataNumber(DataNumber::U16(1234)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::DestinationTransportPort),
                            FieldValue::DataNumber(DataNumber::U16(80)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::ProtocolIdentifier),
                            FieldValue::DataNumber(DataNumber::U8(6)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::FlowStartSysUpTime),
                            FieldValue::DataNumber(DataNumber::U32(100)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::FlowEndSysUpTime),
                            FieldValue::DataNumber(DataNumber::U32(200)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::SourceMacaddress),
                            FieldValue::MacAddr("00:00:00:00:00:01".to_string()),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::DestinationMacaddress),
                            FieldValue::MacAddr("00:00:00:00:00:02".to_string()),
                        ),
                    ])],
                    padding: vec![],
                }),
            }],
        };

        let common: NetflowCommon = NetflowCommon::from(&ipfix);
        assert_eq!(common.version, 10);
        assert_eq!(common.timestamp, 100);
        assert_eq!(common.flowsets.len(), 1);
        let flowset = &common.flowsets[0];
        assert_eq!(
            flowset.src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            flowset.dst_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
        );
        assert_eq!(flowset.src_port.unwrap(), 1234);
        assert_eq!(flowset.dst_port.unwrap(), 80);
        assert_eq!(flowset.protocol_number.unwrap(), 6);
        assert_eq!(
            flowset.protocol_type.unwrap(),
            crate::protocol::ProtocolTypes::Tcp
        );
        assert_eq!(flowset.first_seen.unwrap(), 100);
        assert_eq!(flowset.last_seen.unwrap(), 200);
        assert_eq!(flowset.src_mac.as_ref().unwrap(), "00:00:00:00:00:01");
        assert_eq!(flowset.dst_mac.as_ref().unwrap(), "00:00:00:00:00:02");
    }

    #[test]
    fn it_converts_v9_to_common_with_custom_config() {
        use crate::netflow_common::V9FieldMappingConfig;
        use std::net::Ipv6Addr;

        // Create a V9 packet with both IPv4 and IPv6 addresses
        let v9 = V9 {
            header: V9Header {
                version: 9,
                count: 1,
                sys_up_time: 100,
                unix_secs: 1609459200,
                sequence_number: 1,
                source_id: 0,
            },
            flowsets: vec![V9FlowSet {
                header: V9FlowSetHeader {
                    flowset_id: 0,
                    length: 0,
                },
                body: V9FlowSetBody::Data(V9Data {
                    padding: vec![],
                    fields: vec![Vec::from([
                        (
                            V9Field::Ipv4SrcAddr,
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                        ),
                        (
                            V9Field::Ipv6SrcAddr,
                            FieldValue::Ip6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                        ),
                        (
                            V9Field::L4SrcPort,
                            FieldValue::DataNumber(DataNumber::U16(1234)),
                        ),
                    ])],
                }),
            }],
        };

        // Default config prefers IPv4
        let default_config = V9FieldMappingConfig::default();
        let common = NetflowCommon::from_v9_with_config(&v9, &default_config);
        assert_eq!(
            common.flowsets[0].src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        // Custom config that prefers IPv6
        let mut ipv6_config = V9FieldMappingConfig::default();
        ipv6_config.src_addr.primary = V9Field::Ipv6SrcAddr;
        ipv6_config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);

        let common_ipv6 = NetflowCommon::from_v9_with_config(&v9, &ipv6_config);
        assert_eq!(
            common_ipv6.flowsets[0].src_addr.unwrap(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn it_converts_ipfix_to_common_with_custom_config() {
        use crate::netflow_common::IPFixFieldMappingConfig;
        use std::net::Ipv6Addr;

        // Create an IPFIX packet with both IPv4 and IPv6 addresses
        let ipfix = IPFix {
            header: IPFixHeader {
                version: 10,
                length: 0,
                export_time: 100,
                sequence_number: 1,
                observation_domain_id: 0,
            },
            flowsets: vec![IPFixFlowSet {
                header: IPFixFlowSetHeader {
                    header_id: 0,
                    length: 0,
                },
                body: IPFixFlowSetBody::Data(IPFixData {
                    fields: vec![Vec::from([
                        (
                            IPFixField::IANA(IANAIPFixField::SourceIpv4address),
                            FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::SourceIpv6address),
                            FieldValue::Ip6Addr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                        ),
                        (
                            IPFixField::IANA(IANAIPFixField::SourceTransportPort),
                            FieldValue::DataNumber(DataNumber::U16(1234)),
                        ),
                    ])],
                    padding: vec![],
                }),
            }],
        };

        // Default config prefers IPv4
        let default_config = IPFixFieldMappingConfig::default();
        let common = NetflowCommon::from_ipfix_with_config(&ipfix, &default_config);
        assert_eq!(
            common.flowsets[0].src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );

        // Custom config that prefers IPv6
        let mut ipv6_config = IPFixFieldMappingConfig::default();
        ipv6_config.src_addr.primary = IPFixField::IANA(IANAIPFixField::SourceIpv6address);
        ipv6_config.src_addr.fallback =
            Some(IPFixField::IANA(IANAIPFixField::SourceIpv4address));

        let common_ipv6 = NetflowCommon::from_ipfix_with_config(&ipfix, &ipv6_config);
        assert_eq!(
            common_ipv6.flowsets[0].src_addr.unwrap(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn it_uses_fallback_when_primary_not_found() {
        use crate::netflow_common::V9FieldMappingConfig;

        // Create a V9 packet with only IPv6 address (no IPv4)
        let v9 = V9 {
            header: V9Header {
                version: 9,
                count: 1,
                sys_up_time: 100,
                unix_secs: 1609459200,
                sequence_number: 1,
                source_id: 0,
            },
            flowsets: vec![V9FlowSet {
                header: V9FlowSetHeader {
                    flowset_id: 0,
                    length: 0,
                },
                body: V9FlowSetBody::Data(V9Data {
                    padding: vec![],
                    fields: vec![Vec::from([(
                        V9Field::Ipv4SrcAddr,
                        FieldValue::Ip4Addr(Ipv4Addr::new(10, 0, 0, 1)),
                    )])],
                }),
            }],
        };

        // Config that prefers IPv6 but falls back to IPv4
        let mut config = V9FieldMappingConfig::default();
        config.src_addr.primary = V9Field::Ipv6SrcAddr;
        config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);

        let common = NetflowCommon::from_v9_with_config(&v9, &config);
        // Should fall back to IPv4 since IPv6 is not present
        assert_eq!(
            common.flowsets[0].src_addr.unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
