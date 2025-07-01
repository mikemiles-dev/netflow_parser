use std::collections::BTreeMap;
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
            _ => Err(NetflowCommonError::UnknownVersion(value.clone())),
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

impl From<&V9> for NetflowCommon {
    fn from(value: &V9) -> Self {
        // Convert V9 to NetflowCommon
        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let V9FlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    let value_map: BTreeMap<V9Field, FieldValue> =
                        data_field.values().cloned().collect();
                    flowsets.push(NetflowCommonFlowSet {
                        src_addr: value_map
                            .get(&V9Field::Ipv4SrcAddr)
                            .or_else(|| value_map.get(&V9Field::Ipv6SrcAddr))
                            .and_then(|v| v.try_into().ok()),
                        dst_addr: value_map
                            .get(&V9Field::Ipv4DstAddr)
                            .or_else(|| value_map.get(&V9Field::Ipv6DstAddr))
                            .and_then(|v| v.try_into().ok()),
                        src_port: value_map
                            .get(&V9Field::L4SrcPort)
                            .and_then(|v| v.try_into().ok()),
                        dst_port: value_map
                            .get(&V9Field::L4DstPort)
                            .and_then(|v| v.try_into().ok()),
                        protocol_number: value_map
                            .get(&V9Field::Protocol)
                            .and_then(|v| v.try_into().ok()),
                        protocol_type: value_map.get(&V9Field::Protocol).and_then(|v| {
                            v.try_into()
                                .ok()
                                .map(|proto: u8| ProtocolTypes::from(proto))
                        }),
                        first_seen: value_map
                            .get(&V9Field::FirstSwitched)
                            .and_then(|v| v.try_into().ok()),
                        last_seen: value_map
                            .get(&V9Field::LastSwitched)
                            .and_then(|v| v.try_into().ok()),
                        src_mac: value_map
                            .get(&V9Field::InSrcMac)
                            .and_then(|v| v.try_into().ok()),
                        dst_mac: value_map
                            .get(&V9Field::InDstMac)
                            .and_then(|v| v.try_into().ok()),
                    });
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

impl From<&IPFix> for NetflowCommon {
    fn from(value: &IPFix) -> Self {
        // Convert IPFix to NetflowCommon

        let mut flowsets = vec![];

        for flowset in &value.flowsets {
            if let IPFixFlowSetBody::Data(data) = &flowset.body {
                for data_field in &data.fields {
                    let value_map: BTreeMap<IPFixField, FieldValue> =
                        data_field.values().cloned().collect();
                    flowsets.push(NetflowCommonFlowSet {
                        src_addr: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::SourceIpv4address))
                            .or_else(|| {
                                value_map
                                    .get(&IPFixField::IANA(IANAIPFixField::SourceIpv6address))
                            })
                            .and_then(|v| v.try_into().ok()),
                        dst_addr: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::DestinationIpv4address))
                            .or_else(|| {
                                value_map.get(&IPFixField::IANA(
                                    IANAIPFixField::DestinationIpv6address,
                                ))
                            })
                            .and_then(|v| v.try_into().ok()),
                        src_port: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::SourceTransportPort))
                            .and_then(|v| v.try_into().ok()),
                        dst_port: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::DestinationTransportPort))
                            .and_then(|v| v.try_into().ok()),
                        protocol_number: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::ProtocolIdentifier))
                            .and_then(|v| v.try_into().ok()),
                        protocol_type: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::ProtocolIdentifier))
                            .and_then(|v| {
                                v.try_into()
                                    .ok()
                                    .map(|proto: u8| ProtocolTypes::from(proto))
                            }),
                        first_seen: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::FlowStartSysUpTime))
                            .and_then(|v| v.try_into().ok()),
                        last_seen: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::FlowEndSysUpTime))
                            .and_then(|v| v.try_into().ok()),
                        src_mac: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::SourceMacaddress))
                            .and_then(|v| v.try_into().ok()),
                        dst_mac: value_map
                            .get(&IPFixField::IANA(IANAIPFixField::DestinationMacaddress))
                            .and_then(|v| v.try_into().ok()),
                    });
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

    use std::collections::BTreeMap;
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

        let common: NetflowCommon = NetflowCommon::try_from(&v5).unwrap();

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

        let common: NetflowCommon = NetflowCommon::try_from(&v7).unwrap();

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
                    fields: vec![BTreeMap::from([
                        (
                            0,
                            (
                                V9Field::Ipv4SrcAddr,
                                FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                            ),
                        ),
                        (
                            1,
                            (
                                V9Field::Ipv4DstAddr,
                                FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 2)),
                            ),
                        ),
                        (
                            2,
                            (
                                V9Field::L4SrcPort,
                                FieldValue::DataNumber(DataNumber::U16(1234)),
                            ),
                        ),
                        (
                            3,
                            (
                                V9Field::L4DstPort,
                                FieldValue::DataNumber(DataNumber::U16(80)),
                            ),
                        ),
                        (
                            4,
                            (V9Field::Protocol, FieldValue::DataNumber(DataNumber::U8(6))),
                        ),
                        (
                            5,
                            (
                                V9Field::FirstSwitched,
                                FieldValue::DataNumber(DataNumber::U32(100)),
                            ),
                        ),
                        (
                            6,
                            (
                                V9Field::LastSwitched,
                                FieldValue::DataNumber(DataNumber::U32(200)),
                            ),
                        ),
                        (
                            7,
                            (
                                V9Field::InSrcMac,
                                FieldValue::MacAddr("00:00:00:00:00:01".to_string()),
                            ),
                        ),
                        (
                            8,
                            (
                                V9Field::InDstMac,
                                FieldValue::MacAddr("00:00:00:00:00:02".to_string()),
                            ),
                        ),
                    ])],
                }),
            }],
        };

        let common: NetflowCommon = NetflowCommon::try_from(&v9).unwrap();
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
                    fields: vec![BTreeMap::from([
                        (
                            0,
                            (
                                IPFixField::IANA(IANAIPFixField::SourceIpv4address),
                                FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 1)),
                            ),
                        ),
                        (
                            1,
                            (
                                IPFixField::IANA(IANAIPFixField::DestinationIpv4address),
                                FieldValue::Ip4Addr(Ipv4Addr::new(192, 168, 1, 2)),
                            ),
                        ),
                        (
                            2,
                            (
                                IPFixField::IANA(IANAIPFixField::SourceTransportPort),
                                FieldValue::DataNumber(DataNumber::U16(1234)),
                            ),
                        ),
                        (
                            3,
                            (
                                IPFixField::IANA(IANAIPFixField::DestinationTransportPort),
                                FieldValue::DataNumber(DataNumber::U16(80)),
                            ),
                        ),
                        (
                            4,
                            (
                                IPFixField::IANA(IANAIPFixField::ProtocolIdentifier),
                                FieldValue::DataNumber(DataNumber::U8(6)),
                            ),
                        ),
                        (
                            5,
                            (
                                IPFixField::IANA(IANAIPFixField::FlowStartSysUpTime),
                                FieldValue::DataNumber(DataNumber::U32(100)),
                            ),
                        ),
                        (
                            6,
                            (
                                IPFixField::IANA(IANAIPFixField::FlowEndSysUpTime),
                                FieldValue::DataNumber(DataNumber::U32(200)),
                            ),
                        ),
                        (
                            7,
                            (
                                IPFixField::IANA(IANAIPFixField::SourceMacaddress),
                                FieldValue::MacAddr("00:00:00:00:00:01".to_string()),
                            ),
                        ),
                        (
                            8,
                            (
                                IPFixField::IANA(IANAIPFixField::DestinationMacaddress),
                                FieldValue::MacAddr("00:00:00:00:00:02".to_string()),
                            ),
                        ),
                    ])],
                }),
            }],
        };

        let common: NetflowCommon = NetflowCommon::try_from(&ipfix).unwrap();
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
}
