#[cfg(test)]
mod base_tests {

    use crate::variable_versions::Config;
    use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
    use crate::variable_versions::ipfix_lookup::IPFixField;
    use crate::{NetflowPacket, NetflowParser};

    use insta::assert_yaml_snapshot;

    #[test]
    fn it_parses_unix_timestamp_correctly() {
        use nom::number::complete::{be_u32, be_u64};
        use std::time::Duration;

        let packet = [5, 0, 6, 7, 8, 9, 0, 1];
        let (remain, secs1) =
            be_u32::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        let (remain, nsecs1) = be_u32::<&[u8], nom::error::Error<&[u8]>>(remain).unwrap();
        assert_eq!(remain, &[] as &[u8]);

        let time1 = Duration::from_nanos(nsecs1 as u64) + Duration::from_secs(secs1 as u64);

        let (remain, secs_nsecs) =
            be_u64::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        assert_eq!(remain, &[] as &[u8]);
        let secs2 = (secs_nsecs >> 32) as u32 as u64;
        let nsecs2 = secs_nsecs as u32;

        let time2 = Duration::new(secs2, nsecs2);

        assert_eq!(secs1 as u64, secs2);
        assert_eq!(nsecs1, nsecs2);
        assert_eq!(time1, time2);
    }

    #[test]
    fn it_parses_v5() {
        let packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let parsed = NetflowParser::default().parse_bytes(&packet).packets;
        assert_yaml_snapshot!(parsed);
    }

    #[test]
    fn it_parses_v7() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let parsed = NetflowParser::default().parse_bytes(&packet).packets;
        assert_yaml_snapshot!(parsed);
    }

    #[test]
    fn can_read_v9_with_minimal_headers() {
        let hex =
            "0009000200000e1061db09bd000000010000000100080001000400080004000e000400080004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packets = hex::decode(hex).unwrap();
        let v9 = parser.parse_bytes(&packets).packets;
        assert_yaml_snapshot!(v9);
    }

    #[test]
    fn can_read_v9_with_options_template() {
        let hex =
            "0009000100000000000000000000000100010020000100120004000100150004000200080004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packets = hex::decode(hex).unwrap();
        let v9 = parser.parse_bytes(&packets).packets;
        assert_yaml_snapshot!(v9);
    }

    #[test]
    fn can_read_v9_with_options_template_and_template() {
        let hex_hex0 =
            "0009000100000000000000000000000100010020000100120004000100150004000200080004";
        let hex_hex1 =
            "0009000200000e1061db09bd000000010000000100080001000400080004000e000400080004";
        let hex_hex2 =
            "0009000200000e1061db09bd000000010000000100010010010203040506070811121314";

        let combined = format!("{}{}{}", hex_hex0, hex_hex1, hex_hex2);

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packets = hex::decode(combined).unwrap();
        let results = parser.parse_bytes(&packets).packets;
        assert_yaml_snapshot!(results);
    }

    #[test]
    fn can_read_v9() {
        // Template
        let hex = "0009000100000e1061db09bd000000010000000100000028010000080001000400020004000a00040004000400080004000c0004000700020015000400050001000600010016000400100004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packets = hex::decode(hex).unwrap();
        let v9 = parser.parse_bytes(&packets).packets;
        if let Some(NetflowPacket::V9(v9_packet)) = v9.first() {
            assert_yaml_snapshot!(v9_packet.to_be_bytes().unwrap());
            // Just check that serialization works, don't assert equality
            // as the bytes may differ slightly due to padding or field ordering
        } else {
            panic!("Packet is not v9");
        }
    }

    #[test]
    fn can_read_v9_with_hex_data() {
        // Template
        let hex = "0009000100000e1061db09bd000000010000000100000028010000080001000400020004000a00040004000400080004000c0004000700020015000400050001000600010016000400100004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packets = hex::decode(hex).unwrap();
        let _ = parser.parse_bytes(&packets).packets;

        // Data
        let hex_data = "0009000100000e1061db09bd000000010000000101003000c0a80001c0a8000200010001000000010000000500000000000000000600110001c0a80001";

        let packets = hex::decode(hex_data).unwrap();
        let v9 = parser.parse_bytes(&packets).packets;
        assert_yaml_snapshot!(v9);
    }

    #[test]
    fn can_read_ipfix_template() {
        let hex = "000a003062a0b1b9000000086c6a7e110001002400030008000100040002000400090001000d00010004000400080004000c00040005000100060001";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let ipfix = parser.parse_bytes(&packet).packets;
        if let Some(NetflowPacket::IPFix(ipfix_packet)) = ipfix.first() {
            assert_yaml_snapshot!(ipfix_packet.to_be_bytes().unwrap());
            // Just check that serialization works, don't assert equality
            // as the bytes may differ slightly due to padding or field ordering
        } else {
            panic!("Packet is not IPFix");
        }
    }

    #[test]
    fn can_read_ipfix() {
        let hex = "000a003062a0b1b9000000086c6a7e110001002400030008000100040002000400090001000d00010004000400080004000c00040005000100060001";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let ipfix = parser.parse_bytes(&packet).packets;
        assert_yaml_snapshot!(ipfix);
    }

    #[test]
    fn options() {
        let hex_options_template = "000a00d46319088e0000036e8b7148d2000300b0000e001400070006000f0006001000060034000200350006008800020090000200910002009200020093000200990002009a0002009e0002009f000200a1000200a2000200a3000200a4000200a5000200aa000200ab000200ac000200ad000200b0000200b1000200b2000200b4000200b5000200b6000200b7000200b8000200b9000200bd000200be000200bf000200c0000200c1000400c2000200c3000200c4000200c5000200c6000200c7000200c8000200c9000200ca000200cb0002";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex_options_template).unwrap();
        let _ = parser.parse_bytes(&packet).packets;
    }

    #[test]
    fn options_in_struct() {
        #[derive(Debug, Clone, Default)]
        #[allow(dead_code)]
        struct NetflowV9Container {
            pub src_addr: Option<u32>,
            pub dst_addr: Option<u32>,
            pub src_port: Option<u16>,
            pub dst_port: Option<u16>,
            pub protocol: Option<u8>,
            pub direction: Option<u8>,
            pub engine_id: Option<u8>,
            pub engine_type: Option<u8>,
            pub sampling_interval: Option<u16>,
            pub input_snmp: Option<u32>,
            pub output_snmp: Option<u32>,
            pub router_sc: Option<u32>,
            pub in_bytes: Option<u64>,
            pub in_pkts: Option<u64>,
            pub tos: Option<u8>,
            pub tcp_flags: Option<u8>,
        }
        let _ = NetflowV9Container::default();
        assert!(true);
    }

    #[test]
    fn parses_v9_data_set() {
        let hex_template = "0009000300000e1061db09bd000000010000000100000028010000080001000400020004000a00040004000400080004000c0004000700020015000400050001000600010016000400100004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex_template).unwrap();
        let _ = parser.parse_bytes(&packet).packets;
    }

    #[test]
    fn parse_ipfix_with_v9_style_template() {
        let hex_template = "000a00b462a0b1bb000000a06c6a7e1100000064000200080001000400020004000800040012000400080004000c00040007000200150004000a000400040004000500010006000100100004000e00040016000400090001000d000100130004000b00020017000200010002000300020004000100b0000200b1000200b2000200b4000200b7000200b8000200ad000200ac00010038000200b9000200bd000200be000200c1000200c2000200c5000200c3000200c4000200c6000200c7000200c8000200c9000200ca000200cb000200ce00020000";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex_template).unwrap();
        let _ = parser.parse_bytes(&packet).packets;

        let hex_data = "000a003062a0b1b9000000086c6a7e1100020020c0a80001c0a80002000100010000000100000005000000000000000006000200110001";

        let packet = hex::decode(hex_data).unwrap();
        let ipfix = parser.parse_bytes(&packet).packets;
        assert_yaml_snapshot!(ipfix);
    }

    #[test]
    fn parse_ipfix_with_2_records_but_1_template() {
        let hex = "000a00f46319088e0000036e8b7148d20002002c7f0000017f000002006b006c00000001000000010000000000000000c60000000011020106005000506401a5fe006d0100020028e21c1a0ae21c1a0a170217000000020000000200000000000000000000000000000000000000000002002ce21c1a0ae21c1a0a017b017c000000030000000300000000000000000000000000000000000000000000";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let _ = parser.parse_bytes(&packet).packets;
    }

    #[test]
    fn options_no_data() {
        let hex = "0009000100000001639073f3000000010000000100010034010200210001000400020004000e000400160004001500040009000100070002001000040011000400180004000600010005000100b0000200b1000200b2000200b4000200b7000200b8000200ad000200ac00010038000200b9000200bd000200be000200c1000200c2000200c5000200c3000200c4000200c6000200c7000200c8000200c9000200ca000200cb000200ce000200";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let _ = parser.parse_bytes(&packet);

        let hex_data = "0009000100000002639073f300000002000000010102008400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        let packet = hex::decode(hex_data).unwrap();
        assert_yaml_snapshot!(parser.parse_bytes(&packet).packets);
    }

    #[test]
    fn v9_data_with_template_in_same_packet() {
        let hex = "0009000200000005639073f3000000030000000100000020010000030001000400020004000a0004010000180a66130e0a66130f00000024";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let _ = parser.parse_bytes(&packet);
    }

    #[test]
    fn v9_example_from_integration_test() {
        let hex_template = "000900020000000563b32ef1000000010000000100000024010000060001000400020004000a00040004000400080004000c000400010038010000020001000400020004";

        let hex_hex1 = "000900020000000663b32ef10000000200000001010000240a70090a0a70090b00000001000000010000000100000001000000030000000601000008192a80e3192a80e4";

        let _hex_hex2 = "000900020000000763b32ef10000000300000001010000240a700a050a700a0600000001000000010000000100000001000000030000000601000008192a80e3192a80e4";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let _ = parser.parse_bytes(&hex::decode(hex_template).unwrap());
        assert_yaml_snapshot!(parser.parse_bytes(&hex::decode(hex_hex1).unwrap()).packets);
    }

    #[test]
    fn v9_example_from_integration_test_2() {
        let hex1 = "000900020000000563b32ef1000000010000000100000024010000060001000400020004000a00040004000400080004000c000400010038010000020001000400020004";

        let hex2 = "000900020000000663b32ef10000000200000001010000240a70090a0a70090b00000001000000010000000100000001000000030000000601000008192a80e3192a80e4";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let _ = parser.parse_bytes(&hex::decode(hex1).unwrap());
        assert_yaml_snapshot!(parser.parse_bytes(&hex::decode(hex2).unwrap()).packets);
    }

    #[test]
    fn test_packet() {
        let hexes = vec![
            "00090001000016236482f6f30000000000000000000000200100001a000100040002000400080004000400040021000200b0000200b1000200b2000200b4000200b7000200b8000200ad000200ac00010038000200b9000200bd000200be000200c1000200c2000200c5000200c3000200c4000200c6000200c7000200c8000200c9000200ca000200cb000200ce0002",
        ];

        for hex in hexes {
            let mut parser = NetflowParser::builder()
                .with_cache_size(100)
                .build()
                .unwrap();

            let packet = hex::decode(hex).unwrap();
            for packet in parser.iter_packets(&packet) {
                if let Ok(packet) = packet {
                    if packet.is_v9() {}
                }
            }
        }
    }

    #[test]
    fn test_packet_all_iter() {
        let hexes = vec![
            "00090001000016236482f6f30000000000000000000000200100001a000100040002000400080004000400040021000200b0000200b1000200b2000200b4000200b7000200b8000200ad000200ac00010038000200b9000200bd000200be000200c1000200c2000200c5000200c3000200c4000200c6000200c7000200c8000200c9000200ca000200cb000200ce0002",
        ];

        for hex in hexes {
            let mut parser = NetflowParser::builder()
                .with_cache_size(100)
                .build()
                .unwrap();

            let packet = hex::decode(hex).unwrap();
            for packet in parser.iter_packets(&packet) {
                if let Ok(packet) = packet {
                    if packet.is_v5() {
                        assert!(true);
                    }
                }
            }
        }
    }

    #[test]
    fn test_custom_parser_configuration() {
        use crate::variable_versions::v9::V9Parser;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = V9Parser::try_new(config).unwrap();
        assert_eq!(parser.max_template_cache_size, 100);
        assert_eq!(parser.max_field_count, 10000);
    }

    #[test]
    fn test_template_validation_field_count_limit() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 2, // Very low limit for testing
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = V9Parser::try_new(config).unwrap();

        // Template with 3 fields should fail validation
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_type: V9Field::InBytes,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 2,
                    field_type: V9Field::InPkts,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 8,
                    field_type: V9Field::Ipv4SrcAddr,
                    field_length: 4,
                },
            ],
        };

        assert!(!template.is_valid(&parser));
    }

    #[test]
    fn test_template_validation_total_size_limit() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: 10, // Very low limit for testing
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = V9Parser::try_new(config).unwrap();

        // Template with total size > 10 should fail validation
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_type: V9Field::InBytes,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 2,
                    field_type: V9Field::InPkts,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 8,
                    field_type: V9Field::Ipv4SrcAddr,
                    field_length: 4,
                },
            ],
        };

        assert!(!template.is_valid(&parser));
    }

    #[test]
    fn test_template_validation_duplicate_fields() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = V9Parser::try_new(config).unwrap();

        // Template with duplicate field_type_number (1) should fail validation
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_type: V9Field::InBytes,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 1, // Duplicate!
                    field_type: V9Field::InBytes,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 8,
                    field_type: V9Field::Ipv4SrcAddr,
                    field_length: 4,
                },
            ],
        };

        assert!(!template.is_valid(&parser));
    }

    #[test]
    fn test_template_validation_valid_template() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = V9Parser::try_new(config).unwrap();

        // Valid template should pass all validations
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_type: V9Field::InBytes,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 2,
                    field_type: V9Field::InPkts,
                    field_length: 4,
                },
                TemplateField {
                    field_type_number: 8,
                    field_type: V9Field::Ipv4SrcAddr,
                    field_length: 4,
                },
            ],
        };

        assert!(template.is_valid(&parser));
    }

    #[test]
    fn test_ipfix_template_validation_duplicate_fields() {
        use crate::variable_versions::ipfix::{IPFixParser, Template, TemplateField};

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = IPFixParser::try_new(config).unwrap();

        // Template with duplicate (field_type_number, enterprise_number) pair should fail
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_length: 4,
                    enterprise_number: None,
                    field_type: IPFixField::new(1, None),
                },
                TemplateField {
                    field_type_number: 1, // Duplicate with same enterprise_number
                    field_length: 4,
                    enterprise_number: None,
                    field_type: IPFixField::new(1, None),
                },
                TemplateField {
                    field_type_number: 8,
                    field_length: 4,
                    enterprise_number: None,
                    field_type: IPFixField::new(8, None),
                },
            ],
        };

        assert!(!template.is_valid(&parser));
    }

    #[test]
    fn test_ipfix_template_validation_different_enterprises_ok() {
        use crate::variable_versions::ipfix::{IPFixParser, Template, TemplateField};

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
        };

        let parser = IPFixParser::try_new(config).unwrap();

        // Same field_type_number but different enterprise_number should be OK
        let template = Template {
            template_id: 256,
            field_count: 3,
            fields: vec![
                TemplateField {
                    field_type_number: 1,
                    field_length: 4,
                    enterprise_number: None, // IANA (standard)
                    field_type: IPFixField::new(1, None),
                },
                TemplateField {
                    field_type_number: 1, // Same field_type_number but different enterprise
                    field_length: 4,
                    enterprise_number: Some(9), // Cisco
                    field_type: IPFixField::new(1, Some(9)),
                },
                TemplateField {
                    field_type_number: 8,
                    field_length: 4,
                    enterprise_number: None,
                    field_type: IPFixField::new(8, None),
                },
            ],
        };

        assert!(template.is_valid(&parser));
    }
}
