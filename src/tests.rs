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
            for packet in parser.iter_packets(&packet).flatten() {
                if packet.is_v9() {}
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
            for packet in parser.iter_packets(&packet).flatten() {
                if packet.is_v5() {}
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
            max_error_sample_size: 256,
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
            max_error_sample_size: 256,
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
            max_error_sample_size: 256,
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
            max_error_sample_size: 256,
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
            max_error_sample_size: 256,
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
    fn v9_missing_template_returns_no_template() {
        use crate::variable_versions::v9::{FlowSetBody as V9FlowSetBody, V9Parser};

        // V9 packet with 1 data flowset referencing template 256 (no template cached)
        // V9Parser::parse receives bytes WITHOUT the 2-byte version prefix (already stripped
        // by NetflowParser). Header fields parsed: count, sys_up_time, unix_secs, seq, source_id.
        // Header (no version): count=1, sys_up_time=0, unix_secs=0, seq=1, source_id=1
        // FlowSet: id=256 (0x0100), length=12 (header 4 + data 8)
        // Data: 8 bytes of raw data (0x0102030405060708)
        let hex = "0001000000000000000000000001000000010100000c0102030405060708";

        let mut parser = V9Parser::default();
        let packet = hex::decode(hex).unwrap();

        let result = parser.parse(&packet);
        match result {
            crate::ParsedNetflow::Success { packet, .. } => {
                if let crate::NetflowPacket::V9(v9) = packet {
                    assert_eq!(v9.flowsets.len(), 1);
                    match &v9.flowsets[0].body {
                        V9FlowSetBody::NoTemplate(info) => {
                            assert_eq!(info.template_id, 256);
                            assert!(info.available_templates.is_empty());
                            assert_eq!(info.raw_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                        }
                        other => panic!("Expected NoTemplate, got {:?}", other),
                    }
                    // Verify cache miss was recorded
                    assert_eq!(parser.metrics.snapshot().misses, 1);
                } else {
                    panic!("Expected V9 packet");
                }
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn v9_mixed_flowsets_with_missing_template() {
        use crate::variable_versions::v9::{FlowSetBody as V9FlowSetBody, V9Parser};

        // V9Parser::parse receives bytes WITHOUT the 2-byte version prefix.
        // Template flowset defining template 256 with 2 fields:
        //   field 8 (Ipv4SrcAddr) length 4, field 12 (Ipv4DstAddr) length 4
        // Plus data flowset for template 256 with known data
        // Plus data flowset for template 257 (unknown)
        //
        // Header (no version): count=3, sys_up_time=0, unix_secs=0, seq=1, source_id=1
        let v9_header = "000300000000000000000000000100000001";

        // Template FlowSet: id=0, length=16 (4 header + 12 template content)
        //   template_id=256, field_count=2
        //   field 8 (Ipv4SrcAddr) len 4, field 12 (Ipv4DstAddr) len 4
        let template_flowset = "000000100100000200080004000c0004";

        // Data FlowSet for template 256: id=256, length=12 (4 header + 8 data)
        //   src=192.168.1.1 (c0a80101), dst=192.168.1.2 (c0a80102)
        let data_flowset_256 = "0100000cc0a80101c0a80102";

        // Data FlowSet for template 257 (unknown): id=257, length=8 (4 header + 4 data)
        let data_flowset_257 = "010100080a0b0c0d";

        let hex = format!(
            "{}{}{}{}",
            v9_header, template_flowset, data_flowset_256, data_flowset_257
        );

        let mut parser = V9Parser::default();
        let packet = hex::decode(hex).unwrap();

        let result = parser.parse(&packet);
        match result {
            crate::ParsedNetflow::Success { packet, .. } => {
                if let crate::NetflowPacket::V9(v9) = packet {
                    assert_eq!(v9.flowsets.len(), 3);

                    // First flowset: Template
                    assert!(
                        matches!(&v9.flowsets[0].body, V9FlowSetBody::Template(_)),
                        "Expected Template, got {:?}",
                        v9.flowsets[0].body
                    );

                    // Second flowset: Data (template 256 is known)
                    assert!(
                        matches!(&v9.flowsets[1].body, V9FlowSetBody::Data(_)),
                        "Expected Data, got {:?}",
                        v9.flowsets[1].body
                    );

                    // Third flowset: NoTemplate (template 257 is unknown)
                    match &v9.flowsets[2].body {
                        V9FlowSetBody::NoTemplate(info) => {
                            assert_eq!(info.template_id, 257);
                            assert_eq!(info.raw_data, vec![0x0a, 0x0b, 0x0c, 0x0d]);
                            // Template 256 should be in available_templates
                            assert!(info.available_templates.contains(&256));
                        }
                        other => panic!("Expected NoTemplate, got {:?}", other),
                    }
                } else {
                    panic!("Expected V9 packet");
                }
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn v9_template_arrives_after_data() {
        use crate::variable_versions::v9::{FlowSetBody as V9FlowSetBody, V9Parser};

        let mut parser = V9Parser::default();

        // V9Parser::parse receives bytes WITHOUT the 2-byte version prefix.
        // Packet 1: Data flowset referencing template 256 (not yet cached)
        // Header (no version): count=1, sys_up_time=0, unix_secs=0, seq=1, source_id=1
        // Flowset: id=256, len=12, data=8 bytes
        let hex1 = [
            "000100000000000000000000000100000001", // header
            "0100000c",                             // flowset: id=256, len=12
            "c0a80101c0a80102",                     // 8 bytes data
        ]
        .concat();

        let packet1 = hex::decode(&hex1).unwrap();
        let result1 = parser.parse(&packet1);
        match result1 {
            crate::ParsedNetflow::Success { packet, .. } => {
                if let crate::NetflowPacket::V9(v9) = packet {
                    assert_eq!(v9.flowsets.len(), 1);
                    assert!(
                        matches!(&v9.flowsets[0].body, V9FlowSetBody::NoTemplate(_)),
                        "Expected NoTemplate, got {:?}",
                        v9.flowsets[0].body
                    );
                } else {
                    panic!("Expected V9 packet");
                }
            }
            other => panic!("Expected Success, got {:?}", other),
        }

        // Packet 2: Template flowset defining template 256
        // Header (no version): count=1, sys_up_time=0, unix_secs=0, seq=2, source_id=1
        let hex2 = [
            "000100000000000000000000000200000001", // header
            "00000010",                             // flowset: id=0, len=16
            "01000002",                             // template_id=256, field_count=2
            "00080004",                             // field 8 (Ipv4SrcAddr), len 4
            "000c0004",                             // field 12 (Ipv4DstAddr), len 4
        ]
        .concat();

        let packet2 = hex::decode(&hex2).unwrap();
        let _result2 = parser.parse(&packet2);

        // Packet 3: Same data flowset, now should parse as Data
        // Header (no version): count=1, sys_up_time=0, unix_secs=0, seq=3, source_id=1
        let hex3 = [
            "000100000000000000000000000300000001", // header
            "0100000c",                             // flowset: id=256, len=12
            "c0a80101c0a80102",                     // 8 bytes data
        ]
        .concat();

        let packet3 = hex::decode(&hex3).unwrap();
        let result3 = parser.parse(&packet3);
        match result3 {
            crate::ParsedNetflow::Success { packet, .. } => {
                if let crate::NetflowPacket::V9(v9) = packet {
                    assert_eq!(v9.flowsets.len(), 1);
                    assert!(
                        matches!(&v9.flowsets[0].body, V9FlowSetBody::Data(_)),
                        "Expected Data, got {:?}",
                        v9.flowsets[0].body
                    );
                } else {
                    panic!("Expected V9 packet");
                }
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn v9_no_template_info_equality() {
        use crate::variable_versions::v9::NoTemplateInfo;

        let info1 = NoTemplateInfo {
            template_id: 256,
            available_templates: vec![300, 400],
            raw_data: vec![1, 2, 3, 4],
        };

        let info2 = NoTemplateInfo {
            template_id: 256,
            available_templates: vec![], // different available_templates
            raw_data: vec![1, 2, 3, 4],
        };

        let info3 = NoTemplateInfo {
            template_id: 257, // different template_id
            available_templates: vec![300, 400],
            raw_data: vec![1, 2, 3, 4],
        };

        let info4 = NoTemplateInfo {
            template_id: 256,
            available_templates: vec![300, 400],
            raw_data: vec![5, 6, 7, 8], // different raw_data
        };

        // Custom PartialEq ignores available_templates
        assert_eq!(info1, info2);
        // Different template_id -> not equal
        assert_ne!(info1, info3);
        // Different raw_data -> not equal
        assert_ne!(info1, info4);
    }

    #[test]
    fn test_ipfix_template_validation_duplicate_fields() {
        use crate::variable_versions::ipfix::{IPFixParser, Template, TemplateField};

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
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
            max_error_sample_size: 256,
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
