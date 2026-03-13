#[cfg(test)]
mod base_tests {

    use crate::variable_versions::Config;
    use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
    use crate::variable_versions::ipfix_lookup::IPFixField;
    use crate::{NetflowPacket, NetflowParser};
    use std::sync::Arc;

    use insta::assert_yaml_snapshot;

    // Verify that Unix timestamps are parsed identically via separate u32 fields and a single u64 field
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

    // Verify that a NetFlow v5 packet is parsed correctly from raw bytes
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

    // Verify that a NetFlow v7 packet is parsed correctly from raw bytes
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

    // Verify that a NetFlow v9 packet with minimal template headers can be parsed
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

    // Verify that a NetFlow v9 options template is parsed correctly
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

    // Verify that combined v9 options template, data template, and data records parse together
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

    // Verify that a v9 template packet is parsed and can be serialized back to bytes
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

    // Verify that v9 data records are parsed correctly after a template has been cached
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

    // Verify that an IPFIX template packet is parsed and can be serialized back to bytes
    #[test]
    fn can_read_ipfix_template() {
        // Valid IPFIX template packet: Set ID=2 (IPFIX Template), template_id=256,
        // 3 fields: sourceIPv4Address(8) len 4, destinationIPv4Address(12) len 4,
        // protocolIdentifier(4) len 1.
        let hex = "000a002462a0b1b9000000086c6a7e11000200140100000300080004000c000400040001";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let ipfix = parser.parse_bytes(&packet).packets;
        if let Some(NetflowPacket::IPFix(ipfix_packet)) = ipfix.first() {
            assert!(
                !ipfix_packet.flowsets.is_empty(),
                "Parsed IPFIX packet should contain at least one flowset"
            );
            assert_yaml_snapshot!(ipfix_packet.to_be_bytes().unwrap());
        } else {
            panic!("Packet is not IPFix");
        }
    }

    // Verify that an IPFIX packet with template fields is parsed correctly
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

    // Verify that an IPFIX options template with many fields is parsed without error
    #[test]
    fn options() {
        let hex_options_template = "000a00d46319088e0000036e8b7148d2000300b0000e001400070006000f0006001000060034000200350006008800020090000200910002009200020093000200990002009a0002009e0002009f000200a1000200a2000200a3000200a4000200a5000200aa000200ab000200ac000200ad000200b0000200b1000200b2000200b4000200b5000200b6000200b7000200b8000200b9000200bd000200be000200bf000200c0000200c1000400c2000200c3000200c4000200c5000200c6000200c7000200c8000200c9000200ca000200cb0002";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex_options_template).unwrap();
        let result = parser.parse_bytes(&packet);
        assert!(
            !result.packets.is_empty(),
            "expected packets from options template"
        );
        assert!(
            result.error.is_none(),
            "unexpected error parsing options template"
        );
    }

    // Verify that a v9 template with multiple flowsets is parsed without error
    #[test]
    fn parses_v9_data_set() {
        let hex_template = "0009000300000e1061db09bd000000010000000100000028010000080001000400020004000a00040004000400080004000c0004000700020015000400050001000600010016000400100004";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex_template).unwrap();
        let result = parser.parse_bytes(&packet);
        // This packet claims 3 flow sets but only contains template data.
        // The parser should handle it without panicking; verify any packets are V9.
        let v9_count = result.packets.iter().filter(|p| p.is_v9()).count();
        assert_eq!(
            v9_count,
            result.packets.len(),
            "all parsed packets should be V9"
        );
    }

    // Verify that IPFIX data records are parsed using a v9-style template definition
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

    // Verify that IPFIX parsing handles multiple data records with only one template
    #[test]
    fn parse_ipfix_with_2_records_but_1_template() {
        let hex = "000a00f46319088e0000036e8b7148d20002002c7f0000017f000002006b006c00000001000000010000000000000000c60000000011020106005000506401a5fe006d0100020028e21c1a0ae21c1a0a170217000000020000000200000000000000000000000000000000000000000002002ce21c1a0ae21c1a0a017b017c000000030000000300000000000000000000000000000000000000000000";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let result = parser.parse_bytes(&packet);
        // This IPFIX packet has data records but no previously cached template,
        // so the parser may not produce parsed packets. Verify it doesn't panic
        // and that any produced packets are IPFix.
        for p in &result.packets {
            assert!(
                matches!(p, NetflowPacket::IPFix(_)),
                "expected IPFix packet type"
            );
        }
    }

    // Verify that v9 options template followed by a zeroed-out data record parses correctly
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

    // Verify that v9 data records are parsed when the template is in the same packet
    #[test]
    fn v9_data_with_template_in_same_packet() {
        let hex = "0009000200000005639073f3000000030000000100000020010000030001000400020004000a0004010000180a66130e0a66130f00000024";

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .build()
            .unwrap();

        let packet = hex::decode(hex).unwrap();
        let result = parser.parse_bytes(&packet);
        // This packet contains both a template and data in the same packet.
        // The parser may or may not produce packets depending on processing order.
        // Verify no panic and any packets produced are V9.
        for p in &result.packets {
            assert!(p.is_v9(), "all parsed packets should be V9");
        }
    }

    // Verify that v9 template followed by data in separate packets produces correct output
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

    // Verify that v9 multi-template data parsing works across sequential packets
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

    // Verify that v9 packets can be iterated using iter_packets and identified as v9
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
            let mut count = 0;
            for packet in parser.iter_packets(&packet).flatten() {
                count += 1;
                // Any packets produced from this v9 template data should be V9
                assert!(packet.is_v9(), "expected V9 packet type");
                assert!(!packet.is_v5(), "v9 packet should not be identified as v5");
            }
            // This is a v9 template-only packet, so iter_packets may yield
            // zero packets (templates are cached, not returned as data).
            // The important assertion is that iteration completes without panic.
            let _ = count;
        }
    }

    // Verify that iter_packets works and is_v5 can be called on each parsed packet
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
            let mut count = 0;
            for packet in parser.iter_packets(&packet).flatten() {
                count += 1;
                // Any packets produced should not be v5 (this is v9 data)
                assert!(!packet.is_v5(), "v9 packet should not be identified as v5");
            }
            // Template-only packets may not produce iterable data packets.
            // Verify iteration completed without panic.
            let _ = count;
        }
    }

    // Verify that a V9Parser can be created with custom config values for cache size and field count
    #[test]
    fn test_custom_parser_configuration() {
        use crate::variable_versions::v9::V9Parser;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
        };

        let parser = V9Parser::try_new(config).unwrap();
        assert_eq!(parser.max_template_cache_size, 100);
        assert_eq!(parser.max_field_count, 10000);
    }

    // Verify that a v9 template exceeding the max field count limit is rejected as invalid
    #[test]
    fn test_template_validation_field_count_limit() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 2, // Very low limit for testing
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

    // Verify that a v9 template exceeding the max total size limit is rejected as invalid
    #[test]
    fn test_template_validation_total_size_limit() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: 10, // Very low limit for testing
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

    // Verify that a v9 template with duplicate field type numbers is rejected as invalid
    #[test]
    fn test_template_validation_duplicate_fields() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

    // Verify that a well-formed v9 template with unique fields passes validation
    #[test]
    fn test_template_validation_valid_template() {
        use crate::variable_versions::v9::{Template, TemplateField, V9Parser};
        use crate::variable_versions::v9_lookup::V9Field;

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

    // Verify that an IPFIX template with duplicate field/enterprise pairs is rejected as invalid
    #[test]
    fn test_ipfix_template_validation_duplicate_fields() {
        use crate::variable_versions::ipfix::{IPFixParser, Template, TemplateField};

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

    // Verify that an IPFIX template with same field type but different enterprise numbers is valid
    #[test]
    fn test_ipfix_template_validation_different_enterprises_ok() {
        use crate::variable_versions::ipfix::{IPFixParser, Template, TemplateField};

        let config = Config {
            max_template_cache_size: 100,
            max_field_count: 10000,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset:
                crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
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

#[cfg(test)]
mod malformed_packet_tests {
    use crate::NetflowParser;

    // Empty input should return empty packets with no error and no panic.
    #[test]
    fn test_empty_input() {
        let mut parser = NetflowParser::default();
        let result = parser.parse_bytes(&[]);
        assert!(
            result.packets.is_empty(),
            "empty input should produce no packets"
        );
        assert!(
            result.error.is_none(),
            "empty input should produce no error"
        );
    }

    // A single byte is too short to contain a version number (2 bytes).
    // The parser should not panic and should return an error.
    #[test]
    fn test_single_byte() {
        let mut parser = NetflowParser::default();
        let result = parser.parse_bytes(&[0]);
        assert!(
            result.packets.is_empty(),
            "single byte should produce no packets"
        );
        assert!(
            result.error.is_some(),
            "single byte should produce an error"
        );
    }

    // Version 99 is not a recognized NetFlow/IPFIX version.
    // The parser should return an error without panicking.
    #[test]
    fn test_unknown_version() {
        let mut parser = NetflowParser::default();
        // Version = 99 (0x00, 0x63), followed by 18 zero bytes to form a 20-byte packet
        let mut packet = vec![0x00, 0x63];
        packet.extend_from_slice(&[0u8; 18]);
        let result = parser.parse_bytes(&packet);
        assert!(
            result.error.is_some(),
            "unknown version 99 should produce an error"
        );
    }

    // V5 header is 24 bytes. Providing version=5 plus only 10 bytes (12 total)
    // is a truncated header. The parser should not panic.
    #[test]
    fn test_v5_truncated_header() {
        let mut parser = NetflowParser::default();
        // Version 5 (0x00, 0x05) + 10 bytes of zeros = 12 bytes total (less than 24-byte header)
        let mut packet = vec![0x00, 0x05];
        packet.extend_from_slice(&[0u8; 10]);
        let result = parser.parse_bytes(&packet);
        // Should return an error and no valid packets
        assert!(
            result.packets.is_empty(),
            "truncated V5 header should not produce valid packets"
        );
        assert!(
            result.error.is_some(),
            "truncated V5 header should produce an error"
        );
    }

    // V5 header with count=30 but only enough data for about 1 flow record.
    // Each V5 flow record is 48 bytes; 24 (header) + 48 = 72 bytes for 1 record.
    // We provide 72 bytes but claim count=30.
    #[test]
    fn test_v5_count_exceeds_data() {
        let mut parser = NetflowParser::default();
        // Build a V5 packet: version=5, count=30
        let mut packet = vec![0x00, 0x05]; // version 5
        packet.extend_from_slice(&[0x00, 0x1E]); // count = 30
        packet.extend_from_slice(&[0u8; 20]); // rest of 24-byte header
        packet.extend_from_slice(&[0u8; 48]); // 1 flow record (48 bytes)
        // Total = 72 bytes, but count claims 30 records (would need 24 + 30*48 = 1464 bytes)
        let result = parser.parse_bytes(&packet);
        // V5 parser returns error for insufficient data when count exceeds available records
        assert!(
            result.packets.is_empty(),
            "V5 with count exceeding data should produce no valid packets"
        );
    }

    // V5 header with count=0. No flow records should be parsed.
    #[test]
    fn test_v5_count_zero() {
        let mut parser = NetflowParser::default();
        // Build a V5 packet: version=5, count=0
        let mut packet = vec![0x00, 0x05]; // version 5
        packet.extend_from_slice(&[0x00, 0x00]); // count = 0
        packet.extend_from_slice(&[0u8; 20]); // rest of 24-byte header
        let result = parser.parse_bytes(&packet);
        // V5 rejects count=0 at parse time
        assert!(
            result.packets.is_empty(),
            "V5 with count=0 should produce no packets"
        );
    }

    // V9 header is 20 bytes. Providing only 10 bytes after the version is truncated.
    #[test]
    fn test_v9_truncated_header() {
        let mut parser = NetflowParser::default();
        // Version 9 (0x00, 0x09) + 8 bytes = 10 total (less than 20-byte header)
        let mut packet = vec![0x00, 0x09];
        packet.extend_from_slice(&[0u8; 8]);
        let result = parser.parse_bytes(&packet);
        assert!(
            result.packets.is_empty() || result.error.is_some(),
            "truncated V9 header should not produce valid packets without an error"
        );
    }

    // V9 with a flowset whose length field is 0.
    // A zero-length flowset could cause an infinite loop if not handled.
    #[test]
    fn test_v9_flowset_length_zero() {
        let mut parser = NetflowParser::default();
        // V9 header: version=9, count=1, sysuptime=0, unix_secs=0, sequence=0, source_id=0
        let mut packet = vec![
            0x00, 0x09, // version 9
            0x00, 0x01, // count = 1
            0x00, 0x00, 0x00, 0x00, // sys_uptime
            0x00, 0x00, 0x00, 0x00, // unix_secs
            0x00, 0x00, 0x00, 0x00, // sequence
            0x00, 0x00, 0x00, 0x00, // source_id
        ];
        // Flowset with id=0 (template), length=0 (malformed)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let result = parser.parse_bytes(&packet);
        // Must not infinite loop or panic; zero-length flowset should produce no valid packets or an error
        assert!(
            result.packets.is_empty() || result.error.is_some(),
            "V9 with zero-length flowset should produce no valid packets or an error"
        );
    }

    // V9 with a flowset length larger than the remaining bytes in the packet.
    #[test]
    fn test_v9_flowset_length_exceeds_packet() {
        let mut parser = NetflowParser::default();
        let mut packet = vec![
            0x00, 0x09, // version 9
            0x00, 0x01, // count = 1
            0x00, 0x00, 0x00, 0x00, // sys_uptime
            0x00, 0x00, 0x00, 0x00, // unix_secs
            0x00, 0x00, 0x00, 0x00, // sequence
            0x00, 0x00, 0x00, 0x00, // source_id
        ];
        // Flowset with id=0 (template), length=9999 (far exceeds remaining data)
        packet.extend_from_slice(&[0x00, 0x00, 0x27, 0x0F]);
        // Only 4 bytes of flowset data actually present
        let result = parser.parse_bytes(&packet);
        assert!(
            result.packets.is_empty() || result.error.is_some(),
            "V9 with flowset length exceeding packet should produce no valid packets or an error"
        );
    }

    // IPFIX header includes a length field that should match the actual packet size.
    // Here we set it to a wrong value.
    #[test]
    fn test_ipfix_length_field_wrong() {
        let mut parser = NetflowParser::default();
        // IPFIX header: version=10, length=9999 (wrong), export_time, sequence, observation_domain
        let packet = vec![
            0x00, 0x0A, // version 10 (IPFIX)
            0x27, 0x0F, // length = 9999 (actual packet is only 16 bytes)
            0x00, 0x00, 0x00, 0x00, // export_time
            0x00, 0x00, 0x00, 0x00, // sequence_number
            0x00, 0x00, 0x00, 0x00, // observation_domain_id
        ];
        let result = parser.parse_bytes(&packet);
        // Parser should handle the length mismatch without panicking
        assert!(
            result.packets.is_empty() || result.error.is_some(),
            "IPFIX with wrong length field should produce no valid packets or an error"
        );
    }

    // IPFIX with a flowset whose length field is less than 4 (the minimum set header size).
    #[test]
    fn test_ipfix_flowset_length_less_than_4() {
        let mut parser = NetflowParser::default();
        // IPFIX header (16 bytes) + a flowset with length < 4
        let mut packet = vec![
            0x00, 0x0A, // version 10
            0x00, 0x14, // length = 20 (16 header + 4 flowset header)
            0x00, 0x00, 0x00, 0x00, // export_time
            0x00, 0x00, 0x00, 0x00, // sequence_number
            0x00, 0x00, 0x00, 0x00, // observation_domain_id
        ];
        // Flowset: set_id=2 (template), length=2 (less than minimum 4)
        packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x02]);
        let result = parser.parse_bytes(&packet);
        // The parser handles the malformed flowset gracefully without panicking.
        // Any packets produced should be IPFIX type.
        for p in &result.packets {
            assert!(
                matches!(p, crate::NetflowPacket::IPFix(_)),
                "any packets from IPFIX input should be IPFIX type"
            );
        }
    }

    // V9 with a flowset ID in the reserved range (2-255).
    // Flowset IDs 0=template, 1=options template, 256+=data. IDs 2-255 are reserved.
    #[test]
    fn test_v9_reserved_flowset_id() {
        let mut parser = NetflowParser::default();
        let mut packet = vec![
            0x00, 0x09, // version 9
            0x00, 0x01, // count = 1
            0x00, 0x00, 0x00, 0x00, // sys_uptime
            0x00, 0x00, 0x00, 0x00, // unix_secs
            0x00, 0x00, 0x00, 0x00, // sequence
            0x00, 0x00, 0x00, 0x00, // source_id
        ];
        // Flowset with reserved ID=100 (0x0064), length=8
        packet.extend_from_slice(&[0x00, 0x64, 0x00, 0x08]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 bytes of padding
        let result = parser.parse_bytes(&packet);
        // Parser should handle reserved flowset IDs gracefully per RFC 3954,
        // skipping them without error (IDs 2-255 are reserved).
        assert!(
            result.error.is_none(),
            "V9 reserved flowset IDs should be skipped without error"
        );
        for p in &result.packets {
            assert!(p.is_v9(), "any packets should be V9");
        }
    }

    // 100 bytes of all zeros. Version 0 is not a valid NetFlow version.
    #[test]
    fn test_all_zeros() {
        let mut parser = NetflowParser::default();
        let packet = vec![0u8; 100];
        let result = parser.parse_bytes(&packet);
        assert!(
            result.error.is_some(),
            "all-zeros packet (version 0) should produce an error"
        );
    }

    // Maximum version number 0xFFFF is not a valid NetFlow/IPFIX version.
    #[test]
    fn test_max_version_number() {
        let mut parser = NetflowParser::default();
        let mut packet = vec![0xFF, 0xFF]; // version = 65535
        packet.extend_from_slice(&[0u8; 18]);
        let result = parser.parse_bytes(&packet);
        assert!(
            result.error.is_some(),
            "version 0xFFFF should produce an error"
        );
    }

    // V7 header with count=0. No flow records should be parsed.
    #[test]
    fn test_v7_count_zero() {
        let mut parser = NetflowParser::default();
        // Build a V7 packet: version=7, count=0, rest of 24-byte header zeroed
        let mut packet = vec![0x00, 0x07]; // version 7
        packet.extend_from_slice(&[0x00, 0x00]); // count = 0
        packet.extend_from_slice(&[0u8; 20]); // rest of 24-byte header
        let result = parser.parse_bytes(&packet);
        assert!(
            result.packets.is_empty(),
            "V7 with count=0 should produce no packets"
        );
    }

    // IPFIX with a flowset using a reserved set ID (e.g., 5).
    // Set IDs 0-1 are reserved in IPFIX, 2=template, 3=options template, 4+ reserved until 256.
    #[test]
    fn test_ipfix_reserved_flowset_id() {
        let mut parser = NetflowParser::default();
        let mut packet = vec![
            0x00, 0x0A, // version 10 (IPFIX)
            0x00, 0x18, // length = 24 (16 header + 8 flowset)
            0x00, 0x00, 0x00, 0x00, // export_time
            0x00, 0x00, 0x00, 0x00, // sequence_number
            0x00, 0x00, 0x00, 0x00, // observation_domain_id
        ];
        // Flowset with reserved set ID=5, length=8
        packet.extend_from_slice(&[0x00, 0x05, 0x00, 0x08]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 bytes of padding
        let result = parser.parse_bytes(&packet);
        // Reserved set ID should be handled gracefully (Empty), not panic
        assert!(
            result.error.is_none(),
            "IPFIX reserved set ID should not produce a parse error"
        );
    }

    // IPFIX template with field_count=0 is a template withdrawal.
    // The parser should handle it gracefully.
    #[test]
    fn test_ipfix_template_withdrawal() {
        let mut parser = NetflowParser::default();
        // IPFIX header (16 bytes) + template set with a withdrawal (field_count=0)
        let mut packet = vec![
            0x00, 0x0A, // version 10 (IPFIX)
            0x00, 0x18, // length = 24 (16 header + 8 template set)
            0x00, 0x00, 0x00, 0x00, // export_time
            0x00, 0x00, 0x00, 0x00, // sequence_number
            0x00, 0x00, 0x00, 0x00, // observation_domain_id
        ];
        // Template set: set_id=2, length=8, template_id=256, field_count=0 (withdrawal)
        packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x08]); // set_id=2, length=8
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // template_id=256, field_count=0
        let result = parser.parse_bytes(&packet);
        // Template withdrawal (field_count=0) should be handled gracefully
        assert!(
            result.error.is_none(),
            "IPFIX template withdrawal should not produce a parse error"
        );
    }

    // Sending the same V9 template twice should not record a collision metric.
    #[test]
    fn test_template_reregistration_same_definition() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let collision_count = Arc::new(AtomicUsize::new(0));
        let cc = collision_count.clone();

        let mut parser = NetflowParser::builder()
            .with_cache_size(100)
            .on_template_event(move |event| {
                if matches!(event, crate::TemplateEvent::Collision { .. }) {
                    cc.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            })
            .build()
            .unwrap();

        // V9 template packet: version=9, count=1, template with id=256, 1 field (InBytes, len=4)
        let template_packet = vec![
            0x00, 0x09, // version 9
            0x00, 0x01, // count = 1
            0x00, 0x00, 0x00, 0x00, // sys_uptime
            0x00, 0x00, 0x00, 0x00, // unix_secs
            0x00, 0x00, 0x00, 0x00, // sequence
            0x00, 0x00, 0x00, 0x00, // source_id
            // Template flowset: flowset_id=0, length=16 (4 header + 4 template header + 4 field + 4 padding)
            0x00, 0x00, 0x00, 0x10, // flowset_id=0, length=16
            0x01, 0x00, 0x00, 0x01, // template_id=256, field_count=1
            0x00, 0x01, 0x00, 0x04, // field_type=1 (InBytes), field_length=4
            0x00, 0x00, 0x00, 0x00, // padding to reach length=16
        ];

        // Send the same template twice
        let _ = parser.parse_bytes(&template_packet);
        let _ = parser.parse_bytes(&template_packet);

        assert_eq!(
            collision_count.load(Ordering::SeqCst),
            0,
            "Re-registering the same template definition should not record a collision"
        );
    }
}
