#[cfg(test)]
mod base_tests {

    use crate::variable_versions::ipfix::{
        Template as IPFixTemplate, TemplateField as IPFixTemplateField,
    };
    use crate::variable_versions::v9::{
        Template as V9Template, TemplateField as V9TemplateField,
    };
    use crate::{NetflowPacket, NetflowParser};

    use hex;
    use insta::assert_yaml_snapshot;
    use std::collections::HashSet;

    #[test]
    fn it_parses_unix_timestamp_correctly() {
        use nom::number::complete::{be_u32, be_u64};
        use std::time::Duration;

        let packet = [5, 0, 6, 7, 8, 9, 0, 1];
        let (remain, secs1) =
            be_u32::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        let (remain, nsecs1) = be_u32::<&[u8], nom::error::Error<&[u8]>>(remain).unwrap();
        assert_eq!(remain, []);

        let time1 = Duration::from_nanos(nsecs1 as u64) + Duration::from_secs(secs1 as u64);

        let (remain, secs_nsecs) =
            be_u64::<&[u8], nom::error::Error<&[u8]>>(packet.as_slice()).unwrap();
        assert_eq!(remain, []);
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
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_allow_v5() {
        let packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let mut parser = NetflowParser::default();
        parser.allowed_versions = HashSet::default();
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v5_incomplete() {
        let packet = [0, 5, 0, 0, 1, 1, 1, 1];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v5_and_re_exports() {
        let packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        if let NetflowPacket::V5(v5) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(v5.to_be_bytes());
            assert_eq!(v5.to_be_bytes(), packet);
        }
    }

    #[test]
    fn it_creates_error() {
        let packet = [0, 9, 10, 11];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v7() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_allow_v7() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        let mut parser = NetflowParser::default();
        parser.allowed_versions = HashSet::default();
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v7_and_re_exports() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        if let NetflowPacket::V7(v7) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(v7.to_be_bytes());
            assert_eq!(v7.to_be_bytes(), packet);
        }
    }

    #[test]
    fn it_parses_v9() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_allow_v9() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
        ];
        let mut parser = NetflowParser::default();
        parser.allowed_versions = HashSet::default();
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_ipv6flowlabel() {
        let templates_hex = r#"0009000400a21e176658cb4600000155000000080000004c0102001100080004000c0004000f000400070002000b0002000a0002000e000200fc000400fd000400020004000100040016000400150004000400010005000101000002003d0001000000540103001300080004000c0004000f000400070002000b000200060001000a0002000e000200fc000400fd000400020004000100040016000400150004000400010005000100d1000801000002003d00010000005401050013001b0010001c0010003e001000070002000b000200060001000a0002000e000200fc000400fd00040002000400010004001600040015000400040001000500010050000601000002003d00010000005801060014001b0010001c0010003e0010001f000300070002000b000200060001000a0002000e000200fc000400fd00040002000400010004001600040015000400040001000500010050000601000002003d0001"#;
        let packets_hex = r#"0009000200a3a50e6658cbab000001640000000801020066c0a8120a8d180c0200000000c2c00035000200000000000000000000000000010000005200a31e7700a31e771100080001c0a8120a8d180c02000000009e230035000200000000000000000000000000010000005200a3197b00a3197b110008000101060063fd010008000000002a20235f1f7b9379fd00000000000000b2f208fffe2011800000000000000000000000000000000001f676e2b5003500000200000000000000000000000000010000006600a3197b00a3197b1100109027e0436d86dd01"#;
        let combined = format!("{}{}", templates_hex, packets_hex);
        let packets = hex::decode(combined).unwrap();
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packets));
    }

    #[test]
    fn it_parses_v9_and_re_exports() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
        ];
        if let NetflowPacket::V9(v9) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(v9.to_be_bytes().unwrap());
            assert_eq!(v9.to_be_bytes().unwrap(), packet);
        }
    }

    #[test]
    fn it_parses_v9_no_data() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 4,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_template_and_data_packet() {
        let hex = r#"000900090000cc99664728d80000000100000000000000480400001000080004000c000400160004001500040001000400020004000a0004000e0004003d00010088000100070002000b00020004000100060001003c000100050001000000400401000e00080004000c000400160004001500040001000400020004000a0004000e0004003d0001008800010020000200040001003c0001000500010000004808000010001b0010001c001000160004001500040001000400020004000a0004000e0004003d00010088000100070002000b00020004000100060001003c000100050001000000400801000e001b0010001c001000160004001500040001000400020004000a0004000e0004003d000100880001008b000200040001003c0001000500010001001a01000004000c000200040022000400230001005200100100001d000000000000000101616e7900000000000000000000000000080000cd200300d1ef3b2200fe3497fffeb7686e26064700303200000000000068155338000016050000a418000004bf0000000900000000000000000003e2d401bb0619060026064700303200000000000068155338200300d1ef3b2200fe3497fffeb7686e000016050000a418000000b4000000030000000000000000010301bbe2d406040600000000000000000000000000000000010000000000000000000000000000000100004f2c00004f2c0000003c00000001000000000000000000031f91aaea06140600000000040001009df0fb3dc0a801d700006308000076d500000b7200000018000000000000000000031466ac50061a0400c0a801d79df0fb3d00006308000076d500000e370000002100000000000000000103ac501466061e04005dd10e499df0fb3d00006308000076d6000004bd0000000b00000000000000000003ac501466061e04009df0fb3d5dd10e4900006308000076d6000005b90000000c000000000000000001031466ac50061a0400c0a80125c6fcce190000a9180000a9cd0000027b0000000900000000000000000003a34401bb06190400c6fcce19c0a801250000a9180000a9cd00000108000000060000000000000000010301bba34406150400"#;
        let packet = hex::decode(hex).unwrap();
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(feature = "parse_unknown_fields")]
    fn it_parses_multiple_packets() {
        let v9_packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
        ];
        let v7_packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        let v5_packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let ipfix_packet = [
            0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3, 2, 0, 2,
            0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let mut all = vec![];
        all.extend_from_slice(&v9_packet);
        all.extend_from_slice(&v5_packet);
        all.extend_from_slice(&v7_packet);
        all.extend_from_slice(&v9_packet);
        all.extend_from_slice(&ipfix_packet);
        all.extend_from_slice(&v5_packet);
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&all));
    }

    #[test]
    fn it_parses_v9_many_flows() {
        let packet = [
            0, 9, 0, 3, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2, 0,
            2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 20, 9, 2, 3, 4, 9, 9, 9, 8, 9, 2, 3, 4, 9, 9,
            9, 8,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_options_template() {
        let packet = [
            0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 22, 1, 19, 0,
            4, 0, 8, 0, 2, 0, 2, 0, 34, 0, 2, 0, 36, 0, 1, 1, 19, 0, 9, 0, 2, 0, 100, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_data_cached_template() {
        let packet = [
            0, 9, 0, 1, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 0, 12, 9, 2, 3,
            4, 9, 9, 9, 8,
        ];
        let fields = vec![
            V9TemplateField {
                field_type_number: 1,
                field_type: crate::variable_versions::v9_lookup::V9Field::InBytes,
                field_length: 4,
            },
            V9TemplateField {
                field_type_number: 8,
                field_type: crate::variable_versions::v9_lookup::V9Field::Ipv4SrcAddr,
                field_length: 4,
            },
        ];
        let template = V9Template {
            field_count: 2,
            template_id: 258,
            fields,
        };
        let mut parser = NetflowParser::default();
        parser.v9_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix() {
        let packet = [
            0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3, 2, 0, 2,
            0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_allow_ipfix() {
        let packet = [
            0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3, 2, 0, 2,
            0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        let mut parser = NetflowParser::default();
        parser.allowed_versions = HashSet::default();
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_and_re_exports() {
        let packet = [
            0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3, 2, 0, 2,
            0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        if let NetflowPacket::IPFix(ipfix) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(ipfix.to_be_bytes().unwrap());
            assert_eq!(ipfix.to_be_bytes().unwrap(), packet);
        }
    }

    #[test]
    fn it_parses_0_length_fields_ipfix() {
        let packet = [
            0, 10, 0, 48, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0, 8, 0,
            4, 0, 12, 0, 4, 0, 65, 0, 0, 1, 0, 0, 12, 1, 2, 3, 4, 1, 2, 3, 4,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_doesnt_panic_with_invalid_options_ipfix_template() {
        let packet = [
            0, 10, 0, 44, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 13, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0,
        ];
        NetflowParser::default().parse_bytes(&packet);
    }

    #[test]
    fn it_parses_ipfix_data_cached_template() {
        let packet = [
            0, 10, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let fields = vec![
            IPFixTemplateField {
                field_type_number: 2,
                field_type:
                    crate::variable_versions::ipfix_lookup::IPFixField::PacketDeltaCount,
                field_length: 2,
                enterprise_number: None,
            },
            IPFixTemplateField {
                field_type_number: 8,
                field_type:
                    crate::variable_versions::ipfix_lookup::IPFixField::SourceIpv4address,
                field_length: 4,
                enterprise_number: None,
            },
        ];
        let template = IPFixTemplate {
            field_count: 2,
            template_id: 258,
            fields,
            ..Default::default()
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_with_no_template_fields() {
        let packet = [
            0, 10, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let template = IPFixTemplate {
            field_count: 2,
            template_id: 258,
            ..Default::default()
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_raises_error_when_parsing_v9_with_no_template_fields() {
        let packet = [
            0, 9, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let template = V9Template {
            field_count: 2,
            template_id: 258,
            fields: vec![],
        };
        let mut parser = NetflowParser::default();
        parser.v9_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_with_multiple_options_data() {
        let hex = r#"00090026cfe9ee444b4f72ba0146d3ce000000000000005c0100001500150004001600040001000400020004000a0002000e000200080004000c0004000400010005000100070002000b00020030000100330001000f0004000d00010009000100060001003d00010011000200100002000000540102001300150004001600040001000400020004000a0002000e000200080004000c0004000400010005000100070002000b00020030000100330001000f0004000d00010009000100060001003d00010001002c01010014000c0001000400020004000300040004000400050004002a000400290004002200040000010001e4cfea00f0cfea0094000007d3000057c5000400020a0000570c00006706a00eb812b900360a0000241c05160000c00017cfea00f0cfea0094000007d300002cf7000400020a00002a0c0000be11c0cd9451a500f20a00000907091100005e0077cfea00f0cfea0094000007d30000c42d000400020a0000620c00000a010070fc917a00b70a0000550c161100004500b6cfea00f0cfea0094000007d300004268000400020a00001d0c0000d90610d3037c9400870a0000361214180000030003cfea00f0cfea0094000007d300000efc000400020a0000090c00003e01a05eb7df0700230a000028151d0400002e003ecfea00f0cfea0094000007d30000f36a000400020a00002e0c00009511a04645c8f8005f0a000059040c1b0000c10014cfea00f0cfea0094000007d300003800000400020a00002d0c00009111a07cd085b0008b0a00003e131c1000004600b8cfea00f0cfea0094000007d300004945000400020a00001b0c0000c401a077ef88e5009a0a0000451d021000003e00a3cfea00f0cfea0094000007d300008479000400020a00003a0c0000b711c0b837c8f4005f0a000059040c1b0000c20006cfea00f0cfea0094000007d300001d1e000400020a0000110c00007a0610b0afd42e007a0a00003811151100004c007f010001e4cfea00f0cfea0094000007d300010bc4000400020a0000110c00007e06108c85965d00b80a00004f0a1c1000004200c6cfea00f0cfea0094000007d3000009a6000400020a0000040c00001901c08e5090d000b20a0000540e110200008e00afcfea00f0cfea0094000007d300007244000400020a0000400c0000e501c082408428008f0a000039151a1a00006b0078cfea00f0cfea0094000007d30000c6ed000400020a0000640c0000020100093a19f4002a0a0000320f0f02000066006acfea00f0cfea0094000007d30000a056000400020a00003d0c0000af110031e5526c00f70a00000b050f02000067006ecfea00f0cfea0094000007d30000ae95000400020a00004b0c0000c101a05cdee51300290a00003011111b0000ac0055cfea00f0cfea0094000007d30000d569000400020a0000560c00006a11a04644c914005f0a000058040c1b0000be0011cfea00f0cfea0094000007d3000044f9000400020a00001f0c0000d00610bb6fc328004f0a0000520d121b0000980033cfea00f0cfea0094000007d30000e6b4000400020a00001e0c0000de0610ecf2317a00530a00006003041a00009200a1cfea00f0cfea0094000007d3000065fe000400020a0000620c00000b0100667fa99c00fd0a00000301031000005a0074010001e4cfea00f0cfea0094000007d30000dcb2000400020a00004e0c00004c11c0ac5ef45f001b0a0000120e121b0000c20013cfea00f0cfea0094000007d300003387000400020a0000310c0000840610bda6bf9300430a00004d09191a0000680070cfea00f0cfea0094000007d30000a9e3000400020a0000460c0000d6061093b8bba100c70a00001d1a0c1b00009d0047cfea00f0cfea0094000007d30001141d000400020a0000160c000058110048fcd902006d0a0000481a0c1b0000a10045cfea00f0cfea0094000007d30001209a000400020a0000040c00001901c08a339c1800a70a00005b06091100004e0088cfea00f0cfea0094000007d300011f4c000400020a00000b0c00002d0610a8cafba700020a0000030103100000520093cfea00f0cfea0094000007d30000ef5b000400020a0000220c0000fa01003be54c3900d40a00003210100200008200b9cfea00f0cfea0094000007d3000046ae000400020a00001b0c0000cd06a00f0a131100370a0000231c07160000a70063cfea00f0cfea0094000007d300009833000400020a0000360c0000880610fa1d0544000d0a00000907091100005f006ccfea00f0cfea0094000007d30000ba2b000400020a00003f0c0000df01c0a630e74e003a0a000020190d0200008b00a8010100a400000064000000c80000012c00000190000001f43c66c4a30202610a0000006400000064000000c80000012c00000190000001f43c66c4a30202610a0000006400000064000000c80000012c00000190000001f43c66c4a30202610a0000006400000064000000c80000012c00000190000001f43c66c4a30202610a0000006400000064000000c80000012c00000190000001f43c66c4a30202610a00000064"#;
        let packet = hex::decode(hex).unwrap();
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_options_template() {
        let packet = [
            0, 10, 0, 44, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 3, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_options_template_with_data() {
        let packet = [
            0, 10, 0, 64, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 0, 28, 1, 4, 0, 3, 0, 1,
            128, 123, 0, 4, 0, 0, 0, 2, 0, 41, 0, 2, 0, 42, 0, 2, 0, 0, 1, 4, 0, 20, 0, 0, 0,
            1, 1, 20, 20, 20, 0, 0, 0, 2, 20, 20, 30, 30,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_enterprise_bit_in_non_options_template() {
        let packet = [
            0, 10, 0, 42, 99, 138, 252, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 26, 1, 4, 0, 2,
            128, 103, 255, 255, 24, 77, 128, 103, 255, 255, 0, 0, 24, 77, 129, 64, 0, 4, 0, 0,
            24, 77,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_enterprise_bit_template_and_data() {
        let template_packet = [
            0x00, 0x0a, 0x00, 0xf4, 0x5b, 0x3b, 0x54, 0x85, 0x00, 0x00, 0x86, 0xc7, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x02, 0x00, 0xe4, 0x01, 0x0c, 0x00, 0x22, 0xaf, 0xcc, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x09, 0xaf, 0xcd, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xaf, 0xd0,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0xaf, 0xd1, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09,
            0x00, 0xea, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00, 0xef, 0x00, 0x01, 0xaf, 0xd2,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00, 0x5f, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04,
            0x00, 0x30, 0x00, 0x01, 0xa4, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x25,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x8d, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09,
            0xaf, 0xcb, 0xff, 0xff, 0x00, 0x00, 0x00, 0x09, 0x00, 0x16, 0x00, 0x04, 0x00, 0x15,
            0x00, 0x04, 0x01, 0x16, 0x00, 0x04, 0x00, 0xe8, 0x00, 0x08, 0x01, 0x2b, 0x00, 0x08,
            0x00, 0xe7, 0x00, 0x08, 0x01, 0x2a, 0x00, 0x08, 0xa4, 0x57, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x09, 0xa4, 0x4c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x54, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x09, 0xa4, 0x67, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x64,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x34, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09,
            0xa4, 0x61, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x5a, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x09, 0xa4, 0x5b, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x5d, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x09, 0xa4, 0x39, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, 0xa4, 0x38,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x09,
        ];
        let data_packet = [
            0x00, 0x0a, 0x00, 0xbc, 0x5b, 0x3b, 0x54, 0x7c, 0x00, 0x00, 0x86, 0xc6, 0x00, 0x00,
            0x03, 0x00, 0x01, 0x0c, 0x00, 0xac, 0x0a, 0xd1, 0x65, 0x42, 0x0a, 0x00, 0x00, 0xf1,
            0xc0, 0xe0, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x8d,
            0xc3, 0x3f, 0xe0, 0x03, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x0a, 0x09, 0x10, 0x00,
            0x0b, 0x2f, 0x44, 0x6f, 0x63, 0x4c, 0x69, 0x62, 0x31, 0x00, 0x00, 0x01, 0x1a, 0x03,
            0x00, 0x00, 0x50, 0x34, 0x02, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x2e, 0x6d, 0x65,
            0x64, 0x73, 0x69, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2e, 0x72, 0x75, 0x21, 0xa0, 0xe2,
            0x7b, 0x21, 0xa2, 0x97, 0xbe, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut parser = NetflowParser::default();
        let mut result = parser.parse_bytes(&template_packet);
        result.append(&mut parser.parse_bytes(&data_packet));
        assert_yaml_snapshot!(result);
    }

    #[test]
    fn it_parses_ipfix_scappy_example() {
        let hex_template = r#"000a0074583de05700000ecf00000000000200640133001700080004000c0004000500010004000100070002000b000200200002000a0004001000040011000400120004000e000400010004000200040016000400150004000f000400090001000d000100060001003c00010098000800990008"#;
        let packet = hex::decode(hex_template).unwrap();
        let mut parser = NetflowParser::default();
        let mut result = parser.parse_bytes(&packet);
        let hex_data = r#"000a0060583de05900000ee400000000013300504601730132004701003d0000000000000000033b0000000200000003cc2a6e65000003560000052000000009b3f906eeb3fbaf3ccc2a6ebd1818000400000158b1b138ff00000158b1b3e14d"#;
        let packet = hex::decode(hex_data).unwrap();
        result.append(&mut parser.parse_bytes(&packet));
        assert_yaml_snapshot!(result);
    }

    #[test]
    fn it_parses_ipfix_scappy_example_options_template() {
        let hex_template = r#"000a0028583de05700000ecf00000000000300180134000300010005000200240002002500020000"#;
        let packet = hex::decode(hex_template).unwrap();
        let mut parser = NetflowParser::default();
        let result = parser.parse_bytes(&packet);
        assert_yaml_snapshot!(result);
    }

    #[test]
    fn it_parses_ipfix_with_v9_options_template_packet() {
        let hex = r#"000a00736800a129000186a0000000000001000e04e8000100060022000404e80008000000010002002c0102000900080004000c000400070002000b00020004000100020004000100040016000400150004010200214646010178780101303980090600000064077359406800a1296800a129"#;
        let packet = hex::decode(hex).unwrap();
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_mixed_enteprise_and_non_enterprise_fields() {
        let hex_template = r#"000a00845b3b5496005e9d61000004000002007401080016afcc000400000009afcd0004000000090004000100c3000100c00001afd100020000000900ea0004005f0004003a0002000a000400ef0001a424000100000009000e0004a4250001000000090016000400150004011600040117000800e80008012b000800e70008012a0008"#;
        let packet = hex::decode(hex_template).unwrap();
        let mut parser = NetflowParser::default();
        let mut result = parser.parse_bytes(&packet);
        let hex_data = r#"000a05745b3b5424005e996700000400010805640a65ff010a0a1c391100ff0807000000000d00025e00000000000001100000001400ef92fb5cef93cb9400000000000000000000003500000000000000000000000000000000000000000002eff9000000000000009bac1fff01ac1fff011100fe0ec9000000000d00000100000000000101100000000100ef92fb60ef93e4040000000000000000000000780000000000000000000000000000000000000000000008a000000000000000b80ad016760a6516fb11043d44f6000000000d00000100000000000101100000000400ef92fb64ef93be3400000000000000000000003b00000000000000000000000000000000000000000000006000000000000000060a0097dc0a65975f11003cdffb000000000d00000100000000000101100000000400ef92fbaaef93e4fa00000000000000000000003b000000000000000000000000000000000000000000003ba000000000000000180a6516fb0a19161211007e1389000000000d00000100000000000401100000001400ef92fbaeef93e4c000000000000000000000003b0000000000000000000000000000000000000000000016f0000000000000016fe0000005ac1fff015900010000000000000100005900000000000102100000000000ef92fbe0ef93dbb60000000000000000000000500000000000000000000000000000001700000000000000000000000000000000ac1ffe65ac1ffe651130ff0ec9000000000d00000100000000000001100000000100ef92fc52ef93e50000000000000000000000003c000000000000000000000000000000000000000000000ee8000000000000013ee0000005ac1ffafc5930010000000000000100005901220000001402100000000000ef92fc5cef93db9c00000000000000000000000000000000000000000000000000000007000000000000000000000000000000000ad0160d0a6516fb11043d44f6000000000d00000100000000000101100000000400ef92fc5eef93bf1a0000000000000000000000320000000000000000000000000000000000000000000002e40000000000000041e0000005ac1ffe1b5930010000000000000100005900000000000102100000000000ef92fc66ef93d6ee00000000000000000000000000000000000000000000000000000007000000000000000000000000000000000a6466740acd970911007d0d3d000000000d00000101220000001402100000001100ef92fcacef93c48a0000000000000000000000ef00000000000000e10000000000000008000000000000006000000000000000080ad0167c0a6516fb11043d44f6000000000d00000100000000000101100000000400ef92fcc8ef93bf9a00000000000000000000003b0000000000000000000000000000000000000000000000600000000000000006ac1ffe65ac1ffe011130ff0ec8000000000d00000100000000000001100000000100ef92fcecef93df3e00000000000000000000003c00000000000000000000000000000000000000000000022800000000000000170a01162f0a6516fb11083d44f6000000000d00000100000000000101100000000400ef92fcf8ef93c00e00000000000000000000003200000000000000000000000000000000000000000000030400000000000000430a650a0c0a0097b301003c0000000000000d0001df00000000000102100000000400ef92fd0eef93e2320000000000000000000000000000000000000000000000000000001300000000000000000000000000000000ac1fff01ac1ffe651100ff0ec8000000000d00000100000000000101100000000000ef92fd34ef93e3ac00000000000000000000003b0000000000000000000000000000000000000000000006600000000000000044"#;
        let packet = hex::decode(hex_data).unwrap();
        result.append(&mut parser.parse_bytes(&packet));
        assert_yaml_snapshot!(result);
    }

    #[test]
    fn it_parses_v9_empty_template_doesntz_panic() {
        let packet = vec![
            0, 9, 0, 49, 0, 8, 0, 0, 9, 0, 0, 20, 0, 24, 24, 24, 24, 91, 0, 0, 0, 0, 0, 9, 1,
            0, 0, 0, 0, 1, 0, 0, 0, 24, 0,
        ];
        NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap();
    }
}
