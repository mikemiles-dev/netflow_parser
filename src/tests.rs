#[cfg(test)]
mod base_tests {

    use crate::variable_versions::ipfix::{
        Template as IPFixTemplate, TemplateField as IPFixTemplateField,
    };
    use crate::variable_versions::v9::{
        Template as V9Template, TemplateField as V9TemplateField,
    };
    use crate::{NetflowPacketResult, NetflowParser};

    use hex;
    use insta::assert_yaml_snapshot;

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
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v5() {
        let packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v5_and_re_exports() {
        let packet = [
            0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        if let NetflowPacketResult::V5(v5) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(v5.to_be_bytes());
            assert_eq!(v5.to_be_bytes(), packet);
        }
    }

    #[test]
    #[cfg(feature = "unix_timestamp")]
    fn it_parses_v5_timestamp() {
        let packet = [
            0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    fn it_creates_error() {
        let packet = [12, 13, 14];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v7() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
    }

    #[test]
    #[cfg(not(feature = "unix_timestamp"))]
    fn it_parses_v7_and_re_exports() {
        let packet = [
            0, 7, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        if let NetflowPacketResult::V7(v7) = NetflowParser::default()
            .parse_bytes(&packet)
            .first()
            .unwrap()
        {
            assert_yaml_snapshot!(v7.to_be_bytes());
            assert_eq!(v7.to_be_bytes(), packet);
        }
    }

    #[test]
    #[cfg(feature = "unix_timestamp")]
    fn it_parses_v7_timestamp() {
        let packet = [
            0, 7, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
            4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
        ];
        assert_yaml_snapshot!(NetflowParser::default().parse_bytes(&packet));
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
    fn it_doesnt_parse_0_length_fields_ipfix() {
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
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_ipfix_with_no_template_fields_raises_error() {
        let packet = [
            0, 10, 0, 26, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 10, 0, 8, 0, 0, 1, 1,
        ];
        let template = IPFixTemplate {
            field_count: 2,
            template_id: 258,
            fields: vec![],
        };
        let mut parser = NetflowParser::default();
        parser.ipfix_parser.templates.insert(258, template);
        assert_yaml_snapshot!(parser.parse_bytes(&packet));
    }

    #[test]
    fn it_parses_v9_with_no_template_fields_raises_error() {
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
}
