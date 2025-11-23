# netflow_parser

A Netflow Parser library for Cisco V5, V7, V9, and IPFIX written in Rust. Supports chaining of multiple versions in the same stream.

## Table of Contents

- [Example](#example)
- [Serialization (JSON)](#want-serialization-such-as-json)
- [Filtering for a Specific Version](#filtering-for-a-specific-version)
- [Parsing Out Unneeded Versions](#parsing-out-unneeded-versions)
- [Netflow Common](#netflow-common)
- [Re-Exporting Flows](#re-exporting-flows)
- [V9/IPFIX Notes](#v9ipfix-notes)
- [Features](#features)
- [Included Examples](#included-examples)

## Example

### V5

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
match NetflowParser::default().parse_bytes(&v5_packet).first() {
    Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
    Some(NetflowPacket::Error(e)) => println!("{:?}", e),
    _ => (),
}
```

## Want Serialization such as JSON?
Structures fully support serialization.  Below is an example using the serde_json macro:
```rust
use serde_json::json;
use netflow_parser::NetflowParser;

// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet)).to_string());
```

```json
[
  {
    "V5": {
      "header": {
        "count": 1,
        "engine_id": 7,
        "engine_type": 6,
        "flow_sequence": 33752069,
        "sampling_interval": 2057,
        "sys_up_time": { "nanos": 672000000, "secs": 50332 },
        "unix_nsecs": 134807553,
        "unix_secs": 83887623,
        "version": 5
      },
      "sets": [
        {
          "d_octets": 66051,
          "d_pkts": 101124105,
          "dst_addr": "4.5.6.7",
          "dst_as": 515,
          "dst_mask": 5,
          "dst_port": 1029,
          "first": { "nanos": 87000000, "secs": 67438 },
          "input": 515,
          "last": { "nanos": 553000000, "secs": 134807 },
          "next_hop": "8.9.0.1",
          "output": 1029,
          "pad1": 6,
          "pad2": 1543,
          "protocol_number": 8,
          "protocol_type": "Egp",
          "src_addr": "0.1.2.3",
          "src_as": 1,
          "src_mask": 4,
          "src_port": 515,
          "tcp_flags": 7,
          "tos": 9
        }
      ]
    }
  }
]
```

## Filtering for a Specific Version

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
let parsed = NetflowParser::default().parse_bytes(&v5_packet);

let v5_parsed: Vec<NetflowPacket> = parsed.into_iter().filter(|p| p.is_v5()).collect();
```

## Parsing Out Unneeded Versions
If you only care about a specific version or versions you can specify `allowed_versions`:
```rust
use netflow_parser::{NetflowParser, NetflowPacket};

// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
let mut parser = NetflowParser::default();
parser.allowed_versions = [7, 9].into();
let parsed = parser.parse_bytes(&v5_packet);
```

This code will return an empty Vec as version 5 is not allowed.

## Netflow Common

We have included a `NetflowCommon` and `NetflowCommonFlowSet` structure.
This will allow you to use common fields without unpacking values from specific versions.
If the packet flow does not have the matching field it will simply be left as `None`.

### NetflowCommon and NetflowCommonFlowSet Struct:
```rust
use std::net::IpAddr;
use netflow_parser::protocol::ProtocolTypes;

#[derive(Debug, Default)]
pub struct NetflowCommon {
    pub version: u16,
    pub timestamp: u32,
    pub flowsets: Vec<NetflowCommonFlowSet>,
}

#[derive(Debug, Default)]
struct NetflowCommonFlowSet {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol_number: Option<u8>,
    protocol_type: Option<ProtocolTypes>,
    first_seen: Option<u32>,
    last_seen: Option<u32>,
    src_mac: Option<String>,
    dst_mac: Option<String>,
}
```

### Converting NetflowPacket to NetflowCommon

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
let netflow_common = NetflowParser::default()
                     .parse_bytes(&v5_packet)
                     .first()
                     .unwrap()
                     .as_netflow_common()
                     .unwrap();

for common_flow in netflow_common.flowsets.iter() {
    println!("Src Addr: {} Dst Addr: {}", common_flow.src_addr.unwrap(), common_flow.dst_addr.unwrap());
}
```

### Flattened flowsets

To gather all flowsets from all packets into a flattened vector:

```rust
use netflow_parser::NetflowParser;

let flowsets = NetflowParser::default().parse_bytes_as_netflow_common_flowsets(&v5_packet);
```

### Custom Field Mappings for V9 and IPFIX

By default, NetflowCommon maps standard IANA fields to the common structure. However, you can customize which fields are used for V9 and IPFIX packets using configuration structs. This is useful when:

- You want to prefer IPv6 addresses over IPv4
- Your vendor uses non-standard field mappings
- You need to extract data from vendor-specific enterprise fields

#### V9 Custom Field Mapping

```rust
use netflow_parser::netflow_common::{NetflowCommon, V9FieldMappingConfig};
use netflow_parser::variable_versions::v9_lookup::V9Field;

// Create a custom configuration that prefers IPv6 addresses
let mut config = V9FieldMappingConfig::default();
config.src_addr.primary = V9Field::Ipv6SrcAddr;
config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);
config.dst_addr.primary = V9Field::Ipv6DstAddr;
config.dst_addr.fallback = Some(V9Field::Ipv4DstAddr);

// Use with a parsed V9 packet
// let common = NetflowCommon::from_v9_with_config(&v9_packet, &config);
```

#### IPFIX Custom Field Mapping

```rust
use netflow_parser::netflow_common::{NetflowCommon, IPFixFieldMappingConfig};
use netflow_parser::variable_versions::ipfix_lookup::{IPFixField, IANAIPFixField};

// Create a custom configuration that prefers IPv6 addresses
let mut config = IPFixFieldMappingConfig::default();
config.src_addr.primary = IPFixField::IANA(IANAIPFixField::SourceIpv6address);
config.src_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::SourceIpv4address));
config.dst_addr.primary = IPFixField::IANA(IANAIPFixField::DestinationIpv6address);
config.dst_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::DestinationIpv4address));

// Use with a parsed IPFIX packet
// let common = NetflowCommon::from_ipfix_with_config(&ipfix_packet, &config);
```

#### Available Configuration Fields

Both `V9FieldMappingConfig` and `IPFixFieldMappingConfig` support configuring:

| Field | Description | Default V9 Field | Default IPFIX Field |
|-------|-------------|------------------|---------------------|
| `src_addr` | Source IP address | Ipv4SrcAddr (fallback: Ipv6SrcAddr) | SourceIpv4address (fallback: SourceIpv6address) |
| `dst_addr` | Destination IP address | Ipv4DstAddr (fallback: Ipv6DstAddr) | DestinationIpv4address (fallback: DestinationIpv6address) |
| `src_port` | Source port | L4SrcPort | SourceTransportPort |
| `dst_port` | Destination port | L4DstPort | DestinationTransportPort |
| `protocol` | Protocol number | Protocol | ProtocolIdentifier |
| `first_seen` | Flow start time | FirstSwitched | FlowStartSysUpTime |
| `last_seen` | Flow end time | LastSwitched | FlowEndSysUpTime |
| `src_mac` | Source MAC address | InSrcMac | SourceMacaddress |
| `dst_mac` | Destination MAC address | InDstMac | DestinationMacaddress |

Each field mapping has a `primary` field (always checked first) and an optional `fallback` field (used if primary is not present in the flow record).

## Re-Exporting Flows

Parsed V5, V7, V9, and IPFIX packets can be re-exported back into bytes.

**Note:** For V9/IPFIX, we only export the original padding we dissected and do not calculate/align the flowset padding ourselves. If you modify an existing V9/IPFIX flow or create your own, you must manually adjust the padding.
```rust
// 0000   00 05 00 01 03 00 04 00 05 00 06 07 08 09 00 01   ................
// 0010   02 03 04 05 06 07 08 09 00 01 02 03 04 05 06 07   ................
// 0020   08 09 00 01 02 03 04 05 06 07 08 09 00 01 02 03   ................
// 0030   04 05 06 07 08 09 00 01 02 03 04 05 06 07 08 09   ................
// 0040   00 01 02 03 04 05 06 07                           ........
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
    assert_eq!(v5.to_be_bytes(), packet);
}
```

## V9/IPFIX Notes

Parse the data (`&[u8]`) like any other version. The parser (`NetflowParser`) caches parsed templates, so you can send header/data flowset combos and it will use the cached templates. To see cached templates, use the parser for the correct version (`v9_parser` for V9, `ipfix_parser` for IPFIX).

**IPFIX Note:**  We only parse sequence number and domain id, it is up to you if you wish to validate it.

```rust
use netflow_parser::NetflowParser;
let parser = NetflowParser::default();
dbg!(parser.v9_parser.templates);
dbg!(parser.v9_parser.options_templates);
```

To access templates flowset of a processed V9/IPFix flowset you can find the `flowsets` attribute on the Parsed Record.  In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.

## Features

* `parse_unknown_fields` - When enabled fields not listed in this library will attempt to be parsed as a Vec of bytes and the field_number listed.  When disabled an error is thrown when attempting to parse those fields.  Enabled by default.

## Included Examples

Examples have been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.

To run:

```cargo run --example netflow_udp_listener_multi_threaded```

or 

```cargo run --example netflow_udp_listener_single_threaded```

or

```cargo run --example netflow_udp_listener_tokio```

or

```cargo run --example netflow_pcap```

The pcap example also shows how to cache flows that have not yet discovered a template.

## Support My Work

If you find my work helpful, consider supporting me!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/michaelmileusnich)

[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/mikemiles-dev)
