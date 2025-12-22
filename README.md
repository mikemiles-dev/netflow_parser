# netflow_parser

A Netflow Parser library for Cisco V5, V7, V9, and IPFIX written in Rust. Supports chaining of multiple versions in the same stream.

## Table of Contents

- [Example](#example)
- [Serialization (JSON)](#want-serialization-such-as-json)
- [Filtering for a Specific Version](#filtering-for-a-specific-version)
- [Iterator API](#iterator-api)
- [Parsing Out Unneeded Versions](#parsing-out-unneeded-versions)
- [Error Handling Configuration](#error-handling-configuration)
- [Netflow Common](#netflow-common)
- [Re-Exporting Flows](#re-exporting-flows)
- [Template Cache Configuration](#template-cache-configuration)
  - [Template TTL (Time-to-Live)](#template-ttl-time-to-live)
- [V9/IPFIX Notes](#v9ipfix-notes)
- [Performance & Thread Safety](#performance--thread-safety)
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

## Iterator API
You can use the iterator API to process packets one-by-one as they're parsed instead of returning `Vec`:

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

let buffer = /* your netflow data */;
let mut parser = NetflowParser::default();

// Process packets without collecting into a Vec
for packet in parser.iter_packets(&buffer) {
    match packet {
        NetflowPacket::V5(v5) => {
            // Process V5 packet
            println!("V5 packet from {}", v5.header.version);
        }
        NetflowPacket::V9(v9) => {
            // Process V9 packet
            for flowset in &v9.flowsets {
                // Handle flowsets
            }
        }
        NetflowPacket::IPFix(ipfix) => {
            // Process IPFIX packet
        }
        NetflowPacket::Error(e) => {
            eprintln!("Parse error: {:?}", e);
        }
        _ => {}
    }
}
```

The iterator provides access to unconsumed bytes for advanced use cases:

```rust
use netflow_parser::NetflowParser;

let buffer = /* your netflow data */;
let mut parser = NetflowParser::default();
let mut iter = parser.iter_packets(&buffer);

while let Some(packet) = iter.next() {
    // Process packet
}

// Check if all bytes were consumed
if !iter.is_complete() {
    println!("Warning: {} bytes remain unconsumed", iter.remaining().len());
}
```

### Benefits of Iterator API

- **Zero allocation**: Packets are yielded one-by-one without allocating a `Vec`
- **Memory efficient**: Ideal for processing large batches or continuous streams
- **Lazy evaluation**: Only parses packets as you consume them
- **Template caching preserved**: V9/IPFIX template state is maintained across iterations
- **Composable**: Works with standard Rust iterator methods (`.filter()`, `.map()`, `.take()`, etc.)
- **Buffer inspection**: Access unconsumed bytes via `.remaining()` and check completion with `.is_complete()`

### Iterator Examples

```rust
// Count V5 packets without collecting
let count = parser.iter_packets(&buffer)
    .filter(|p| p.is_v5())
    .count();

// Process only the first 10 packets
for packet in parser.iter_packets(&buffer).take(10) {
    // Handle packet
}

// Collect only if needed (equivalent to parse_bytes())
let packets: Vec<_> = parser.iter_packets(&buffer).collect();

// Check unconsumed bytes (useful for mixed protocol streams)
let mut iter = parser.iter_packets(&buffer);
for packet in &mut iter {
    // Process packet
}
if !iter.is_complete() {
    let remaining = iter.remaining();
    // Handle non-netflow data at end of buffer
}
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

## Error Handling Configuration

To prevent memory exhaustion from malformed packets, the parser limits the size of error buffer samples. By default, only the first 256 bytes of unparseable data are stored in error messages. You can customize this limit for all parsers:

```rust
use netflow_parser::NetflowParser;

let mut parser = NetflowParser::default();

// Configure maximum error buffer size for the main parser (default: 256 bytes)
// This applies to generic parsing errors
parser.max_error_sample_size = 512;

// Configure maximum error buffer size for V9 (default: 256 bytes)
parser.v9_parser.max_error_sample_size = 512;

// Configure maximum error buffer size for IPFIX (default: 256 bytes)
parser.ipfix_parser.max_error_sample_size = 512;

let parsed = parser.parse_bytes(&some_packet);
```

This setting helps prevent memory exhaustion when processing malformed or malicious packets while still providing enough context for debugging.

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

**V9/IPFIX Padding Behavior:**
- For **parsed packets**: Original padding is preserved exactly for byte-perfect round-trips
- For **manually created packets**: Padding is automatically calculated to align FlowSets to 4-byte boundaries

**Creating Data Structs:**
For convenience, use `Data::new()` and `OptionsData::new()` to create data structures without manually specifying padding:

```rust
use netflow_parser::variable_versions::ipfix::Data;

// Padding is automatically set to empty vec and calculated during export
let data = Data::new(vec![vec![
    (field1, value1),
    (field2, value2),
]]);
```

See `examples/manual_ipfix_creation.rs` for a complete example of creating IPFIX packets from scratch.

```rust
use netflow_parser::{NetflowParser, NetflowPacket};
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

## Template Cache Configuration

V9 and IPFIX parsers use LRU (Least Recently Used) caching to store templates with a configurable size limit. This prevents memory exhaustion from template flooding attacks while maintaining good performance for legitimate traffic.

### Default Behavior

By default, parsers cache up to 1000 templates:

```rust
use netflow_parser::NetflowParser;

// Uses default cache size of 1000 templates per parser
let parser = NetflowParser::default();
```

### Custom Cache Size - Using Builder Pattern (Recommended)

The builder pattern provides an ergonomic way to configure your parser:

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ttl::TtlConfig;

// Configure both V9 and IPFIX parsers with the same settings
let parser = NetflowParser::builder()
    .with_cache_size(2000)
    .build()
    .expect("Failed to build parser");

// Configure V9 and IPFIX independently
let parser = NetflowParser::builder()
    .with_v9_cache_size(1000)
    .with_ipfix_cache_size(5000)
    .build()
    .expect("Failed to build parser");

// Combine cache size with TTL configuration
let parser = NetflowParser::builder()
    .with_cache_size(2000)
    .with_ttl(TtlConfig::packet_based(100))
    .build()
    .expect("Failed to build parser");

// Full configuration example
let parser = NetflowParser::builder()
    .with_v9_cache_size(1000)
    .with_ipfix_cache_size(2000)
    .with_v9_ttl(TtlConfig::packet_based(100))
    .with_ipfix_ttl(TtlConfig::time_based(std::time::Duration::from_secs(3600)))
    .with_allowed_versions([5, 9, 10].into())
    .with_max_error_sample_size(512)
    .build()
    .expect("Failed to build parser");
```

### Cache Behavior

- When the cache is full, the least recently used template is evicted
- Templates are keyed by template ID (per source)
- Each parser instance maintains its own template cache
- For multi-source deployments, create separate parser instances per source

### Template TTL (Time-to-Live)

Optionally configure templates to expire after a time duration or packet count. This is useful for:
- Handling exporters that reuse template IDs with different schemas
- Forcing periodic template refresh from exporters
- Testing template re-learning behavior

**Note:** TTL is disabled by default for backward compatibility. Templates persist until LRU eviction unless explicitly configured.

#### Configuration Examples

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ttl::TtlConfig;
use std::time::Duration;

// Time-based: Templates expire after 2 hours
let parser = NetflowParser::builder()
    .with_cache_size(1000)
    .with_ttl(TtlConfig::time_based(Duration::from_secs(2 * 3600)))
    .build()
    .unwrap();

// Packet-based: Templates expire after 100 packets
let parser = NetflowParser::builder()
    .with_cache_size(1000)
    .with_ttl(TtlConfig::packet_based(100))
    .build()
    .unwrap();

// Combined: Expire after 1 hour OR 50 packets (whichever comes first)
let parser = NetflowParser::builder()
    .with_cache_size(1000)
    .with_ttl(TtlConfig::combined(Duration::from_secs(3600), 50))
    .build()
    .unwrap();

// Different TTL for V9 and IPFIX
let parser = NetflowParser::builder()
    .with_v9_ttl(TtlConfig::packet_based(100))
    .with_ipfix_ttl(TtlConfig::time_based(Duration::from_secs(2 * 3600)))
    .build()
    .unwrap();
```

### Template Cache Introspection

You can inspect the template cache state at runtime:

```rust
use netflow_parser::NetflowParser;

let parser = NetflowParser::default();

// Get cache statistics
let v9_stats = parser.v9_cache_stats();
println!("V9 cache: {}/{} templates", v9_stats.current_size, v9_stats.max_size);

let ipfix_stats = parser.ipfix_cache_stats();
println!("IPFIX cache: {}/{} templates", ipfix_stats.current_size, ipfix_stats.max_size);

// List all cached template IDs
let v9_templates = parser.v9_template_ids();
println!("V9 template IDs: {:?}", v9_templates);

let ipfix_templates = parser.ipfix_template_ids();
println!("IPFIX template IDs: {:?}", ipfix_templates);

// Check if a specific template exists (doesn't affect LRU ordering)
if parser.has_v9_template(256) {
    println!("Template 256 is cached");
}

// Clear all templates (useful for testing)
let mut parser = NetflowParser::default();
parser.clear_v9_templates();
parser.clear_ipfix_templates();
```

## V9/IPFIX Notes

Parse the data (`&[u8]`) like any other version. The parser (`NetflowParser`) caches parsed templates using LRU eviction, so you can send header/data flowset combos and it will use the cached templates. Templates are automatically cached and evicted when the cache limit is reached.

**Template Cache Access:**
Use the introspection methods to inspect template cache state without affecting LRU ordering:

```rust
use netflow_parser::NetflowParser;
let parser = NetflowParser::default();

// Check if a template exists (doesn't affect LRU)
if parser.has_v9_template(256) {
    println!("Template 256 is cached");
}

// Get cache stats
let stats = parser.v9_cache_stats();
println!("V9 cache: {}/{} templates", stats.current_size, stats.max_size);

// List all template IDs
let template_ids = parser.v9_template_ids();
println!("Cached templates: {:?}", template_ids);
```

**IPFIX Note:**  We only parse sequence number and domain id, it is up to you if you wish to validate it.

To access templates flowset of a processed V9/IPFix flowset you can find the `flowsets` attribute on the Parsed Record.  In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.

## Performance & Thread Safety

### Thread Safety

Parsers (`NetflowParser`, `V9Parser`, `IPFixParser`) are **not thread-safe** and should not be shared across threads without external synchronization. Each parser maintains internal state (template caches) that is modified during parsing.

**Recommended pattern for multi-threaded applications:**
- Create one parser instance per thread
- Each thread processes packets from a single router/source
- See `examples/netflow_udp_listener_multi_threaded.rs` for implementation example

### Performance Optimizations

This library includes several performance optimizations:

1. **Single-pass field caching** - NetflowCommon conversions use efficient single-pass lookups
2. **Minimal cloning** - Template storage avoids unnecessary vector clones
3. **Optimized string processing** - Single-pass filtering and prefix stripping
4. **Capacity pre-allocation** - Vectors pre-allocate when sizes are known
5. **Bounded error buffers** - Error handling limits memory consumption to prevent exhaustion

**Best practices for optimal performance:**
- Reuse parser instances instead of creating new ones for each packet
- Use `iter_packets()` instead of `parse_bytes()` when you don't need all packets in a Vec
- Use `parse_bytes_as_netflow_common_flowsets()` when you only need flow data
- For V9/IPFIX, batch process packets from the same source to maximize template cache hits

## Features

* `parse_unknown_fields` - When enabled fields not listed in this library will attempt to be parsed as a Vec of bytes and the field_number listed.  When disabled an error is thrown when attempting to parse those fields.  Enabled by default.
* `netflow_common` - When enabled provides `NetflowCommon` and `NetflowCommonFlowSet` structures for working with common fields across different Netflow versions.  Disabled by default.

## Included Examples

Examples have been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.

Examples that listen on a specific port use 9995 by default, however netflow can be configurated to use a variety of URP ports:
* **2055**: The most widely recognized default for NetFlow.
* **9995 / 9996**: Popular alternatives, especially with Cisco devices.
* **9025, 9026**: Other recognized port options.
* **6343**: The default for sFlow, often used alongside NetFlow.
* **4739**: The default port for IPFIX (a NetFlow successor). 

To run:

```cargo run --example netflow_udp_listener_multi_threaded```

```cargo run --example netflow_udp_listener_single_threaded```

```cargo run --example netflow_udp_listener_tokio```

```cargo run --example netflow_pcap```

```cargo run --example manual_ipfix_creation```

The pcap example also shows how to cache flows that have not yet discovered a template.

## Support My Work

If you find my work helpful, consider supporting me!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/michaelmileusnich)

[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/mikemiles-dev)
