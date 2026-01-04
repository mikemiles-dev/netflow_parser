# netflow_parser

[![CI](https://github.com/mikemiles-dev/netflow_parser/actions/workflows/rust.yml/badge.svg)](https://github.com/mikemiles-dev/netflow_parser/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/netflow_parser.svg)](https://crates.io/crates/netflow_parser)
[![Downloads](https://img.shields.io/crates/d/netflow_parser.svg)](https://crates.io/crates/netflow_parser)
[![Documentation](https://docs.rs/netflow_parser/badge.svg)](https://docs.rs/netflow_parser)
[![License](https://img.shields.io/crates/l/netflow_parser.svg)](https://github.com/mikemiles-dev/netflow_parser/blob/main/LICENSE-MIT)

A Netflow Parser library for Cisco V5, V7, V9, and IPFIX written in Rust. Supports chaining of multiple versions in the same stream.

> **⚠️ Multi-Router Deployments**: Use [`AutoScopedParser`](#multi-source-deployments) instead of `NetflowParser` when parsing from multiple routers to prevent template cache collisions. See [Template Management Guide](#template-management-guide) for details.

## Table of Contents

- [Example](#example)
- [Serialization (JSON)](#want-serialization-such-as-json)
- [Filtering for a Specific Version](#filtering-for-a-specific-version)
- [Iterator API](#iterator-api)
- [Parser Configuration](#parser-configuration)
  - [Template Cache Size](#template-cache-size)
  - [Template TTL (Time-to-Live)](#template-ttl-time-to-live)
  - [Filtering Versions](#filtering-versions)
  - [Error Handling Configuration](#error-handling-configuration)
  - [Custom Enterprise Fields (IPFIX)](#custom-enterprise-fields-ipfix)
- [Netflow Common](#netflow-common)
- [Re-Exporting Flows](#re-exporting-flows)
- [V9/IPFIX Notes](#v9ipfix-notes)
- [Template Management Guide](#template-management-guide)
  - [Template Cache Metrics](#template-cache-metrics)
  - [Multi-Source Deployments](#multi-source-deployments)
  - [Template Collision Detection](#template-collision-detection)
  - [Handling Missing Templates](#handling-missing-templates)
  - [Template Lifecycle Management](#template-lifecycle-management)
  - [Best Practices](#best-practices)
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
let result = NetflowParser::default().parse_bytes(&v5_packet);
match result.packets.first() {
    Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
    _ => (),
}
// Check for errors
if let Some(e) = result.error {
    eprintln!("Parse error: {}", e);
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
let result = NetflowParser::default().parse_bytes(&v5_packet);
println!("{}", json!(result.packets).to_string());
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
let result = NetflowParser::default().parse_bytes(&v5_packet);

let v5_parsed: Vec<NetflowPacket> = result.packets.into_iter().filter(|p| p.is_v5()).collect();
```

## Iterator API
You can use the iterator API to process packets one-by-one as they're parsed instead of returning `Vec`:

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

let buffer = /* your netflow data */;
let mut parser = NetflowParser::default();

// Process packets without collecting into a Vec
for packet_result in parser.iter_packets(&buffer) {
    match packet_result {
        Ok(NetflowPacket::V5(v5)) => {
            // Process V5 packet
            println!("V5 packet from {}", v5.header.version);
        }
        Ok(NetflowPacket::V9(v9)) => {
            // Process V9 packet
            for flowset in &v9.flowsets {
                // Handle flowsets
            }
        }
        Ok(NetflowPacket::IPFix(ipfix)) => {
            // Process IPFIX packet
        }
        Err(e) => {
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

## Parser Configuration

The `NetflowParser` can be configured using the builder pattern to customize behavior for your specific use case.

### Basic Builder Usage

```rust
use netflow_parser::NetflowParser;

// Create parser with default settings
let parser = NetflowParser::default();

// Or use the builder for custom configuration
let parser = NetflowParser::builder()
    .build()
    .expect("Failed to build parser");
```

### Template Cache Size

V9 and IPFIX parsers use LRU (Least Recently Used) caching to store templates. Configure the cache size to prevent memory exhaustion while maintaining good performance:

```rust
use netflow_parser::NetflowParser;

// Configure both V9 and IPFIX parsers with the same cache size
let parser = NetflowParser::builder()
    .with_cache_size(2000)  // Default is 1000
    .build()
    .expect("Failed to build parser");

// Configure V9 and IPFIX independently
let parser = NetflowParser::builder()
    .with_v9_cache_size(1000)
    .with_ipfix_cache_size(5000)
    .build()
    .expect("Failed to build parser");
```

**Cache Behavior:**
- When the cache is full, the least recently used template is evicted
- Templates are keyed by template ID (per source)
- Each parser instance maintains its own template cache
- For multi-source deployments, use `RouterScopedParser` (see Template Management section)

### Maximum Field Count (Security)

Configure the maximum number of fields allowed per template to prevent DoS attacks via malicious packets with excessive field counts:

```rust
use netflow_parser::NetflowParser;

// Configure both V9 and IPFIX parsers with the same limit
let parser = NetflowParser::builder()
    .with_max_field_count(5000)  // Default is 10,000
    .build()
    .expect("Failed to build parser");

// Configure V9 and IPFIX independently
let parser = NetflowParser::builder()
    .with_v9_max_field_count(5000)
    .with_ipfix_max_field_count(15000)
    .build()
    .expect("Failed to build parser");
```

**Security Considerations:**
- Default limit: 10,000 fields per template (accommodates legitimate use cases)
- Malicious packets claiming 65,535 fields will be rejected
- Templates exceeding the limit return a parse error
- Lower limits provide stricter security but may reject valid templates
- Higher limits are more permissive but increase DoS risk

**Additional Security Validations:**
The parser also automatically validates:
- **Template Total Size**: Maximum sum of all field lengths per template (default: u16::MAX = 65,535 bytes)
  - Prevents DoS attacks via templates with excessive total field lengths
  - Configurable via `Config::max_template_total_size`
- **Duplicate Field Detection**: Templates with duplicate field IDs are rejected
  - For V9: Validates unique `field_type_number` values
  - For IPFIX: Validates unique `(field_type_number, enterprise_number)` pairs
  - Catches malformed or corrupted template definitions

### Template TTL (Time-to-Live)

> **⚠️ Breaking Change in v0.7.0:** Packet-based and combined TTL modes have been removed. Only time-based TTL is now supported. See [RELEASES.md](RELEASES.md) for migration guide.

Optionally configure templates to expire after a time duration. This is useful for:
- Handling exporters that reuse template IDs with different schemas
- Forcing periodic template refresh from exporters
- Testing template re-learning behavior

**Note:** TTL is disabled by default. Templates persist until LRU eviction unless explicitly configured.

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ttl::TtlConfig;
use std::time::Duration;

// Templates expire after 2 hours
let parser = NetflowParser::builder()
    .with_cache_size(1000)
    .with_ttl(TtlConfig::new(Duration::from_secs(2 * 3600)))
    .build()
    .unwrap();

// Using default TTL (2 hours)
let parser = NetflowParser::builder()
    .with_cache_size(1000)
    .with_ttl(TtlConfig::default())
    .build()
    .unwrap();

// Different TTL for V9 and IPFIX
let parser = NetflowParser::builder()
    .with_v9_ttl(TtlConfig::new(Duration::from_secs(3600)))
    .with_ipfix_ttl(TtlConfig::new(Duration::from_secs(2 * 3600)))
    .build()
    .unwrap();
```

### Filtering Versions

If you only care about specific NetFlow versions, configure allowed versions:

```rust
use netflow_parser::NetflowParser;

// Only parse V5 and V9 packets
let parser = NetflowParser::builder()
    .with_allowed_versions([5, 9].into())
    .build()
    .expect("Failed to build parser");

// Or set directly on an existing parser
let mut parser = NetflowParser::default();
parser.allowed_versions = [7, 9].into();
```

Packets with versions not in the allowed list will be ignored (returns empty Vec).

### Error Handling & ParseResult

**parse_bytes()** returns `ParseResult` to preserve partially parsed packets when errors occur mid-stream:

```rust
use netflow_parser::{NetflowParser, ParseResult};

let result = parser.parse_bytes(&buffer);

// Always get successfully parsed packets, even if an error occurred later
for packet in result.packets {
    // Process packet
}

// Check for errors
if let Some(e) = result.error {
    eprintln!("Error after {} packets: {}", result.packets.len(), e);
}
```

**iter_packets()** yields `Result<NetflowPacket, NetflowError>` for per-packet error handling:

```rust
// Per-packet error handling
for result in parser.iter_packets(&buffer) {
    match result {
        Ok(packet) => { /* process */ }
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

**Error types**: `Incomplete`, `UnsupportedVersion`, `Partial`, `MissingTemplate`, `ParseError`. All implement `Display` and `std::error::Error`.

#### Error Sample Size Configuration

To prevent memory exhaustion from malformed packets, the parser limits the size of error buffer samples. By default, only the first 256 bytes of unparseable data are stored in error messages:

```rust
use netflow_parser::NetflowParser;

// Recommended: Use builder pattern (automatically configures all parsers)
let parser = NetflowParser::builder()
    .with_max_error_sample_size(512)  // Default is 256 bytes
    .build()
    .expect("Failed to build parser");

// Or configure directly on an existing parser (requires manual sync)
let mut parser = NetflowParser::default();
parser.max_error_sample_size = 512;
parser.v9_parser.max_error_sample_size = 512;
parser.ipfix_parser.max_error_sample_size = 512;
```

This setting helps prevent memory exhaustion when processing malformed or malicious packets while still providing enough context for debugging.

#### Migration Guide

##### From 0.7.x to 0.8.0

**What changed:** Two major improvements to error handling:

1. **ParseResult** - `parse_bytes()` now returns `ParseResult` to preserve partial results on errors
2. **Error Handling** - `NetflowPacket::Error` variant removed, errors now use `Result`

**ParseResult (prevents data loss):**

```rust
// ❌ Old (0.7.x) - loses packets 1-4 if packet 5 errors
let packets = parser.parse_bytes(&data);  // Returns Vec<NetflowPacket>
// Silent error: if parsing stopped at packet 5, you lost packets 1-4

// ✅ New (0.8.0) - keep packets 1-4 even if packet 5 errors
let result = parser.parse_bytes(&data);  // Returns ParseResult
for packet in result.packets {
    // Process successfully parsed packets 1-4
}
if let Some(e) = result.error {
    eprintln!("Error at packet 5: {}", e);  // But still got partial results!
}
```

**Error Handling (use Result instead of Error variant):**

```rust
// ❌ Old (0.7.x) - errors inline with packets
for packet in parser.parse_bytes(&data) {
    match packet {
        NetflowPacket::V5(v5) => { /* process */ }
        NetflowPacket::Error(e) => { /* error */ }
        _ => {}
    }
}

// ✅ New (0.8.0) - use iter_packets() for Result-based errors
for result in parser.iter_packets(&data) {
    match result {
        Ok(NetflowPacket::V5(v5)) => { /* process */ }
        Err(e) => { /* error */ }
        _ => {}
    }
}
```

### Custom Enterprise Fields (IPFIX)

IPFIX supports vendor-specific enterprise fields that extend the standard IANA field set. The library provides built-in support for several vendors (Cisco, VMWare, Netscaler, etc.), but you can also register your own custom enterprise fields:

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::data_number::FieldDataType;
use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;

// Register custom enterprise fields for your vendor
let parser = NetflowParser::builder()
    .register_enterprise_field(EnterpriseFieldDef::new(
        12345,  // Your enterprise number (assigned by IANA)
        1,      // Field number within your enterprise
        "customMetric",
        FieldDataType::UnsignedDataNumber,
    ))
    .register_enterprise_field(EnterpriseFieldDef::new(
        12345,
        2,
        "customApplicationName",
        FieldDataType::String,
    ))
    .build()
    .expect("Failed to build parser");

// Parse IPFIX packets - custom fields are automatically decoded!
let packets = parser.parse_bytes(&buffer);
```

#### Bulk Registration

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::data_number::FieldDataType;
use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;

let custom_fields = vec![
    EnterpriseFieldDef::new(12345, 1, "field1", FieldDataType::UnsignedDataNumber),
    EnterpriseFieldDef::new(12345, 2, "field2", FieldDataType::String),
    EnterpriseFieldDef::new(12345, 3, "field3", FieldDataType::Ip4Addr),
    EnterpriseFieldDef::new(12345, 4, "field4", FieldDataType::DurationMillis),
];

let parser = NetflowParser::builder()
    .register_enterprise_fields(custom_fields)
    .build()
    .expect("Failed to build parser");
```

#### Available Data Types

When registering enterprise fields, you can use any of these built-in data types:

- `FieldDataType::UnsignedDataNumber` - Unsigned integers (variable length)
- `FieldDataType::SignedDataNumber` - Signed integers (variable length)
- `FieldDataType::Float64` - 64-bit floating point
- `FieldDataType::String` - UTF-8 strings
- `FieldDataType::Ip4Addr` - IPv4 addresses
- `FieldDataType::Ip6Addr` - IPv6 addresses
- `FieldDataType::MacAddr` - MAC addresses
- `FieldDataType::DurationSeconds` - Durations in seconds
- `FieldDataType::DurationMillis` - Durations in milliseconds
- `FieldDataType::DurationMicrosNTP` - NTP microsecond timestamps
- `FieldDataType::DurationNanosNTP` - NTP nanosecond timestamps
- `FieldDataType::ProtocolType` - Protocol numbers
- `FieldDataType::Vec` - Raw byte arrays
- `FieldDataType::ApplicationId` - Application identifiers

**How It Works:**
1. **Without registration**: Unknown enterprise fields are parsed as raw bytes (`FieldValue::Vec`)
2. **With registration**: Registered enterprise fields are automatically parsed according to their specified data type
3. **Field names**: The `name` parameter is used for debugging and can help identify fields in logs

See `examples/custom_enterprise_fields.rs` for a complete working example.

### Complete Configuration Example

```rust
use netflow_parser::NetflowParser;
use netflow_parser::variable_versions::ttl::TtlConfig;
use netflow_parser::variable_versions::data_number::FieldDataType;
use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;
use std::time::Duration;

let parser = NetflowParser::builder()
    // Cache configuration
    .with_v9_cache_size(1000)
    .with_ipfix_cache_size(2000)

    // Security limits
    .with_v9_max_field_count(5000)
    .with_ipfix_max_field_count(10000)
    .with_max_error_sample_size(512)

    // Template TTL
    .with_v9_ttl(TtlConfig::new(Duration::from_secs(3600)))
    .with_ipfix_ttl(TtlConfig::new(Duration::from_secs(7200)))

    // Version filtering
    .with_allowed_versions([5, 9, 10].into())

    // Enterprise fields
    .register_enterprise_fields(vec![
        EnterpriseFieldDef::new(12345, 1, "field1", FieldDataType::UnsignedDataNumber),
        EnterpriseFieldDef::new(12345, 2, "field2", FieldDataType::String),
    ])

    // Template lifecycle hooks
    .on_template_event(|event| {
        println!("Template event: {:?}", event);
    })

    .build()
    .expect("Failed to build parser");

// For multi-source deployments, use AutoScopedParser instead:
// let scoped_parser = NetflowParser::builder()./* config */.multi_source();
```

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
let result = NetflowParser::default().parse_bytes(&v5_packet);
let netflow_common = result.packets
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
let result = NetflowParser::default().parse_bytes(&packet);
if let Some(NetflowPacket::V5(v5)) = result.packets.first() {
    assert_eq!(v5.to_be_bytes(), packet);
}
```

## V9/IPFIX Notes

Parse the data (`&[u8]`) like any other version. The parser (`NetflowParser`) caches parsed templates using LRU eviction, so you can send header/data flowset combos and it will use the cached templates. Templates are automatically cached and evicted when the cache limit is reached.

**Template Management:** For comprehensive information about template caching, introspection, multi-source deployments, and best practices, see the [Template Management Guide](#template-management-guide) section below.

**IPFIX Note:** We only parse sequence number and domain id, it is up to you if you wish to validate it.

**FlowSet Access:** To access templates flowset of a processed V9/IPFIX flowset you can find the `flowsets` attribute on the Parsed Record. In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.

## Template Management Guide

### Overview

NetFlow V9 and IPFIX are template-based protocols where templates define the structure of flow records. This library provides comprehensive template management features to handle various deployment scenarios.

### Template Cache Metrics

Track template cache performance to understand your parser's behavior:

```rust
use netflow_parser::NetflowParser;

let mut parser = NetflowParser::default();

// Parse some packets...
parser.parse_bytes(&data);

// Get cache statistics
let v9_stats = parser.v9_cache_stats();
println!("V9 Cache: {}/{} templates", v9_stats.current_size, v9_stats.max_size);

// Access performance metrics
let metrics = &v9_stats.metrics;
println!("Cache hits: {}", metrics.hits);
println!("Cache misses: {}", metrics.misses);
println!("Evictions: {}", metrics.evictions);
println!("Collisions: {}", metrics.collisions);
println!("Expired templates: {}", metrics.expired);

// Calculate hit rate
if let Some(hit_rate) = metrics.hit_rate() {
    println!("Cache hit rate: {:.2}%", hit_rate * 100.0);
}
```

**Metrics tracked:**
- **Hits**: Successful template lookups
- **Misses**: Failed template lookups (template not in cache)
- **Evictions**: Templates removed due to LRU policy when cache is full
- **Collisions**: Template ID reused (same ID, potentially different definition)
- **Expired**: Templates removed due to TTL expiration

### Multi-Source Deployments (RFC-Compliant)

**⚠️ IMPORTANT**: When parsing from multiple routers, template IDs **collide**. Different routers often use the same template ID (e.g., 256) with completely different schemas, causing cache thrashing and parsing failures.

**The Problem:**
```rust
// ❌ DON'T: Multiple sources sharing one parser
let mut parser = NetflowParser::default();
loop {
    let (data, source_addr) = recv_from_network();
    parser.parse_bytes(&data); // Router A's template 256 overwrites Router B's!
}
```

**The Solution - Use `AutoScopedParser`:**
```rust
// ✅ DO: Each source gets isolated template cache (RFC-compliant)
use netflow_parser::AutoScopedParser;
use std::net::SocketAddr;

let mut parser = AutoScopedParser::new();

// Parser automatically handles RFC-compliant scoping:
// - NetFlow v9: Uses (source_addr, source_id) per RFC 3954
// - IPFIX: Uses (source_addr, observation_domain_id) per RFC 7011
// - NetFlow v5/v7: Uses source_addr only

let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();
let packets = parser.parse_from_source(source, &data);

// Monitor cache health
if parser.source_count() > 1 {
    println!("Parsing from {} sources with isolated caches", parser.source_count());
}
```

**Why AutoScopedParser?**
- **Prevents template collisions** - Each source has isolated cache
- **RFC-compliant** - Follows NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) scoping rules
- **Automatic** - No manual key management required
- **Better performance** - Higher cache hit rates, no thrashing

#### Advanced: Custom Scoping with RouterScopedParser

For specialized requirements beyond automatic RFC-compliant scoping, use `RouterScopedParser` with custom key types:

```rust
use netflow_parser::RouterScopedParser;
use std::net::SocketAddr;

// Example: Custom scoping for named sources
let mut scoped = RouterScopedParser::<String>::new();
scoped.parse_from_source("router-nyc-01".to_string(), &data);

// Example: Manual composite key (not recommended - use AutoScopedParser instead)
#[derive(Hash, Eq, PartialEq, Clone)]
struct CustomKey {
    router_name: String,
    region: String,
}

let mut scoped = RouterScopedParser::<CustomKey>::new();
```

**When to use `RouterScopedParser` instead of `AutoScopedParser`:**
- You need custom scoping logic beyond protocol standards
- You're using named identifiers for sources
- You have application-specific grouping requirements

**For standard NetFlow/IPFIX deployments, use `AutoScopedParser` instead.**

#### Custom Parser Configuration

Configure parsers with custom settings:

```rust
use netflow_parser::{AutoScopedParser, NetflowParser};
use netflow_parser::variable_versions::ttl::TtlConfig;
use std::time::Duration;

// Configure AutoScopedParser
let builder = NetflowParser::builder()
    .with_cache_size(5000)
    .with_ttl(TtlConfig::new(Duration::from_secs(3600)));

let mut parser = AutoScopedParser::with_builder(builder);

// Or configure RouterScopedParser for custom scoping
use netflow_parser::RouterScopedParser;
let mut scoped = RouterScopedParser::<String>::with_builder(builder);
```

### Template Collision Detection

Monitor when template IDs are reused:

```rust
let v9_stats = parser.v9_cache_stats();
if v9_stats.metrics.collisions > 0 {
    println!("Warning: {} template collisions detected", v9_stats.metrics.collisions);
    println!("Use AutoScopedParser for RFC-compliant multi-source deployments");
}
```

### Handling Missing Templates

When a data flowset arrives before its template (IPFIX):

```rust
use netflow_parser::{NetflowParser, NetflowPacket};
use netflow_parser::variable_versions::ipfix::FlowSetBody;

let mut parser = NetflowParser::default();
let mut pending_data = Vec::new();

for packet in parser.iter_packets(&data) {
    if let NetflowPacket::IPFix(ipfix) = packet {
        for flowset in &ipfix.flowsets {
            if let FlowSetBody::NoTemplate(info) = &flowset.body {
                println!("Missing template ID: {}", info.template_id);
                println!("Available templates: {:?}", info.available_templates);

                // Save for retry after template arrives
                pending_data.push(info.raw_data.clone());
            }
        }
    }
}

// Retry pending data after templates arrive
for pending in &pending_data {
    let _ = parser.parse_bytes(pending);
}
```

### Template Lifecycle Management

#### Template Introspection

Inspect the template cache state at runtime without affecting LRU ordering:

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
```

#### Clearing Templates

```rust
// Clear all V9 templates
parser.clear_v9_templates();

// Clear all IPFIX templates
parser.clear_ipfix_templates();

// With RouterScopedParser - clear specific source
scoped_parser.clear_source_templates(&source_addr);

// Or clear all sources
scoped_parser.clear_all_templates();
```

### Best Practices

1. **Use AutoScopedParser for multi-source deployments** ⭐
   - Automatically implements RFC-compliant scoping
   - Prevents template ID collisions between sources and observation domains
   - No manual key management required
   - Correct for all NetFlow/IPFIX versions

2. **Monitor cache metrics**
   - High miss rates indicate templates arriving out of order
   - High collision rates suggest need for scoped parsing (if not using AutoScopedParser)
   - High eviction rates indicate cache size should be increased

3. **Configure appropriate cache size**
   - Default: 1000 templates per source
   - Increase for routers that define many templates
   - Monitor `current_size` vs `max_size` to right-size

4. **Use TTL for long-running parsers**
   - Prevents stale templates in 24/7 collectors
   - Recommended: 1-2 hours for typical deployments
   - See [Template TTL](#template-ttl-time-to-live) section

5. **Handle missing templates gracefully**
   - Cache data flowsets that arrive before templates
   - Retry after template packets are processed
   - Use `NoTemplateInfo` to understand what's missing

6. **Thread safety with scoped parsers**
   - `AutoScopedParser` and `RouterScopedParser` are not thread-safe
   - Use `Arc<Mutex<AutoScopedParser>>` for multi-threaded applications
   - See [Thread Safety](#thread-safety) for details

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

```cargo run --example custom_enterprise_fields```

The pcap example also shows how to cache flows that have not yet discovered a template. The custom_enterprise_fields example demonstrates how to register vendor-specific IPFIX fields.

## Support My Work

If you find my work helpful, consider supporting me!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/michaelmileusnich)

[![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/mikemiles-dev)
