//! # netflow_parser
//!
//! A Netflow Parser library for Cisco V5, V7, V9, and IPFIX written in Rust. Supports chaining of multiple versions in the same stream.
//!
//! > **⚠️ Breaking Changes in v0.7.0:** The Template TTL API has been simplified to only support time-based expiration.
//! > Packet-based and combined TTL modes have been removed. See the [RELEASES.md](https://github.com/mikemiles-dev/netflow_parser/blob/main/RELEASES.md)
//! > for the full migration guide.
//!
//! ## Quick Start
//!
//! ### Using the Builder Pattern (Recommended)
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//! use netflow_parser::variable_versions::ttl::TtlConfig;
//! use std::time::Duration;
//!
//! // Create a parser with custom configuration
//! let mut parser = NetflowParser::builder()
//!     .with_cache_size(2000)
//!     .with_ttl(TtlConfig::new(Duration::from_secs(7200)))
//!     .build()
//!     .expect("Failed to build parser");
//!
//! // Parse packets
//! let buffer = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
//! let packets = parser.parse_bytes(&buffer);
//! ```
//!
//! ### Using Default Configuration
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! match NetflowParser::default().parse_bytes(&v5_packet).packets.first() {
//!     Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
//!     _ => (),
//! }
//! ```
//!
//! ## Want Serialization such as JSON?
//! Structures fully support serialization.  Below is an example using the serde_json macro:
//! ```rust
//! use serde_json::json;
//! use netflow_parser::NetflowParser;
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet).packets).to_string());
//! ```
//!
//! ```json
//! [
//!   {
//!     "V5": {
//!       "header": {
//!         "count": 1,
//!         "engine_id": 7,
//!         "engine_type": 6,
//!         "flow_sequence": 33752069,
//!         "sampling_interval": 2057,
//!         "sys_up_time": { "nanos": 672000000, "secs": 50332 },
//!         "unix_nsecs": 134807553,
//!         "unix_secs": 83887623,
//!         "version": 5
//!       },
//!       "sets": [
//!         {
//!           "d_octets": 66051,
//!           "d_pkts": 101124105,
//!           "dst_addr": "4.5.6.7",
//!           "dst_as": 515,
//!           "dst_mask": 5,
//!           "dst_port": 1029,
//!           "first": { "nanos": 87000000, "secs": 67438 },
//!           "input": 515,
//!           "last": { "nanos": 553000000, "secs": 134807 },
//!           "next_hop": "8.9.0.1",
//!           "output": 1029,
//!           "pad1": 6,
//!           "pad2": 1543,
//!           "protocol_number": 8,
//!           "protocol_type": "Egp",
//!           "src_addr": "0.1.2.3",
//!           "src_as": 1,
//!           "src_mask": 4,
//!           "src_port": 515,
//!           "tcp_flags": 7,
//!           "tos": 9
//!         }
//!       ]
//!     }
//!   }
//! ]
//! ```
//!
//! ## Filtering for a Specific Version
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let parsed = NetflowParser::default().parse_bytes(&v5_packet).packets;
//!
//! let v5_parsed: Vec<NetflowPacket> = parsed.into_iter().filter(|p| p.is_v5()).collect();
//! ```
//!
//! ## Iterator API
//!
//! For high-performance scenarios where you want to avoid allocating a `Vec`, you can use the iterator API to process packets one-by-one as they're parsed:
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! # let buffer = [0u8; 72];
//! let mut parser = NetflowParser::default();
//!
//! // Process packets without collecting into a Vec
//! for result in parser.iter_packets(&buffer) {
//!     match result {
//!         Ok(NetflowPacket::V5(v5)) => {
//!             // Process V5 packet
//!             println!("V5 packet from {}", v5.header.version);
//!         }
//!         Ok(NetflowPacket::V9(v9)) => {
//!             // Process V9 packet
//!             for flowset in &v9.flowsets {
//!                 // Handle flowsets
//!             }
//!         }
//!         Ok(NetflowPacket::IPFix(ipfix)) => {
//!             // Process IPFIX packet
//!         }
//!         Err(e) => {
//!             eprintln!("Parse error: {:?}", e);
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! The iterator provides access to unconsumed bytes for advanced use cases:
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//!
//! # let buffer = [0u8; 72];
//! let mut parser = NetflowParser::default();
//! let mut iter = parser.iter_packets(&buffer);
//!
//! while let Some(result) = iter.next() {
//!     match result {
//!         Ok(_packet) => {
//!             // Process packet
//!         }
//!         Err(_e) => {
//!             // Handle error
//!         }
//!     }
//! }
//!
//! // Check if all bytes were consumed
//! if !iter.is_complete() {
//!     println!("Warning: {} bytes remain unconsumed", iter.remaining().len());
//! }
//! ```
//!
//! ### Benefits of Iterator API
//!
//! - **Zero allocation**: Packets are yielded one-by-one without allocating a `Vec`
//! - **Memory efficient**: Ideal for processing large batches or continuous streams
//! - **Lazy evaluation**: Only parses packets as you consume them
//! - **Template caching preserved**: V9/IPFIX template state is maintained across iterations
//! - **Composable**: Works with standard Rust iterator methods (`.filter()`, `.map()`, `.take()`, etc.)
//! - **Buffer inspection**: Access unconsumed bytes via `.remaining()` and check completion with `.is_complete()`
//!
//! ### Iterator Examples
//!
//! ```rust
//! # use netflow_parser::{NetflowParser, NetflowPacket};
//! # let buffer = [0u8; 72];
//! # let mut parser = NetflowParser::default();
//! // Count V5 packets without collecting
//! let count = parser.iter_packets(&buffer)
//!     .filter(|r| r.as_ref().map(|p| p.is_v5()).unwrap_or(false))
//!     .count();
//!
//! // Process only the first 10 packets
//! for result in parser.iter_packets(&buffer).take(10) {
//!     if let Ok(packet) = result {
//!         // Handle packet
//! #       _ = packet;
//!     }
//! }
//!
//! // Collect only if needed (equivalent to parse_bytes())
//! let packets: Vec<_> = parser.iter_packets(&buffer)
//!     .filter_map(Result::ok)
//!     .collect();
//!
//! // Check unconsumed bytes (useful for mixed protocol streams)
//! let mut iter = parser.iter_packets(&buffer);
//! for result in &mut iter {
//!     if let Ok(packet) = result {
//!         // Process packet
//! #       _ = packet;
//!     }
//! }
//! if !iter.is_complete() {
//!     let remaining = iter.remaining();
//!     // Handle non-netflow data at end of buffer
//! #   _ = remaining;
//! }
//! ```
//!
//! ## Parsing Out Unneeded Versions
//! If you only care about a specific version or versions you can specify `allowed_versions`:
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
//! let mut parser = NetflowParser::default();
//! parser.allowed_versions = [7, 9].into();
//! let parsed = parser.parse_bytes(&v5_packet).packets;
//! ```
//!
//! This code will return an empty Vec as version 5 is not allowed.
//!
//! ## Error Handling Configuration
//!
//! To prevent memory exhaustion from malformed packets, the parser limits the size of error buffer samples. By default, only the first 256 bytes of unparseable data are stored in error messages. You can customize this limit for all parsers:
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//!
//! let mut parser = NetflowParser::default();
//!
//! // Configure maximum error buffer size for the main parser (default: 256 bytes)
//! // This applies to generic parsing errors
//! parser.max_error_sample_size = 512;
//!
//! // Configure maximum error buffer size for V9 (default: 256 bytes)
//! parser.v9_parser.max_error_sample_size = 512;
//!
//! // Configure maximum error buffer size for IPFIX (default: 256 bytes)
//! parser.ipfix_parser.max_error_sample_size = 512;
//!
//! # let some_packet = [0u8; 72];
//! let parsed = parser.parse_bytes(&some_packet);
//! ```
//!
//! This setting helps prevent memory exhaustion when processing malformed or malicious packets while still providing enough context for debugging.
//!
//! ## Netflow Common
//!
//! We have included a `NetflowCommon` and `NetflowCommonFlowSet` structure.
//! This will allow you to use common fields without unpacking values from specific versions.
//! If the packet flow does not have the matching field it will simply be left as `None`.
//!
//! ### NetflowCommon and NetflowCommonFlowSet Struct:
//! ```rust
//! use std::net::IpAddr;
//! use netflow_parser::protocol::ProtocolTypes;
//!
//! #[derive(Debug, Default)]
//! pub struct NetflowCommon {
//!     pub version: u16,
//!     pub timestamp: u32,
//!     pub flowsets: Vec<NetflowCommonFlowSet>,
//! }
//!
//! #[derive(Debug, Default)]
//! struct NetflowCommonFlowSet {
//!     src_addr: Option<IpAddr>,
//!     dst_addr: Option<IpAddr>,
//!     src_port: Option<u16>,
//!     dst_port: Option<u16>,
//!     protocol_number: Option<u8>,
//!     protocol_type: Option<ProtocolTypes>,
//!     first_seen: Option<u32>,
//!     last_seen: Option<u32>,
//!     src_mac: Option<String>,
//!     dst_mac: Option<String>,
//! }
//! ```
//!
//! ### Converting NetflowPacket to NetflowCommon
//!
//! ```rust,ignore
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
//!     4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
//!     2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
//! let netflow_common = NetflowParser::default()
//!                      .parse_bytes(&v5_packet)
//!                      .first()
//!                      .unwrap()
//!                      .as_netflow_common()
//!                      .unwrap();
//!
//! for common_flow in netflow_common.flowsets.iter() {
//!     println!("Src Addr: {} Dst Addr: {}", common_flow.src_addr.unwrap(), common_flow.dst_addr.unwrap());
//! }
//! ```
//!
//! ### Flattened flowsets
//!
//! To gather all flowsets from all packets into a flattened vector:
//!
//! ```rust,ignore
//! use netflow_parser::NetflowParser;
//!
//! # let v5_packet = [0u8; 72];
//! let flowsets = NetflowParser::default().parse_bytes_as_netflow_common_flowsets(&v5_packet);
//! ```
//!
//! ### Custom Field Mappings for V9 and IPFIX
//!
//! By default, NetflowCommon maps standard IANA fields to the common structure. However, you can customize which fields are used for V9 and IPFIX packets using configuration structs. This is useful when:
//!
//! - You want to prefer IPv6 addresses over IPv4
//! - Your vendor uses non-standard field mappings
//! - You need to extract data from vendor-specific enterprise fields
//!
//! #### V9 Custom Field Mapping
//!
//! ```rust,ignore
//! use netflow_parser::netflow_common::{NetflowCommon, V9FieldMappingConfig};
//! use netflow_parser::variable_versions::v9_lookup::V9Field;
//!
//! // Create a custom configuration that prefers IPv6 addresses
//! let mut config = V9FieldMappingConfig::default();
//! config.src_addr.primary = V9Field::Ipv6SrcAddr;
//! config.src_addr.fallback = Some(V9Field::Ipv4SrcAddr);
//! config.dst_addr.primary = V9Field::Ipv6DstAddr;
//! config.dst_addr.fallback = Some(V9Field::Ipv4DstAddr);
//!
//! // Use with a parsed V9 packet
//! // let common = NetflowCommon::from_v9_with_config(&v9_packet, &config);
//! ```
//!
//! #### IPFIX Custom Field Mapping
//!
//! ```rust,ignore
//! use netflow_parser::netflow_common::{NetflowCommon, IPFixFieldMappingConfig};
//! use netflow_parser::variable_versions::ipfix_lookup::{IPFixField, IANAIPFixField};
//!
//! // Create a custom configuration that prefers IPv6 addresses
//! let mut config = IPFixFieldMappingConfig::default();
//! config.src_addr.primary = IPFixField::IANA(IANAIPFixField::SourceIpv6address);
//! config.src_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::SourceIpv4address));
//! config.dst_addr.primary = IPFixField::IANA(IANAIPFixField::DestinationIpv6address);
//! config.dst_addr.fallback = Some(IPFixField::IANA(IANAIPFixField::DestinationIpv4address));
//!
//! // Use with a parsed IPFIX packet
//! // let common = NetflowCommon::from_ipfix_with_config(&ipfix_packet, &config);
//! ```
//!
//! #### Available Configuration Fields
//!
//! Both `V9FieldMappingConfig` and `IPFixFieldMappingConfig` support configuring:
//!
//! | Field | Description | Default V9 Field | Default IPFIX Field |
//! |-------|-------------|------------------|---------------------|
//! | `src_addr` | Source IP address | Ipv4SrcAddr (fallback: Ipv6SrcAddr) | SourceIpv4address (fallback: SourceIpv6address) |
//! | `dst_addr` | Destination IP address | Ipv4DstAddr (fallback: Ipv6DstAddr) | DestinationIpv4address (fallback: DestinationIpv6address) |
//! | `src_port` | Source port | L4SrcPort | SourceTransportPort |
//! | `dst_port` | Destination port | L4DstPort | DestinationTransportPort |
//! | `protocol` | Protocol number | Protocol | ProtocolIdentifier |
//! | `first_seen` | Flow start time | FirstSwitched | FlowStartSysUpTime |
//! | `last_seen` | Flow end time | LastSwitched | FlowEndSysUpTime |
//! | `src_mac` | Source MAC address | InSrcMac | SourceMacaddress |
//! | `dst_mac` | Destination MAC address | InDstMac | DestinationMacaddress |
//!
//! Each field mapping has a `primary` field (always checked first) and an optional `fallback` field (used if primary is not present in the flow record).
//!
//! ## Re-Exporting Flows
//!
//! Parsed V5, V7, V9, and IPFIX packets can be re-exported back into bytes.
//!
//! **V9/IPFIX Padding Behavior:**
//! - For **parsed packets**: Original padding is preserved exactly for byte-perfect round-trips
//! - For **manually created packets**: Padding is automatically calculated to align FlowSets to 4-byte boundaries
//!
//! **Creating Data Structs:**
//! For convenience, use `Data::new()` and `OptionsData::new()` to create data structures without manually specifying padding:
//!
//! ```rust,ignore
//! use netflow_parser::variable_versions::ipfix::Data;
//!
//! // Padding is automatically set to empty vec and calculated during export
//! let data = Data::new(vec![vec![
//!     (field1, value1),
//!     (field2, value2),
//! ]]);
//! ```
//!
//! See `examples/manual_ipfix_creation.rs` for a complete example of creating IPFIX packets from scratch.
//!
//! ```rust
//! use netflow_parser::{NetflowParser, NetflowPacket};
//!
//! let packet = [
//!     0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
//!     4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
//!     2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
//! ];
//! if let NetflowPacket::V5(v5) = NetflowParser::default()
//!     .parse_bytes(&packet)
//!     .packets
//!     .first()
//!     .unwrap()
//! {
//!     assert_eq!(v5.to_be_bytes(), packet);
//! }
//! ```
//!
//! ## Template Cache Configuration
//!
//! V9 and IPFIX parsers use LRU (Least Recently Used) caching to store templates with a configurable size limit. This prevents memory exhaustion from template flooding attacks while maintaining good performance for legitimate traffic.
//!
//! ### Default Behavior
//!
//! By default, parsers cache up to 1000 templates:
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//!
//! // Uses default cache size of 1000 templates per parser
//! let parser = NetflowParser::default();
//! ```
//!
//! ### Custom Cache Size
//!
//! Use the builder pattern to configure cache sizes:
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//!
//! // Configure both V9 and IPFIX with the same cache size
//! let parser = NetflowParser::builder()
//!     .with_cache_size(2000)
//!     .build()
//!     .expect("Failed to build parser");
//!
//! // Configure V9 and IPFIX independently
//! let parser = NetflowParser::builder()
//!     .with_v9_cache_size(1000)
//!     .with_ipfix_cache_size(5000)
//!     .build()
//!     .expect("Failed to build parser");
//! ```
//!
//! ### Cache Behavior
//!
//! - When the cache is full, the least recently used template is evicted
//! - Templates are keyed by template ID (per source)
//! - Each parser instance maintains its own template cache
//! - For multi-source deployments, create separate parser instances per source
//!
//! ### Template TTL (Time-to-Live)
//!
//! Optionally configure templates to expire after a time duration. This is useful for:
//! - Handling exporters that reuse template IDs with different schemas
//! - Forcing periodic template refresh from exporters
//! - Testing template re-learning behavior
//!
//! **Note:** TTL is disabled by default. Templates persist until LRU eviction unless explicitly configured.
//!
//! #### Configuration Examples
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//! use netflow_parser::variable_versions::ttl::TtlConfig;
//! use std::time::Duration;
//!
//! // Templates expire after 2 hours
//! let parser = NetflowParser::builder()
//!     .with_cache_size(1000)
//!     .with_ttl(TtlConfig::new(Duration::from_secs(2 * 3600)))
//!     .build()
//!     .unwrap();
//!
//! // Using default TTL (2 hours)
//! let parser = NetflowParser::builder()
//!     .with_cache_size(1000)
//!     .with_ttl(TtlConfig::default())
//!     .build()
//!     .unwrap();
//!
//! // Different TTL for V9 and IPFIX
//! let parser = NetflowParser::builder()
//!     .with_v9_ttl(TtlConfig::new(Duration::from_secs(3600)))
//!     .with_ipfix_ttl(TtlConfig::new(Duration::from_secs(2 * 3600)))
//!     .build()
//!     .unwrap();
//! ```
//!
//! ## V9/IPFIX Notes
//!
//! Parse the data (`&[u8]`) like any other version. The parser (`NetflowParser`) caches parsed templates using LRU eviction, so you can send header/data flowset combos and it will use the cached templates. Templates are automatically cached and evicted when the cache limit is reached.
//!
//! **Template Cache Introspection:**
//! Use the introspection methods to inspect template cache state without affecting LRU ordering:
//!
//! ```rust
//! use netflow_parser::NetflowParser;
//! let parser = NetflowParser::default();
//!
//! // Get cache statistics
//! let stats = parser.v9_cache_stats();
//! println!("V9 cache: {}/{} templates", stats.current_size, stats.max_size);
//!
//! // List all cached template IDs
//! let template_ids = parser.v9_template_ids();
//! println!("Cached templates: {:?}", template_ids);
//!
//! // Check if a specific template exists (doesn't affect LRU)
//! if parser.has_v9_template(256) {
//!     println!("Template 256 is cached");
//! }
//! ```
//!
//! **IPFIX Note:**  We only parse sequence number and domain id, it is up to you if you wish to validate it.
//!
//! To access templates flowset of a processed V9/IPFix flowset you can find the `flowsets` attribute on the Parsed Record.  In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.
//!
//! ## Performance & Thread Safety
//!
//! ### Thread Safety
//!
//! Parsers (`NetflowParser`, `V9Parser`, `IPFixParser`) are **not thread-safe** and should not be shared across threads without external synchronization. Each parser maintains internal state (template caches) that is modified during parsing.
//!
//! **Recommended pattern for multi-threaded applications:**
//! - Create one parser instance per thread
//! - Each thread processes packets from a single router/source
//! - See `examples/netflow_udp_listener_multi_threaded.rs` for implementation example
//!
//! ### Performance Optimizations
//!
//! This library includes several performance optimizations:
//!
//! 1. **Single-pass field caching** - NetflowCommon conversions use efficient single-pass lookups
//! 2. **Minimal cloning** - Template storage avoids unnecessary vector clones
//! 3. **Optimized string processing** - Single-pass filtering and prefix stripping
//! 4. **Capacity pre-allocation** - Vectors pre-allocate when sizes are known
//! 5. **Bounded error buffers** - Error handling limits memory consumption to prevent exhaustion
//!
//! **Best practices for optimal performance:**
//! - Reuse parser instances instead of creating new ones for each packet
//! - Use `iter_packets()` instead of `parse_bytes()` when you don't need all packets in a Vec
//! - Use `parse_bytes_as_netflow_common_flowsets()` when you only need flow data
//! - For V9/IPFIX, batch process packets from the same source to maximize template cache hits
//!
//! ## Features
//!
//! * `parse_unknown_fields` - When enabled fields not listed in this library will attempt to be parsed as a Vec of bytes and the field_number listed.  When disabled an error is thrown when attempting to parse those fields.  Enabled by default.
//! * `netflow_common` - When enabled provides `NetflowCommon` and `NetflowCommonFlowSet` structures for working with common fields across different Netflow versions.  Disabled by default.
//!
//! ## Included Examples
//!
//! Examples have been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.
//!
//! Examples that listen on a specific port use 9995 by default, however netflow can be configurated to use a variety of URP ports:
//! * **2055**: The most widely recognized default for NetFlow.
//! * **9995 / 9996**: Popular alternatives, especially with Cisco devices.
//! * **9025, 9026**: Other recognized port options.
//! * **6343**: The default for sFlow, often used alongside NetFlow.
//! * **4739**: The default port for IPFIX (a NetFlow successor).
//!
//! To run:
//!
//! ```cargo run --example netflow_udp_listener_multi_threaded```
//!
//! ```cargo run --example netflow_udp_listener_single_threaded```
//!
//! ```cargo run --example netflow_udp_listener_tokio```
//!
//! ```cargo run --example netflow_pcap```
//!
//! ```cargo run --example manual_ipfix_creation```
//!
//! The pcap example also shows how to cache flows that have not yet discovered a template.
//!
//! ## Support My Work
//!
//! If you find my work helpful, consider supporting me!
//!
//! [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/michaelmileusnich)
//!
//! [![GitHub Sponsors](https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA)](https://github.com/sponsors/mikemiles-dev)

#[cfg(feature = "netflow_common")]
pub mod netflow_common;
pub mod protocol;
pub mod scoped_parser;
pub mod static_versions;
pub mod template_events;
mod tests;
pub mod variable_versions;

#[cfg(feature = "netflow_common")]
use crate::netflow_common::{NetflowCommon, NetflowCommonError, NetflowCommonFlowSet};

use static_versions::{
    v5::{V5, V5Parser},
    v7::{V7, V7Parser},
};
use variable_versions::Config;
use variable_versions::enterprise_registry::EnterpriseFieldDef;
use variable_versions::ipfix::{IPFix, IPFixParser};
use variable_versions::v9::{V9, V9Parser};

use nom_derive::{Nom, Parse};
use serde::Serialize;

use std::collections::HashSet;

// Re-export scoped parser types for convenience
pub use scoped_parser::{
    AutoScopedParser, IpfixSourceKey, RouterScopedParser, ScopingInfo, V9SourceKey,
    extract_scoping_info,
};

// Re-export template event types for convenience
pub use template_events::{TemplateEvent, TemplateHook, TemplateHooks, TemplateProtocol};

/// Enum of supported Netflow Versions
#[derive(Debug, Clone, Serialize)]
pub enum NetflowPacket {
    /// Version 5
    V5(V5),
    /// Version 7
    V7(V7),
    /// Version 9
    V9(V9),
    /// IPFix
    IPFix(IPFix),
}

impl NetflowPacket {
    pub fn is_v5(&self) -> bool {
        matches!(self, Self::V5(_v))
    }
    pub fn is_v7(&self) -> bool {
        matches!(self, Self::V7(_v))
    }
    pub fn is_v9(&self) -> bool {
        matches!(self, Self::V9(_v))
    }
    pub fn is_ipfix(&self) -> bool {
        matches!(self, Self::IPFix(_v))
    }
    #[cfg(feature = "netflow_common")]
    pub fn as_netflow_common(&self) -> Result<NetflowCommon, NetflowCommonError> {
        self.try_into()
    }
}

/// Result of parsing NetFlow packets from a byte buffer.
///
/// This struct contains both successfully parsed packets and an optional error
/// that stopped parsing. This ensures no data loss when parsing fails partway
/// through a buffer.
///
/// # Examples
///
/// ```rust
/// use netflow_parser::NetflowParser;
///
/// let mut parser = NetflowParser::default();
/// let buffer = vec![/* netflow data */];
///
/// let result = parser.parse_bytes(&buffer);
///
/// // Process all successfully parsed packets
/// for packet in result.packets {
///     println!("Parsed packet");
/// }
///
/// // Check if parsing stopped due to error
/// if let Some(error) = result.error {
///     eprintln!("Parsing stopped: {}", error);
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ParseResult {
    /// Successfully parsed NetFlow packets.
    /// This vec contains all packets that were successfully parsed before
    /// any error occurred.
    pub packets: Vec<NetflowPacket>,

    /// Optional error that stopped parsing.
    /// - `None` means all data was successfully parsed
    /// - `Some(error)` means parsing stopped due to an error, but `packets`
    ///   contains all successfully parsed packets up to that point
    pub error: Option<NetflowError>,
}

impl ParseResult {
    /// Returns true if parsing completed without errors.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let mut parser = NetflowParser::default();
    /// let result = parser.parse_bytes(&[]);
    /// assert!(result.is_ok());
    /// ```
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    /// Returns true if parsing stopped due to an error.
    ///
    /// Note: Even when this returns `true`, `packets` may contain
    /// successfully parsed packets.
    pub fn is_err(&self) -> bool {
        self.error.is_some()
    }
}

#[derive(Nom)]
/// Generic Netflow Header for shared versions
struct GenericNetflowHeader {
    version: u16,
}

/// Main parser for Netflow packets supporting V5, V7, V9, and IPFIX.
///
/// Use [`NetflowParser::builder()`] for ergonomic configuration with the builder pattern,
/// or [`NetflowParser::default()`] for quick setup with defaults.
///
/// # ⚠️ Multi-Source Deployments
///
/// **IMPORTANT**: If you're parsing NetFlow from multiple routers or sources,
/// use [`AutoScopedParser`] instead of `NetflowParser`
/// to prevent template cache collisions.
///
/// Template IDs are **NOT unique across sources**. Different routers can (and often do)
/// use the same template ID with completely different schemas. When multiple sources
/// share a single `NetflowParser`, their templates collide in the cache, causing:
///
/// - Template thrashing (constant eviction and re-learning)
/// - Parsing failures (data parsed with wrong template)
/// - Performance degradation (high cache miss rate)
///
/// ## Single Source (✅ Use NetflowParser)
///
/// ```rust
/// use netflow_parser::NetflowParser;
///
/// let mut parser = NetflowParser::default();
/// let data = [0u8; 72]; // Example NetFlow data
/// // Single router/source - no collisions possible
/// let packets = parser.parse_bytes(&data);
/// ```
///
/// ## Multiple Sources (✅ Use AutoScopedParser)
///
/// ```rust
/// use netflow_parser::AutoScopedParser;
/// use std::net::SocketAddr;
///
/// let mut parser = AutoScopedParser::new();
/// let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();
/// let data = [0u8; 72]; // Example NetFlow data
/// // Each source gets isolated template cache (RFC-compliant)
/// let packets = parser.parse_from_source(source, &data);
/// ```
///
/// # Examples
///
/// ```rust
/// use netflow_parser::NetflowParser;
/// use netflow_parser::variable_versions::ttl::TtlConfig;
/// use std::time::Duration;
///
/// // Using builder pattern (recommended)
/// let parser = NetflowParser::builder()
///     .with_cache_size(2000)
///     .with_ttl(TtlConfig::new(Duration::from_secs(7200)))
///     .build()
///     .expect("Failed to build parser");
///
/// // Using default
/// let parser = NetflowParser::default();
/// ```
#[derive(Debug)]
pub struct NetflowParser {
    pub v9_parser: V9Parser,
    pub ipfix_parser: IPFixParser,
    pub allowed_versions: HashSet<u16>,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
    /// Template event hooks for monitoring template lifecycle events.
    template_hooks: TemplateHooks,
}

/// Statistics about template cache utilization.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of cached templates
    pub current_size: usize,
    /// Maximum cache size before LRU eviction
    pub max_size: usize,
    /// TTL configuration (if enabled)
    pub ttl_config: Option<variable_versions::ttl::TtlConfig>,
    /// Performance metrics snapshot
    pub metrics: variable_versions::metrics::CacheMetricsSnapshot,
}

/// Builder for configuring and constructing a [`NetflowParser`].
///
/// # Examples
///
/// ```rust
/// use netflow_parser::NetflowParser;
/// use netflow_parser::variable_versions::ttl::TtlConfig;
/// use std::collections::HashSet;
/// use std::time::Duration;
///
/// let parser = NetflowParser::builder()
///     .with_cache_size(2000)
///     .with_ttl(TtlConfig::new(Duration::from_secs(7200)))
///     .with_allowed_versions([5, 9, 10].into())
///     .with_max_error_sample_size(512)
///     .build()
///     .expect("Failed to build parser");
/// ```
#[derive(Clone)]
pub struct NetflowParserBuilder {
    v9_config: Config,
    ipfix_config: Config,
    allowed_versions: HashSet<u16>,
    max_error_sample_size: usize,
    template_hooks: TemplateHooks,
}

// Custom Debug implementation to avoid printing closures
impl std::fmt::Debug for NetflowParserBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetflowParserBuilder")
            .field("v9_config", &self.v9_config)
            .field("ipfix_config", &self.ipfix_config)
            .field("allowed_versions", &self.allowed_versions)
            .field("max_error_sample_size", &self.max_error_sample_size)
            .field(
                "template_hooks",
                &format!("{} hooks", self.template_hooks.len()),
            )
            .finish()
    }
}

impl Default for NetflowParserBuilder {
    fn default() -> Self {
        Self {
            v9_config: Config::new(1000, None),
            ipfix_config: Config::new(1000, None),
            allowed_versions: [5, 7, 9, 10].iter().cloned().collect(),
            max_error_sample_size: 256,
            template_hooks: TemplateHooks::new(),
        }
    }
}

impl NetflowParserBuilder {
    /// Sets the template cache size for both V9 and IPFIX parsers.
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum number of templates to cache (must be > 0)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_cache_size(2000)
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.v9_config.max_template_cache_size = size;
        self.ipfix_config.max_template_cache_size = size;
        self
    }

    /// Sets the V9 parser template cache size independently.
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum number of templates to cache (must be > 0)
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_v9_cache_size(mut self, size: usize) -> Self {
        self.v9_config.max_template_cache_size = size;
        self
    }

    /// Sets the IPFIX parser template cache size independently.
    ///
    /// * `size` - Maximum number of templates to cache (must be > 0)
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_ipfix_cache_size(mut self, size: usize) -> Self {
        self.ipfix_config.max_template_cache_size = size;
        self
    }

    /// Sets the maximum field count for both V9 and IPFIX parsers.
    ///
    /// This limits the number of fields allowed in a single template to prevent DoS attacks.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of fields per template (default: 10,000)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_max_field_count(5000)  // More restrictive limit
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_max_field_count(mut self, count: usize) -> Self {
        self.v9_config.max_field_count = count;
        self.ipfix_config.max_field_count = count;
        self
    }

    /// Sets the V9 parser maximum field count independently.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of fields per template
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_v9_max_field_count(mut self, count: usize) -> Self {
        self.v9_config.max_field_count = count;
        self
    }

    /// Sets the IPFIX parser maximum field count independently.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of fields per template
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_ipfix_max_field_count(mut self, count: usize) -> Self {
        self.ipfix_config.max_field_count = count;
        self
    }

    /// Sets the TTL configuration for both V9 and IPFIX parsers.
    ///
    /// # Arguments
    ///
    /// * `ttl` - TTL configuration (time-based)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    /// use netflow_parser::variable_versions::ttl::TtlConfig;
    /// use std::time::Duration;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_ttl(TtlConfig::new(Duration::from_secs(7200)))
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_ttl(mut self, ttl: variable_versions::ttl::TtlConfig) -> Self {
        self.v9_config.ttl_config = Some(ttl.clone());
        self.ipfix_config.ttl_config = Some(ttl);
        self
    }

    /// Sets the TTL configuration for V9 parser independently.
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_v9_ttl(mut self, ttl: variable_versions::ttl::TtlConfig) -> Self {
        self.v9_config.ttl_config = Some(ttl);
        self
    }

    /// Sets the TTL configuration for IPFIX parser independently.
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_ipfix_ttl(mut self, ttl: variable_versions::ttl::TtlConfig) -> Self {
        self.ipfix_config.ttl_config = Some(ttl);
        self
    }

    /// Sets which Netflow versions are allowed to be parsed.
    ///
    /// # Arguments
    ///
    /// * `versions` - Set of allowed version numbers (5, 7, 9, 10)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// // Only parse V9 and IPFIX
    /// let parser = NetflowParser::builder()
    ///     .with_allowed_versions([9, 10].into())
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_allowed_versions(mut self, versions: HashSet<u16>) -> Self {
        self.allowed_versions = versions;
        self
    }

    /// Sets the maximum error sample size for error reporting.
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum bytes to include in error messages
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_max_error_sample_size(512)
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn with_max_error_sample_size(mut self, size: usize) -> Self {
        self.max_error_sample_size = size;
        self.v9_config.max_error_sample_size = size;
        self.ipfix_config.max_error_sample_size = size;
        self
    }

    /// Registers a custom enterprise field definition for both V9 and IPFIX parsers.
    ///
    /// This allows library users to define their own enterprise-specific fields without
    /// modifying the library source code. Registered fields will be parsed according to
    /// their specified data type instead of falling back to raw bytes.
    ///
    /// # Arguments
    ///
    /// * `def` - Enterprise field definition containing enterprise number, field number, name, and data type
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    /// use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;
    /// use netflow_parser::variable_versions::data_number::FieldDataType;
    ///
    /// let parser = NetflowParser::builder()
    ///     .register_enterprise_field(EnterpriseFieldDef::new(
    ///         12345,  // Enterprise number
    ///         1,      // Field number
    ///         "customMetric",
    ///         FieldDataType::UnsignedDataNumber,
    ///     ))
    ///     .register_enterprise_field(EnterpriseFieldDef::new(
    ///         12345,
    ///         2,
    ///         "customApplicationName",
    ///         FieldDataType::String,
    ///     ))
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn register_enterprise_field(mut self, def: EnterpriseFieldDef) -> Self {
        self.v9_config.enterprise_registry.register(def.clone());
        self.ipfix_config.enterprise_registry.register(def);
        self
    }

    /// Registers multiple custom enterprise field definitions at once.
    ///
    /// # Arguments
    ///
    /// * `defs` - Iterator of enterprise field definitions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    /// use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;
    /// use netflow_parser::variable_versions::data_number::FieldDataType;
    ///
    /// let fields = vec![
    ///     EnterpriseFieldDef::new(12345, 1, "field1", FieldDataType::UnsignedDataNumber),
    ///     EnterpriseFieldDef::new(12345, 2, "field2", FieldDataType::String),
    ///     EnterpriseFieldDef::new(12345, 3, "field3", FieldDataType::Ip4Addr),
    /// ];
    ///
    /// let parser = NetflowParser::builder()
    ///     .register_enterprise_fields(fields)
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn register_enterprise_fields(
        mut self,
        defs: impl IntoIterator<Item = EnterpriseFieldDef>,
    ) -> Self {
        // Collect once to avoid unnecessary cloning
        let defs: Vec<_> = defs.into_iter().collect();

        // Register clones in V9 registry
        for def in &defs {
            self.v9_config.enterprise_registry.register(def.clone());
        }

        // Move originals into IPFIX registry (no clone needed)
        for def in defs {
            self.ipfix_config.enterprise_registry.register(def);
        }

        self
    }

    /// Hint for single-source deployments (documentation only).
    ///
    /// This method exists for clarity and returns `self` unchanged.
    /// Use when parsing from a single router or source.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::builder()
    ///     .single_source()  // Documents intent
    ///     .with_cache_size(1000)
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn single_source(self) -> Self {
        self
    }

    /// Creates an AutoScopedParser for multi-source deployments.
    ///
    /// **Recommended** for parsing NetFlow from multiple routers. Each source
    /// gets an isolated template cache, preventing template ID collisions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    /// use std::net::SocketAddr;
    ///
    /// // Multi-source deployment
    /// let mut parser = NetflowParser::builder()
    ///     .with_cache_size(2000)
    ///     .multi_source();
    ///
    /// let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();
    /// let data = [0u8; 72]; // Example data
    /// let packets = parser.parse_from_source(source, &data);
    /// ```
    ///
    /// Equivalent to:
    /// ```rust
    /// use netflow_parser::{NetflowParser, AutoScopedParser};
    ///
    /// let builder = NetflowParser::builder().with_cache_size(2000);
    /// let _parser = AutoScopedParser::with_builder(builder);
    /// ```
    pub fn multi_source(self) -> AutoScopedParser {
        AutoScopedParser::with_builder(self)
    }

    /// Builds the configured [`NetflowParser`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Template cache size is 0
    /// - Parser initialization fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_cache_size(2000)
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    /// Registers a callback for template lifecycle events.
    ///
    /// This allows you to monitor template operations in real-time, including:
    /// - Template learning (new templates added to cache)
    /// - Template collisions (template ID reused)
    /// - Template evictions (LRU policy removed template)
    /// - Template expirations (TTL-based removal)
    /// - Missing templates (data packet for unknown template)
    ///
    /// # Arguments
    ///
    /// * `hook` - A closure that will be called for each template event
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::{NetflowParser, TemplateEvent, TemplateProtocol};
    ///
    /// let parser = NetflowParser::builder()
    ///     .on_template_event(|event| {
    ///         match event {
    ///             TemplateEvent::Learned { template_id, protocol } => {
    ///                 println!("Learned template {}", template_id);
    ///             }
    ///             TemplateEvent::Collision { template_id, protocol } => {
    ///                 eprintln!("⚠️  Template collision: {}", template_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     })
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use = "builder methods consume self and return a new builder; the return value must be used"]
    pub fn on_template_event<F>(mut self, hook: F) -> Self
    where
        F: Fn(&TemplateEvent) + Send + Sync + 'static,
    {
        self.template_hooks.register(hook);
        self
    }

    /// Builds the `NetflowParser` with the configured settings.
    ///
    /// Returns an error if the parser configuration is invalid.
    pub fn build(self) -> Result<NetflowParser, String> {
        let v9_parser =
            V9Parser::try_new(self.v9_config).map_err(|e| format!("V9 parser error: {}", e))?;
        let ipfix_parser = IPFixParser::try_new(self.ipfix_config)
            .map_err(|e| format!("IPFIX parser error: {}", e))?;

        Ok(NetflowParser {
            v9_parser,
            ipfix_parser,
            allowed_versions: self.allowed_versions,
            max_error_sample_size: self.max_error_sample_size,
            template_hooks: self.template_hooks,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ParsedNetflow<'a> {
    Success {
        packet: NetflowPacket,
        remaining: &'a [u8],
    },
    Error {
        error: NetflowError,
    },
    UnallowedVersion,
}

/// Comprehensive error type for NetFlow parsing operations.
///
/// Provides rich context about parsing failures including offset, error kind,
/// and relevant data for debugging.
#[derive(Debug, Clone, Serialize)]
pub enum NetflowError {
    /// Incomplete data - more bytes needed to parse a complete packet.
    ///
    /// Contains the number of bytes available and a description of what was expected.
    Incomplete {
        /// Number of bytes that were available
        available: usize,
        /// Description of what was being parsed
        context: String,
    },

    /// Unknown or unsupported NetFlow version encountered.
    ///
    /// The version number found in the packet header doesn't match any known
    /// NetFlow version (V5, V7, V9, IPFIX).
    UnsupportedVersion {
        /// The version number found in the packet
        version: u16,
        /// Offset in bytes where the version was found
        offset: usize,
        /// Sample of the packet data for debugging
        sample: Vec<u8>,
    },

    /// Version is valid but filtered out by `allowed_versions` configuration.
    ///
    /// The parser was configured to only accept certain versions and this
    /// version was explicitly excluded.
    FilteredVersion {
        /// The version number that was filtered
        version: u16,
    },

    /// Template definition is required but not found in cache.
    ///
    /// For V9 and IPFIX, data packets reference template IDs that must be
    /// learned from template packets. This error occurs when data arrives
    /// before (or without) its corresponding template.
    MissingTemplate {
        /// The template ID that was not found
        template_id: u16,
        /// The protocol (V9 or IPFIX)
        protocol: TemplateProtocol,
        /// List of currently cached template IDs for this protocol
        available_templates: Vec<u16>,
        /// Raw packet data that couldn't be parsed
        raw_data: Vec<u8>,
    },

    /// Parsing error with detailed context.
    ///
    /// Generic parsing failure with information about what failed and where.
    ParseError {
        /// Offset in bytes where the error occurred
        offset: usize,
        /// Description of what was being parsed
        context: String,
        /// The specific error kind
        kind: String,
        /// Sample of remaining data for debugging
        remaining: Vec<u8>,
    },

    /// Partial parse - some data was parsed but errors occurred.
    ///
    /// Used when processing continues despite errors (e.g., some flowsets
    /// parsed successfully but others failed).
    Partial {
        /// Description of the partial parse result
        message: String,
    },
}

impl std::fmt::Display for NetflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetflowError::Incomplete { available, context } => {
                write!(
                    f,
                    "Incomplete data: {} (only {} bytes available)",
                    context, available
                )
            }
            NetflowError::UnsupportedVersion {
                version, offset, ..
            } => {
                write!(
                    f,
                    "Unsupported NetFlow version {} at offset {}",
                    version, offset
                )
            }
            NetflowError::FilteredVersion { version } => {
                write!(
                    f,
                    "NetFlow version {} filtered out by allowed_versions configuration",
                    version
                )
            }
            NetflowError::MissingTemplate {
                template_id,
                protocol,
                available_templates,
                ..
            } => {
                write!(
                    f,
                    "Missing template {} for {:?} (available: {:?})",
                    template_id, protocol, available_templates
                )
            }
            NetflowError::ParseError {
                offset,
                context,
                kind,
                ..
            } => {
                write!(
                    f,
                    "Parse error at offset {}: {} ({})",
                    offset, context, kind
                )
            }
            NetflowError::Partial { message } => {
                write!(f, "Partial parse error: {}", message)
            }
        }
    }
}

impl std::error::Error for NetflowError {}

// Legacy type alias for backwards compatibility during migration
#[deprecated(since = "0.8.0", note = "Use NetflowError instead")]
pub type NetflowPacketError = NetflowError;

#[deprecated(since = "0.8.0", note = "Use NetflowError instead")]
pub type NetflowParseError = NetflowError;

#[derive(Debug, Clone, Serialize)]
pub struct PartialParse {
    pub version: u16,
    pub remaining: Vec<u8>,
    pub error: String,
}

/// Iterator that yields NetflowPacket items from a byte buffer without allocating a Vec.
/// Maintains parser state for template caching (V9/IPFIX).
pub struct NetflowPacketIterator<'a> {
    parser: &'a mut NetflowParser,
    remaining: &'a [u8],
    errored: bool,
}

impl<'a> NetflowPacketIterator<'a> {
    /// Returns the unconsumed bytes remaining in the buffer.
    ///
    /// This is useful for:
    /// - Debugging: See how much data was consumed
    /// - Mixed protocols: Process non-netflow data after netflow packets
    /// - Resumption: Know where parsing stopped
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let mut parser = NetflowParser::default();
    /// let mut iter = parser.iter_packets(&v5_packet);
    ///
    /// while let Some(_packet) = iter.next() {
    ///     // Process packet
    /// }
    ///
    /// // Check how many bytes remain unconsumed
    /// assert_eq!(iter.remaining().len(), 0);
    /// ```
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    /// Returns true if all bytes have been consumed or an error occurred.
    ///
    /// This is useful for validation and ensuring complete buffer processing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let mut parser = NetflowParser::default();
    /// let mut iter = parser.iter_packets(&v5_packet);
    ///
    /// // Consume all packets
    /// for _packet in &mut iter {
    ///     // Process packet
    /// }
    ///
    /// assert!(iter.is_complete());
    /// ```
    pub fn is_complete(&self) -> bool {
        self.remaining.is_empty() || self.errored
    }
}

impl<'a> Iterator for NetflowPacketIterator<'a> {
    type Item = Result<NetflowPacket, NetflowError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Stop if we've errored or no bytes remain
        if self.errored || self.remaining.is_empty() {
            return None;
        }

        match self.parser.parse_packet_by_version(self.remaining) {
            ParsedNetflow::Success {
                packet,
                remaining: new_remaining,
            } => {
                self.remaining = new_remaining;
                Some(Ok(packet))
            }
            ParsedNetflow::UnallowedVersion => {
                self.errored = true;
                None
            }
            ParsedNetflow::Error { error } => {
                self.errored = true;
                Some(Err(error))
            }
        }
    }
}

impl Default for NetflowParser {
    fn default() -> Self {
        Self {
            v9_parser: V9Parser::default(),
            ipfix_parser: IPFixParser::default(),
            allowed_versions: [5, 7, 9, 10].iter().cloned().collect(),
            max_error_sample_size: 256,
            template_hooks: TemplateHooks::new(),
        }
    }
}

impl NetflowParser {
    /// Creates a new builder for configuring a [`NetflowParser`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    /// use netflow_parser::variable_versions::ttl::TtlConfig;
    /// use std::time::Duration;
    ///
    /// let parser = NetflowParser::builder()
    ///     .with_cache_size(2000)
    ///     .with_ttl(TtlConfig::new(Duration::from_secs(7200)))
    ///     .build()
    ///     .expect("Failed to build parser");
    /// ```
    pub fn builder() -> NetflowParserBuilder {
        NetflowParserBuilder::default()
    }

    /// Gets statistics about the V9 template cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// let stats = parser.v9_cache_stats();
    /// println!("V9 cache: {}/{} templates", stats.current_size, stats.max_size);
    /// ```
    pub fn v9_cache_stats(&self) -> CacheStats {
        CacheStats {
            current_size: self.v9_parser.templates.len()
                + self.v9_parser.options_templates.len(),
            max_size: self.v9_parser.max_template_cache_size,
            ttl_config: self.v9_parser.ttl_config.clone(),
            metrics: self.v9_parser.metrics.snapshot(),
        }
    }

    /// Gets statistics about the IPFIX template cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// let stats = parser.ipfix_cache_stats();
    /// println!("IPFIX cache: {}/{} templates", stats.current_size, stats.max_size);
    /// ```
    pub fn ipfix_cache_stats(&self) -> CacheStats {
        CacheStats {
            current_size: self.ipfix_parser.templates.len()
                + self.ipfix_parser.v9_templates.len()
                + self.ipfix_parser.ipfix_options_templates.len()
                + self.ipfix_parser.v9_options_templates.len(),
            max_size: self.ipfix_parser.max_template_cache_size,
            ttl_config: self.ipfix_parser.ttl_config.clone(),
            metrics: self.ipfix_parser.metrics.snapshot(),
        }
    }

    /// Lists all cached V9 template IDs.
    ///
    /// Note: This returns template IDs from both regular and options templates.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// let template_ids = parser.v9_template_ids();
    /// println!("Cached V9 templates: {:?}", template_ids);
    /// ```
    pub fn v9_template_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self.v9_parser.templates.iter().map(|(id, _)| *id).collect();
        ids.extend(self.v9_parser.options_templates.iter().map(|(id, _)| *id));
        ids.sort_unstable();
        ids
    }

    /// Lists all cached IPFIX template IDs.
    ///
    /// Note: This returns template IDs from both IPFIX and V9-format templates (IPFIX can contain both).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// let template_ids = parser.ipfix_template_ids();
    /// println!("Cached IPFIX templates: {:?}", template_ids);
    /// ```
    pub fn ipfix_template_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self
            .ipfix_parser
            .templates
            .iter()
            .map(|(id, _)| *id)
            .collect();
        ids.extend(self.ipfix_parser.v9_templates.iter().map(|(id, _)| *id));
        ids.extend(
            self.ipfix_parser
                .ipfix_options_templates
                .iter()
                .map(|(id, _)| *id),
        );
        ids.extend(
            self.ipfix_parser
                .v9_options_templates
                .iter()
                .map(|(id, _)| *id),
        );
        ids.sort_unstable();
        ids
    }

    /// Checks if a V9 template with the given ID is cached.
    ///
    /// Note: This uses `peek()` which does not affect LRU ordering.
    ///
    /// # Arguments
    ///
    /// * `template_id` - The template ID to check
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// if parser.has_v9_template(256) {
    ///     println!("Template 256 is cached");
    /// }
    /// ```
    pub fn has_v9_template(&self, template_id: u16) -> bool {
        self.v9_parser.templates.peek(&template_id).is_some()
            || self
                .v9_parser
                .options_templates
                .peek(&template_id)
                .is_some()
    }

    /// Checks if an IPFIX template with the given ID is cached.
    ///
    /// Note: This uses `peek()` which does not affect LRU ordering.
    ///
    /// # Arguments
    ///
    /// * `template_id` - The template ID to check
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let parser = NetflowParser::default();
    /// if parser.has_ipfix_template(256) {
    ///     println!("Template 256 is cached");
    /// }
    /// ```
    pub fn has_ipfix_template(&self, template_id: u16) -> bool {
        self.ipfix_parser.templates.peek(&template_id).is_some()
            || self.ipfix_parser.v9_templates.peek(&template_id).is_some()
            || self
                .ipfix_parser
                .ipfix_options_templates
                .peek(&template_id)
                .is_some()
            || self
                .ipfix_parser
                .v9_options_templates
                .peek(&template_id)
                .is_some()
    }

    /// Clears all cached V9 templates.
    ///
    /// This is useful for testing or when you need to force template re-learning.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let mut parser = NetflowParser::default();
    /// parser.clear_v9_templates();
    /// ```
    pub fn clear_v9_templates(&mut self) {
        self.v9_parser.templates.clear();
        self.v9_parser.options_templates.clear();
    }

    /// Clears all cached IPFIX templates.
    ///
    /// This is useful for testing or when you need to force template re-learning.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let mut parser = NetflowParser::default();
    /// parser.clear_ipfix_templates();
    /// ```
    pub fn clear_ipfix_templates(&mut self) {
        self.ipfix_parser.templates.clear();
        self.ipfix_parser.v9_templates.clear();
        self.ipfix_parser.ipfix_options_templates.clear();
        self.ipfix_parser.v9_options_templates.clear();
    }

    /// Triggers template event hooks.
    ///
    /// This method is called internally by template operations to notify
    /// registered hooks about template lifecycle events. It can also be called
    /// manually for testing or custom integration scenarios.
    ///
    /// # Arguments
    ///
    /// * `event` - The template event to trigger
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::{NetflowParser, TemplateEvent, TemplateProtocol};
    ///
    /// let parser = NetflowParser::default();
    /// parser.trigger_template_event(TemplateEvent::Learned {
    ///     template_id: 256,
    ///     protocol: TemplateProtocol::V9,
    /// });
    /// ```
    #[inline]
    pub fn trigger_template_event(&self, event: TemplateEvent) {
        self.template_hooks.trigger(&event);
    }

    /// Parses NetFlow packets from a byte slice, preserving all successfully parsed packets.
    ///
    /// This function parses packets in sequence and returns a [`ParseResult`] containing both
    /// successfully parsed packets and an optional error. **No data is lost** - if parsing fails
    /// partway through, you still get all packets parsed before the error.
    ///
    /// # Arguments
    ///
    /// * `packet` - Byte slice containing NetFlow packet(s)
    ///
    /// # Returns
    ///
    /// [`ParseResult`] with:
    /// * `packets` - All successfully parsed packets (even if error occurred)
    /// * `error` - `None` if fully successful, `Some(error)` if parsing stopped
    ///
    /// # Examples
    ///
    /// ## Basic usage
    ///
    /// ```rust
    /// use netflow_parser::NetflowParser;
    ///
    /// let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let result = NetflowParser::default().parse_bytes(&v5_packet);
    ///
    /// // Process all packets
    /// for packet in result.packets {
    ///     println!("Parsed packet");
    /// }
    ///
    /// // Check for errors
    /// if let Some(e) = result.error {
    ///     eprintln!("Error: {}", e);
    /// }
    /// ```
    ///
    /// ## With JSON serialization
    ///
    /// ```rust
    /// use serde_json::json;
    /// use netflow_parser::NetflowParser;
    ///
    /// let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let result = NetflowParser::default().parse_bytes(&v5_packet);
    /// println!("{}", json!(result.packets).to_string());
    /// ```
    ///
    #[inline]
    pub fn parse_bytes(&mut self, packet: &[u8]) -> ParseResult {
        if packet.is_empty() {
            return ParseResult {
                packets: vec![],
                error: None,
            };
        }

        let mut packets = Vec::new();
        let mut remaining = packet;
        let mut error = None;

        while !remaining.is_empty() {
            match self.parse_packet_by_version(remaining) {
                ParsedNetflow::Success {
                    packet,
                    remaining: new_remaining,
                } => {
                    packets.push(packet);
                    remaining = new_remaining;
                }
                ParsedNetflow::UnallowedVersion => {
                    break;
                }
                ParsedNetflow::Error { error: e } => {
                    // Store error but keep successfully parsed packets
                    error = Some(e);
                    break;
                }
            }
        }

        ParseResult { packets, error }
    }

    /// Returns an iterator that yields NetflowPacket items without allocating a Vec.
    /// This is useful for processing large batches of packets without collecting all results in memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::{NetflowParser, NetflowPacket};
    ///
    /// let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
    /// let mut parser = NetflowParser::default();
    ///
    /// for result in parser.iter_packets(&v5_packet) {
    ///     match result {
    ///         Ok(NetflowPacket::V5(v5)) => println!("V5 packet: {:?}", v5.header.version),
    ///         Err(e) => println!("Error: {:?}", e),
    ///         _ => (),
    ///     }
    /// }
    /// ```
    #[inline]
    pub fn iter_packets<'a>(&'a mut self, packet: &'a [u8]) -> NetflowPacketIterator<'a> {
        NetflowPacketIterator {
            parser: self,
            remaining: packet,
            errored: false,
        }
    }

    #[inline]
    fn parse_packet_by_version<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match GenericNetflowHeader::parse(packet) {
            Ok((remaining, header)) if self.allowed_versions.contains(&header.version) => {
                match header.version {
                    5 => V5Parser::parse(remaining),
                    7 => V7Parser::parse(remaining),
                    9 => self.v9_parser.parse(remaining),
                    10 => self.ipfix_parser.parse(remaining),
                    _ => ParsedNetflow::Error {
                        error: NetflowError::UnsupportedVersion {
                            version: header.version,
                            offset: 0,
                            sample: packet[..packet.len().min(self.max_error_sample_size)]
                                .to_vec(),
                        },
                    },
                }
            }
            Ok(_) => {
                // Version is valid but filtered by allowed_versions
                ParsedNetflow::UnallowedVersion
            }
            Err(e) => ParsedNetflow::Error {
                error: NetflowError::Incomplete {
                    available: packet.len(),
                    context: format!("NetFlow header: {}", e),
                },
            },
        }
    }

    /// Takes a Netflow packet slice and returns a vector of Parsed NetflowCommonFlowSet
    #[cfg(feature = "netflow_common")]
    #[inline]
    pub fn parse_bytes_as_netflow_common_flowsets(
        &mut self,
        packet: &[u8],
    ) -> Vec<NetflowCommonFlowSet> {
        let netflow_packets = self.parse_bytes(packet);
        netflow_packets
            .packets
            .iter()
            .flat_map(|n| n.as_netflow_common().unwrap_or_default().flowsets)
            .collect()
    }
}
