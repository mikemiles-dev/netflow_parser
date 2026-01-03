# 0.8.0

  * **Template Cache Metrics:**
    * Added comprehensive performance metrics tracking for V9 and IPFIX template caches
    * New `CacheMetrics` struct with atomic counters for:
      * `hits` - Successful template lookups
      * `misses` - Failed template lookups (template not in cache)
      * `evictions` - Templates removed due to LRU policy when cache is full
      * `collisions` - Template ID reused (same ID, potentially different definition)
      * `expired` - Templates removed due to TTL expiration
      * `insertions` - Total template insertions
    * `CacheMetricsSnapshot` provides point-in-time view with helper methods:
      * `hit_rate()` - Calculate cache hit rate (0.0 to 1.0)
      * `miss_rate()` - Calculate cache miss rate (0.0 to 1.0)
      * `total_lookups()` - Total number of lookups (hits + misses)
    * Metrics accessible via updated `CacheStats` struct returned by:
      * `NetflowParser::v9_cache_stats()`
      * `NetflowParser::ipfix_cache_stats()`
    * All metrics use atomic operations for thread-safe reads
    * New module: `src/variable_versions/metrics.rs`

  * **Template Collision Detection:**
    * Automatic tracking when template IDs are reused with potentially different definitions
    * Critical for multi-source deployments where different routers may use the same template ID
    * Collision counter helps identify when `RouterScopedParser` should be used
    * Integrated into V9 and IPFIX template insertion logic

  * **Enhanced NoTemplate Error Context:**
    * **BREAKING CHANGE:** `FlowSetBody::NoTemplate` variant changed from `Vec<u8>` to `NoTemplateInfo` struct
    * New `NoTemplateInfo` struct provides rich debugging context:
      * `template_id` - The template ID that was requested but not found
      * `available_templates` - List of currently cached template IDs
      * `raw_data` - Unparsed flowset data for potential retry after template arrives
    * Helper methods for creating `NoTemplateInfo`:
      * `new()` - Create with template ID and raw data
      * `with_available_templates()` - Automatically populate available templates from parser
    * Makes debugging missing template issues significantly easier
    * See "Handling Missing Templates" section in README for usage examples

  * **AutoScopedParser - RFC-Compliant Automatic Scoping (Recommended):**
    * **NEW:** High-level parser that automatically implements RFC-compliant template scoping
    * Extracts scoping identifiers from packet headers without user intervention
    * Automatic scoping per RFC specifications:
      * **NetFlow v9**: Uses `(source_addr, source_id)` composite key per RFC 3954
      * **IPFIX**: Uses `(source_addr, observation_domain_id)` composite key per RFC 7011
      * **NetFlow v5/v7**: Uses `source_addr` only (no scoping IDs in these versions)
    * Solves the template collision problem correctly:
      * Prevents collisions when multiple observation domains from same router use same template IDs
      * No manual key management required
      * Automatically handles mixed protocol deployments
    * Key methods:
      * `parse_from_source(addr, data)` - Parse with automatic scoping
      * `iter_packets_from_source(addr, data)` - Iterator API
      * `ipfix_source_count()`, `v9_source_count()`, `legacy_source_count()` - Per-protocol counts
      * `ipfix_stats()`, `v9_stats()`, `legacy_stats()` - Per-protocol statistics
      * `clear_all_templates()` - Clear all cached templates
    * Constructor options:
      * `new()` - Create with default parser configuration
      * `with_builder()` - Use custom `NetflowParserBuilder` for all sources
    * New types for RFC-compliant scoping:
      * `IpfixSourceKey { addr, observation_domain_id }` - IPFIX composite key
      * `V9SourceKey { addr, source_id }` - NetFlow v9 composite key
      * `ScopingInfo` enum - Result of header extraction
      * `extract_scoping_info(data)` - Utility function for manual header parsing
    * **Recommended for production deployments** - automatically does the right thing
    * Re-exported at crate root as `netflow_parser::AutoScopedParser`

  * **RouterScopedParser for Multi-Source Deployments:**
    * Generic high-level API for managing NetFlow from multiple routers/exporters
    * Maintains separate template caches per source to prevent template ID collisions
    * Generic over source identifier type - supports any hashable key:
      * `SocketAddr` for UDP sources
      * `String` for named routers
      * `u32` for observation domain IDs
      * Custom types implementing `Hash + Eq`
    * Key methods:
      * `parse_from_source()` - Parse data from specific source (auto-creates parser)
      * `iter_packets_from_source()` - Iterator API for efficient parsing
      * `get_source_stats()` - Get cache stats for specific source
      * `all_stats()` - Get stats for all sources
      * `clear_source_templates()` - Clear templates for specific source
      * `clear_all_templates()` - Clear templates for all sources
      * `remove_source()` - Remove inactive source parser
    * Constructor options:
      * `new()` - Create with default parser configuration
      * `with_builder()` - Use custom `NetflowParserBuilder` for all sources
    * **Use AutoScopedParser for standard deployments; use RouterScopedParser for custom scoping needs**
    * New module: `src/scoped_parser.rs`
    * Re-exported at crate root as `netflow_parser::RouterScopedParser`

  * **Comprehensive Template Management Documentation:**
    * New "Template Management Guide" section in README covering:
      * Template cache metrics - How to track and interpret performance
      * Multi-source deployments - RFC-compliant scoping with `AutoScopedParser` (recommended)
      * Advanced custom scoping with `RouterScopedParser`
      * Template collision detection - Identifying and resolving collisions
      * Handling missing templates - Strategies for out-of-order packet arrival
      * Template lifecycle management - Cache inspection and cleanup
      * Best practices for V9/IPFIX template management
    * RFC compliance documentation:
      * NetFlow v9 (RFC 3954) scoping requirements explained
      * IPFIX (RFC 7011) scoping requirements explained
      * When composite keys `(addr, observation_domain_id)` are required
    * Updated Table of Contents with new sections
    * All features include detailed code examples
    * Enhanced thread safety documentation linking to template isolation

  * **New Example:**
    * `examples/template_management_demo.rs` - Comprehensive demonstration of:
      * Cache metrics monitoring and interpretation
      * Multi-source parsing with `RouterScopedParser`
      * Template collision detection and warnings
      * Missing template handling and retry strategies
      * Template lifecycle management (inspection, clearing)
    * Runnable example showing all new template management features

  * **Updated Examples:**
    * `examples/netflow_udp_listener_tokio.rs` - **Updated to use `AutoScopedParser` (RFC-compliant)**:
      * Demonstrates RFC-compliant automatic scoping
      * Shows IPFIX sources with `(addr, observation_domain_id)` scoping
      * Shows NetFlow v9 sources with `(addr, source_id)` scoping
      * Enhanced metrics reporting per protocol type (IPFIX, V9, Legacy)
      * Displays observation domain IDs and source IDs in output
      * Demonstrates async usage pattern with `Arc<Mutex<AutoScopedParser>>`
      * Custom parser configuration with 2000 template cache and 1-hour TTL
      * **Recommended example for production deployments**
    * `examples/netflow_udp_listener_single_threaded.rs` - Modernized to use `RouterScopedParser`:
      * Replaced manual HashMap management with `RouterScopedParser`
      * Added periodic metrics reporting (every 5 seconds)
      * Displays per-source template cache statistics and hit rates
      * Socket created once for better performance
      * Demonstrates simple single-threaded usage pattern
    * `examples/netflow_udp_listener_multi_threaded.rs` - Modernized to use `RouterScopedParser`:
      * Replaced per-source thread management with shared `Arc<Mutex<RouterScopedParser>>`
      * Added dedicated metrics reporter thread
      * Enhanced metrics showing per-source cache performance
      * Spawns thread per packet to avoid blocking receive loop
      * Demonstrates thread-safe multi-threaded usage pattern

  * **Migration Notes:**
    * **Breaking:** Code matching on `FlowSetBody::NoTemplate` must be updated:
      * Old: `NoTemplate(data)` where `data: Vec<u8>`
      * New: `NoTemplate(info)` where `info: NoTemplateInfo`
      * The raw data is now accessed via `info.raw_data`
      * Additional context available via `info.template_id` and `info.available_templates`
    * Existing code using `v9_cache_stats()` or `ipfix_cache_stats()` will continue to work
    * The `CacheStats` struct now has an additional `metrics` field

# 0.7.4

  * **Fixed critical bug in protocol.rs:**
    * Fixed `impl From<u8> for ProtocolTypes` mapping that was off-by-one
    * Added missing case for `0` → `ProtocolTypes::Hopopt`
    * Fixed case `1` from `Hopopt` to `Icmp` (correct mapping)
    * Fixed case `144` from `Reserved` to `Aggfrag` (correct mapping)
    * Added missing case for `255` → `ProtocolTypes::Reserved`
    * All protocol number conversions now correctly match the enum definition

# 0.7.3

  * **Comprehensive Documentation Improvements for docs.rs:**
      * Modified `ipfix_field_enum!` macro to auto-generate doc comments showing data types
      * Each field variant now displays: "Field ID: <number> | Data Type: <type>"
      * Example: `SourceIpv4address` shows "Field ID: 8 | Data Type: FieldDataType::Ip4Addr"
      * Affects 6 enums with 1,000+ total variants: `IANAIPFixField`, `CiscoIPFixField`, `YafIPFixField`, `VMWareIPFixField`, `NetscalerIPFixField`, `ReverseInformationElement`
      * `IANAIPFixField`: Added comprehensive docs with examples, field categories, and IANA registry link
      * `YafIPFixField`: Documented deep packet inspection categories (DNS, SSL/TLS, HTTP, RTP, MPTCP)
      * `VMWareIPFixField`: Explained NSX virtualization and tenant isolation fields
      * `CiscoIPFixField`: Documented AVC, business metrics, and security monitoring fields
      * `NetscalerIPFixField`: Added ADC metrics, ICA, HTTP, and database monitoring categories
      * `NatIPFixField` & `ReverseInformationElement`: Documented NAT and bidirectional flow fields
      * `ProtocolTypes`: Added comprehensive docs with common protocol table and IANA reference
      * Added extensive `variable_versions` module docs explaining V9 vs IPFIX architecture
      * Documented template caching, enterprise field support, and TTL configuration
      * Added comparison table showing key differences between V9 and IPFIX
      * Included enterprise vendor table with IDs: Cisco (9), NetScaler (5951), YAF (6871), VMware (6876)
      * `FieldDataType`: Categorized all data types (Network, Numeric, Time, Text, Special)
      * Added examples showing type conversions and field data type lookups
      * Documented byte sizes and usage for each data type variant
      * Enhanced module docs with common enterprise number reference table
      * Added complete usage example for custom field registration
      * Documented integration with parser configuration
      * Cross-references use proper rustdoc link syntax

# 0.7.2

  * **Custom Enterprise Fields for IPFIX:**
    * Added runtime registration of custom enterprise-specific IPFIX fields
    * New `EnterpriseFieldRegistry` for managing user-defined enterprise fields
    * New `EnterpriseFieldDef` struct for defining custom fields with enterprise number, field number, name, and data type
    * Builder API methods:
      * `register_enterprise_field()` - Register a single enterprise field
      * `register_enterprise_fields()` - Register multiple enterprise fields at once
    * Custom enterprise fields are automatically parsed according to their registered data type
    * Unregistered enterprise fields continue to parse as raw bytes (backward compatible)
    * Enhanced `IPFixField::Enterprise` variant to store both enterprise number and field number
    * Added `to_field_data_type()` method to `IPFixField` for registry-aware type resolution
  * **New example:** `custom_enterprise_fields.rs` demonstrating enterprise field registration
  * **Documentation updates:**
    * Added comprehensive "Custom Enterprise Fields (IPFIX)" section to README
    * Updated Table of Contents and Included Examples sections
    * Added inline documentation for all new public APIs
  * Re-added examples directory from published crate

# 0.7.1
  * Updates to various dependencies
  * Exclude examples directory from published crate to reduce package size
  * Updated tokio example to display metrics every 5 seconds instead of printing individual packets
  * Tokio example now tracks successful and failed packet counts using atomic counters
  * **Performance optimizations for tokio example:**
    * Changed HashMap key from `String` to `SocketAddr` for faster lookups and reduced allocations
    * Eliminated unnecessary buffer allocations in packet processing
    * Implemented asynchronous packet processing using dedicated tasks per source address
    * Main receive loop no longer blocks on packet parsing, preventing dropped packets under high load
    * Each source address gets its own processing task with bounded channels (capacity: 100) for backpressure

# 0.7.0

**⚠️ BREAKING CHANGES**

This release simplifies the Template TTL API by removing packet-based TTL support. Only time-based TTL is now supported.

  * **Simplified TTL API:**
    * Removed `TtlStrategy` enum entirely
    * Removed packet-based TTL (`TtlConfig::packet_based()`)
    * Removed combined TTL (`TtlConfig::combined()`)
    * Simplified `TtlConfig` to only contain a `Duration` field
    * New API: `TtlConfig::new(duration: Duration)`
    * `TtlConfig::default()` returns 2-hour TTL
  * **Removed packet counting from parsers:**
    * Removed `packet_count` field from `V9Parser` and `IPFixParser`
    * Templates now expire based on wall-clock time only
  * **Updated trait methods:**
    * `ParserConfig::set_ttl_strategy()` renamed to `set_ttl_config()`
    * Now takes `Option<TtlConfig>` instead of `TtlStrategy`
  * **Migration guide:**
    * `TtlConfig::time_based(d)` → `TtlConfig::new(d)`
    * `TtlConfig::packet_based(n)` → Use `TtlConfig::new(Duration::from_secs(...))` with appropriate time duration
    * `TtlConfig::combined(d, n)` → Use `TtlConfig::new(d)` (time component only)
    * `TtlConfig::default_time_based()` → `TtlConfig::default()`
  * **Rationale:** Packet-based TTL using a global packet counter didn't correlate well with template staleness. Time-based TTL better reflects actual template expiration patterns as exporters typically refresh templates on time intervals.

# 0.6.9
  * Added Template Time Based / Packet Based TTL for V9/IPFix.
  * **Added Builder Pattern for NetflowParser:**
    * New `NetflowParser::builder()` method returns `NetflowParserBuilder`
    * Ergonomic configuration with chainable methods:
      * `with_cache_size()` / `with_v9_cache_size()` / `with_ipfix_cache_size()`
      * `with_ttl()` / `with_v9_ttl()` / `with_ipfix_ttl()`
      * `with_allowed_versions()` / `with_max_error_sample_size()`
      * `build()` - Constructs configured parser
  * **Added Template Cache Introspection API:**
    * `v9_cache_stats()` / `ipfix_cache_stats()` - Get cache statistics
    * `v9_template_ids()` / `ipfix_template_ids()` - List all cached template IDs
    * `has_v9_template()` / `has_ipfix_template()` - Check if template exists (non-mutating)
    * `clear_v9_templates()` / `clear_ipfix_templates()` - Clear all templates
  * New `CacheStats` struct for cache statistics
  * Added `Debug` and `Clone` derives to `Config` struct
  * Comprehensive documentation updates with builder pattern examples

# 0.6.8
  * Added LRU-based template caching for V9Parser and IPFixParser to prevent memory exhaustion
  * Default template cache size: 1000 templates per parser (configurable)
  * New `V9Parser::try_new(cache_size)` and `IPFixParser::try_new(cache_size)` constructors for custom cache sizes
  * Added `V9ParserError` and `IPFixParserError` error types for proper error handling
  * Template cache is automatically evicted using LRU policy when limit is reached
  * Provides protection against DoS attacks via template flooding
  * Removed `PartialEq`, `Clone`, and `Serialize` derives from parser structs (due to LruCache)

# 0.6.7
* Optimized NetflowCommon conversion with single-pass field lookups (reduced O(n*m) to O(n))
* Added V5/V7/DataNumber capacity pre-allocation
* Faster string processing in hot paths
* Fixed integer overflow in V9 options template field counting
* Fixed unbounded buffer reads in IPFIX variable-length fields
* Fixed memory exhaustion vulnerability in error handling
* Enhanced validation for malformed packets
* Improved IPFIX error handling - parse errors now properly propagate
* Added thread safety documentation and performance tuning guide
* **Fixed V9/IPFIX padding handling:**
  * Fixed missing padding export for V9 Data FlowSets
  * Added padding fields to IPFIX Data and OptionsData structures
  * Auto-calculate padding for manually created packets (when padding field is empty)
  * Preserve original padding for parsed packets (byte-perfect round-trips)
  * Added `examples/manual_ipfix_creation.rs` demonstrating manual packet creation

# 0.6.6
* Added configurable field mappings for V9 and IPFIX in NetflowCommon.
* New `V9FieldMappingConfig` and `IPFixFieldMappingConfig` structs allow customizing which fields map to `NetflowCommonFlowSet`.
* New methods `NetflowCommon::from_v9_with_config()` and `NetflowCommon::from_ipfix_with_config()` for custom field extraction.
* Each field mapping supports a primary field and an optional fallback (e.g., prefer IPv6, fall back to IPv4).
* Default configurations maintain backward compatibility with existing behavior.
* Netflow Common is now a feature.

# 0.6.5
* Several memory and performance optimizations.

# 0.6.4
* Removed uneeded DataNumber Parsing for Durations.
* Renamed methods DurationMicros and DurationNanos into DurationMicrosNTP and DurationNanosNTP.
* Minor Performance optimizations

# 0.6.3
* Ipfix dateTimeNanoseconds and dateTimeMicroseconds use the NTP 64 bit time format #15
* Added NetEvent and ObservationTimeMilliseconds for V9.

# 0.6.2
* IPFix supports multiple V9 Options templates.
* Found casting issues that could result in dataloss in the DataNumbers module.
* Fixed incorrect datatypes for DataNumbers.
* Added Reverse Information Element PEN fields.

# 0.6.1
* V9 Fields also now a Vec instead of BTreeMap.
* IPFix Templates are now HashMap instead of BTreeMap.
* Faster Data Parsing for V9/IPFix by removing inefficient contains_key lookup.
* Fixed issue with certain ipfix lookup fields.

# 0.6.0
* Remove Control Characters and P4 starting chars from FieldDataType unicode strings.
* Added PCAP example and how to cache IPFix flows without a packet for later parsing.

# 0.5.9
* IPFIX now supports multiple Templates in a flow
* Fixed bug with parsing IPFix fields that would omit some data.
* New IPFix FlowSetBody type added called NoTemplate and Empty.
* NoTemplate returns data that allows you to cache flows that do not have a template for later parsing.
* Correctly handling different Enterprise Field Types.
* Added Netscaler PEN Types.
* Added NAT PEN Types.
* Added YAF PEN Types.
* Added VMWARE PEN Types.
* Re-added Enterprise Field Type for Unknown Enterprise Types.

# 0.5.8
* V9 Found and fixed divide by 0 issue.
* IPFix Protocol Identifier now parsers as ProtocolIdentifier Field Type and not UnsignedDataNumber.
* IPFix added Application ID Data Type.
* Enterprise Fields are no longer classified as an "enterprise" field type.
* IPFix now supports some Cisco PEN fields listed below:
```
    CiscoServerBytesNetwork = 8337,
    CiscoClientBytesNetwork = 8338,
    CiscoServicesWaasSegment = 9252,
    CiscoServicesWaasPassthroughReason = 9253,
    CiscoAppHttpUriStatistics = 9357,
    CiscoAppCategoryName = 12232,
    CiscoAppGroupName = 12234,
    CiscoAppHttpHost = 12235,
    CiscoClientIpv4Address = 12236,
    CiscoServerIpv4Address = 12237,
    CiscoClientL4Port = 12240,
    CiscoServerL4Port = 12241,
    CiscoConnectionId = 12242,
    CiscoAppBusiness = 12244,
```

# 0.5.7
* Fix Scope Data Parsing.

# 0.5.6
* Simplify V9/IPFix Parse function.
* Added more cases for DataNumber Parsing.
* IPFix now supports V9 Templates/Options Templates.

# 0.5.5
* More IPFIx/V9 Cleanup.
* Reworked FlowSetBody for V9/IPFIX into an enum since a flowset can only contain a single type.
* Fixed potential V9 parsing bug with a potential divide by 0.
* DataNumber to_be_bytes to now a Result type return to handle failed u24 conversions.
* FieldValue to_be_bytes now supports all data types.

# 0.5.4
* Reworked how padding is calculated for IPFIx.
* Fixed Vecs not being exported for DataNumber.

# 0.5.3
* Fixed bug when calcualting the enteperise field.
* Now properly parses variable length fields.
* Cleanup ipfix code.
* Rust 2024 Edition.

# 0.5.2
* Can now parse enterprise fields in non options templates for IPFIX.

# 0.5.1
* Reworked NetflowParseError.  Added a Partial Type.
* Added ability to parse only `allowed_versions`.
* V9, IPFix, Datanumber Code cleanup.
* Added benchmarking

# 0.5.0
* Typos in documentation fixed.
* Added cargo-fuzz for fuzzing.
  * Uncovered area in V9 that could cause panic.

# 0.4.9
* Added FlowStartMilliseconds, FlowEndMilliseconds 

# 0.4.8
* Now Parsing IPFix Mac Addresses correctly.

# 0.4.7
* Added `src_mac` and `dst_mac` to NetflowCommonFlowSet to help identify devices on V9, IPFix.

# 0.4.6
* Added `NetflowParser` function `parse_bytes_as_netflow_common_flowsets`.  Will allow the caller
  to gather all flowsets from all `NetflowPacket` into a single `Vec` of `NetflowCommonFlowSet`.

# 0.4.5
 * Fixed bug with NetflowCommon V9 where Src and Dst IP where Ipv6 wasn't being checked.

# 0.4.4
* Fix Readme example packets.
* Optimized IPFix, V9 NetflowCommon lookup.
* DataNumbers can now be downcast into actual data types: (u8, u16, i32, u32, u64, u128).

# 0.4.3
 * Fixed bug in NetflowCommon where ProtocolType was never set.
 * Minor Readme Changes.

# 0.4.2
 * Increased coverage.
 * Reworked Readme.

# 0.4.1
 * Added NetflowCommon structure.  This acts as a helper for common Netflow Fields (like src_ip, src_port, etc).
 * V5, V7 SysUpTime, First, Last times now u32 from Duration.
 * IPFix export time u32 from Duration.

# 0.4.0
 * NetflowPacketResult now simply NetflowPacket.
 * General parser cleanup and removal of unneeded code.
 * Small performance optimization in lib parse_bytes.

# 0.3.6
 * Added V9 Post NAT fields 225-228.
 * Added Tokio Async Example

# 0.3.5
 * 3 Byte Data Numbers now correctly converts back to be_bytes.

# 0.3.4
 * Added 3 byte DataNumber support.

# 0.3.3
 * Renamed Sets to FlowSets for IPFIX for consistency.
 * Concrete error type for parsing
 * V5, V7, V9, IPFix now supports exporting back into bytes with `to_be_bytes`.
 * V9,IPFix field maps are now keyed by order.
 * Removed unix timestamp feature.  May re-implement in the future.

# 0.3.2
 * Readme changes

# 0.3.1
  * Added 0 length check when parsing template lengths.

# 0.3.0
  * Reworked IPFIX + V9 Parsing.  Flowset length is now used.
  * Flow data field Counts are now correctly calculated.
  * Added `parse_unknown_fields` feature flag to attempt to parse unknown fields not supported by the library.
  * `parse_unknown_fields` is enabled by default.

# 0.2.9
  * Fixed parsing issue with V9 flow and padding.

# 0.2.8
  * Removed body for V5, V7.  Only has Sets now.

# 0.2.7
  * Added support for multiple flowsets for V5, V7.

# 0.2.6
  * Re-added static and variable versions as public.

# 0.2.5
  * Now Parsing V9 Mac Addresses correctly.
  * More code reorganization. (Moved tests to tests.rs and added parsing.rs for majority of parsing).
  * Removed unneeded IPFIX Option Template Code.

# 0.2.4
  * Fixes for V9 parsing.  Now supports processing multiple templates.
  * General code cleanup/Removal of unneeded code.

# 0.2.3
  * Small performance improvement by not parsing netflow version twice each packet.
  * General Code cleanup for field_types and DataNumbers.

# 0.2.2
  * Optimizations in V9/IPFIX, removed some clone/cloned.
  * Reworked Template Fields/Option Template Fields into single struct.
    This avoids having to make an additional clone for each parse.

# 0.2.1
  * Fixed issue where v9/ipfix template fields can infinite loop.

# 0.2.0
  * Clippy updates for 1.76
  * Removed dbg! macros for now for performance reason until we have a better solution.
  * Fixed issue where bad IPFIX options template causes panic.

# 0.1.9
  * Fixed bug with flow counts in V9.

# 0.1.8
  * Introduced parse unix_timestamp feature. 

# 0.1.7
  * Renamed NetflowPacket to NetflowPacketResult.
  * Created an Error Type on NetflowPacketResult.  Contains the error message and bytes that was trying to be parsed.

# 0.1.6
  * Fixed bug when parsing empty byte arrays or empty remaining slices.

# 0.1.5
  * Removed logging crate dependency 

# 0.1.4
  * Removed insta for non dev-dependency.

# 0.1.3
  * unix_secs and unix_nsecs for V5 are now pub.

# 0.1.2
  * Added Cisco to README.md
  * Fixed some IPFIX Fields not being correctly mapped.
  * Safer addition and subtraction in V9/IPFix

# 0.1.1
  * Removed serde import from filter example.
  * Removed link to ipfix in V9 doc string.
  * Added RELEASES.md

