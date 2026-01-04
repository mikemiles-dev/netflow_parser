# 0.8.0

  * **Testing Improvements:**
    * Added comprehensive DoS and edge case test suite (`tests/dos_edge_cases.rs`)
      * V9/IPFIX max field count validation tests
      * Template cache eviction scenarios
      * Error buffer size configuration tests
      * Rapid template collision handling
      * Cache metrics accuracy verification
      * Template TTL expiration tests
      * Zero-size cache rejection tests
      * Malformed flowset length handling
    * 9 new security-focused integration tests

  * **Performance Optimizations:**
    * Optimized clone usage in enterprise field registration
    * Reduced unnecessary allocations when registering multiple enterprise fields
    * Now collects iterator once and moves originals to second registry

  * **ParseResult - Partial Success Handling (BREAKING CHANGE):**
    * **BREAKING CHANGE:** `parse_bytes()` now returns `ParseResult` instead of `Result<Vec<NetflowPacket>, NetflowError>`
    * New `ParseResult` struct preserves successfully parsed packets even when errors occur mid-stream
    * Prevents data loss when parsing multiple packets in a buffer (error in packet 5 doesn't lose packets 1-4)
    * `ParseResult` fields:
      * `packets: Vec<NetflowPacket>` - All successfully parsed packets
      * `error: Option<NetflowError>` - Error if parsing stopped early
    * Helper methods:
      * `is_ok()` - Check if parsing completed without errors
      * `is_err()` - Check if an error occurred
      * `into_result()` - Convert to `Result` for backward compatibility (loses partial packets on error)
    * `iter_packets()` unchanged - still yields `Result<NetflowPacket, NetflowError>`
    * **Migration from 0.7.x:**
      ```rust
      // Old (0.7.x):
      let packets = parser.parse_bytes(&data)?;

      // New (0.8.0) - Handle partial results:
      let result = parser.parse_bytes(&data);
      for packet in result.packets { /* process */ }
      if let Some(e) = result.error { /* handle */ }

      // New (0.8.0) - Fail-fast (same as old):
      let packets = parser.parse_bytes(&data).into_result()?;
      ```

  * **Security Improvements:**
    * **DoS Protection - Configurable Maximum Field Count Validation:**
      * Added configurable `max_field_count` limit to prevent memory exhaustion attacks
      * Default limit: 10,000 fields per template (configurable via builder)
      * IPFIX Template validates `field_count <= max_field_count` before parsing
      * V9 Template validates `field_count <= max_field_count` before parsing
      * V9 OptionsTemplate validates calculated field counts against `max_field_count`
      * Malicious packets with excessive field counts (e.g., 65,535 fields) are now rejected
      * Returns `nom::error::ErrorKind::Verify` on validation failure
      * New builder methods:
        * `.with_max_field_count(count)` - Sets limit for both V9 and IPFIX
        * `.with_v9_max_field_count(count)` - Sets V9-specific limit
        * `.with_ipfix_max_field_count(count)` - Sets IPFIX-specific limit
    * **Scope Field Validation in IPFIX Options Templates:**
      * Added validation that `scope_field_count <= field_count` in IPFIX OptionsTemplate
      * Prevents logic errors when scope field count exceeds total field count
      * Simplified field counting logic to use total `field_count` directly
    * **Variable-Length Field Size Limits:**
      * Variable-length fields in IPFIX are naturally bounded by u16 (max 65,535 bytes)
      * Enhanced `parse_field_length()` with improved buffer boundary validation
      * Removed redundant `MAX_VARIABLE_FIELD_LENGTH` constant (replaced with u16::MAX)
      * Prevents unbounded reads beyond available buffer data
    * **Removed Unsafe Unwrap Operations:**
      * Replaced `unwrap()` calls in IPFIX field parsing with safe pattern matching
      * Changed `FieldParser::parse()` to use `match` instead of `is_err()` + `unwrap()` pattern
      * Changed `FieldParser::parse_with_registry()` to use `match` for error handling
      * Eliminates potential panic points that could cause DoS via malformed input
      * Gracefully returns partial results when field parsing fails
  * **Security Impact:**
    * Prevents resource exhaustion DoS attacks via malicious template definitions
    * Eliminates panic-based DoS attack vectors in field parsing
    * Adds multiple layers of validation for untrusted network input
    * No breaking API changes - all fixes are internal validation improvements


  * **Template Cache Metrics and Collision Detection:**
    * Added comprehensive performance metrics tracking for V9 and IPFIX template caches
    * New `CacheMetrics` struct with atomic counters: hits, misses, evictions, collisions, expired, insertions
    * Automatic tracking when template IDs are reused (critical for multi-source deployments)
    * `CacheMetricsSnapshot` provides point-in-time view with `hit_rate()`, `miss_rate()`, `total_lookups()` helpers
    * Metrics accessible via `NetflowParser::v9_cache_stats()` and `NetflowParser::ipfix_cache_stats()`
    * All metrics use atomic operations for thread-safe reads
    * New module: `src/variable_versions/metrics.rs`

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

  * **Documentation and Examples:**
    * New "Template Management Guide" section in README with detailed coverage of cache metrics, multi-source deployments, collision detection, missing templates, and best practices
    * RFC compliance documentation for NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) scoping requirements
    * New examples:
      * `examples/template_management_demo.rs` - Comprehensive demo of cache metrics, multi-source parsing, collision detection, and template lifecycle
      * `examples/multi_source_comparison.rs` - Visual comparison showing why `AutoScopedParser` is needed for multi-router deployments
    * Updated examples to use `AutoScopedParser` and `RouterScopedParser`:
      * `netflow_udp_listener_tokio.rs` - Updated to `AutoScopedParser` (recommended for production)
      * `netflow_udp_listener_single_threaded.rs` - Modernized with `RouterScopedParser` and metrics
      * `netflow_udp_listener_multi_threaded.rs` - Modernized with `RouterScopedParser` and dedicated metrics thread

  * **Template Event Hooks:**
    * **NEW:** Callback system for monitoring template lifecycle events in real-time
    * Register hooks via `.on_template_event()` builder method to receive notifications for:
      * `TemplateEvent::Learned` - New template added to cache
      * `TemplateEvent::Collision` - Template ID reused (indicates multi-source issues)
      * `TemplateEvent::Evicted` - Template removed due to LRU policy
      * `TemplateEvent::Expired` - Template removed due to TTL timeout
      * `TemplateEvent::MissingTemplate` - Data packet for unknown template
    * Use cases: Real-time monitoring, custom metrics collection, observability integration, alerting
    * Hooks are `Send + Sync` for thread safety
    * New types: `TemplateEvent`, `TemplateProtocol`, `TemplateHook`, `TemplateHooks`
    * New module: `src/template_events.rs`
    * New example: `examples/template_hooks.rs` - Comprehensive demonstration of hook system
    * Integration tests: 7 new tests in `tests/template_hooks.rs`

  * **Enhanced Error Handling (BREAKING CHANGES):**
    * **BREAKING CHANGE:** `NetflowPacket::Error` variant removed - errors now returned via Result
    * **BREAKING CHANGE:** `parse_bytes()` now returns `Result<Vec<NetflowPacket>, NetflowError>`
    * **BREAKING CHANGE:** `iter_packets()` now yields `Result<NetflowPacket, NetflowError>`
    * **BREAKING CHANGE:** `AutoScopedParser::parse_from_source()` returns `Result<Vec<NetflowPacket>, NetflowError>`
    * **BREAKING CHANGE:** `RouterScopedParser::parse_from_source()` returns `Result<Vec<NetflowPacket>, NetflowError>`
    * **BREAKING CHANGE:** Iterator methods yield `Result<NetflowPacket, NetflowError>`
    * **BREAKING CHANGE:** Replaced parsing library errors with custom `NetflowError` type
    * New `NetflowError` enum provides rich error context with these variants:
      * `Incomplete { available, context }` - Not enough data to parse packet
      * `UnsupportedVersion { version, offset, sample }` - Unknown NetFlow version with sample data
      * `FilteredVersion { version }` - Version filtered by allowed_versions config (internal use)
      * `MissingTemplate { template_id, protocol, available_templates, raw_data }` - Template not in cache
      * `ParseError { offset, context, kind, remaining }` - Generic parsing error with details
      * `Partial { message }` - Partial parse result from nom parser
    * All errors implement `Display` and `std::error::Error` traits for better debugging
    * `NetflowError` is serializable via serde for logging and storage
    * More idiomatic Rust API separating success and error paths
    * Enables use of `?` operator for error propagation
    * Deprecated type aliases for backward compatibility:
      * `NetflowPacketError` → `NetflowError` (deprecated)
      * `NetflowParseError` → `NetflowError` (deprecated)
    * Error messages now include:
      * Specific context about what was being parsed
      * Offset information where applicable (UnsupportedVersion, ParseError)
      * Sample of problematic data for debugging
      * Available templates when template is missing

  * **API and Developer Experience Improvements:**
    * Builder API: Added `.single_source()` and `.multi_source()` methods for clearer API discoverability
    * Integration tests: Added 48 tests (total) across 7 files covering parser configuration, multi-version parsing, template cache, scoped parsing, serialization, PCAP integration, and template hooks
    * Crate discoverability: Added keywords `["netflow", "ipfix", "parser", "network", "cisco"]` to Cargo.toml
    * README badges: Added CI status, crates.io version, and docs.rs documentation badges
    * Fuzzing: Configured to run 5 minutes on main branch, 60 seconds on other branches

  * **Migration Notes:**
    * **Breaking:** Code matching on `FlowSetBody::NoTemplate` must be updated:
      * Old: `NoTemplate(data)` where `data: Vec<u8>`
      * New: `NoTemplate(info)` where `info: NoTemplateInfo`
      * The raw data is now accessed via `info.raw_data`
      * Additional context available via `info.template_id` and `info.available_templates`
    * **Breaking:** Error handling has changed completely:
      * `NetflowPacket::Error` variant has been **removed**
      * `parse_bytes()` now returns `Result<Vec<NetflowPacket>, NetflowError>` instead of `Vec<NetflowPacket>`
      * `iter_packets()` now yields `Result<NetflowPacket, NetflowError>` instead of `NetflowPacket`
      * All scoped parser methods also return `Result`
      * Example migration for `parse_bytes`:
        ```rust
        // Old code (0.7.x)
        let packets = parser.parse_bytes(&data);
        for packet in packets {
            match packet {
                NetflowPacket::V5(v5) => { /* process */ }
                NetflowPacket::Error(e) => { /* handle error */ }
                _ => {}
            }
        }

        // New code (0.8.0)
        match parser.parse_bytes(&data) {
            Ok(packets) => {
                for packet in packets {
                    match packet {
                        NetflowPacket::V5(v5) => { /* process */ }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("Parse error: {}", e);
            }
        }

        // Or use ? operator
        let packets = parser.parse_bytes(&data)?;
        ```
      * Example migration for `iter_packets`:
        ```rust
        // Old code (0.7.x)
        for packet in parser.iter_packets(&data) {
            match packet {
                NetflowPacket::V5(v5) => { /* process */ }
                NetflowPacket::Error(e) => { /* handle error */ }
                _ => {}
            }
        }

        // New code (0.8.0)
        for packet in parser.iter_packets(&data) {
            match packet {
                Ok(NetflowPacket::V5(v5)) => { /* process */ }
                Ok(_) => { /* other versions */ }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    break; // or continue
                }
            }
        }

        // Or collect with error handling
        let packets: Result<Vec<_>, _> = parser.iter_packets(&data).collect();
        ```
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

# 0.6.x Series - Builder Pattern, LRU Caching, Performance
  * **0.6.9**: Builder pattern, template cache introspection API, TTL support
  * **0.6.8**: LRU-based template caching (default 1000 templates), DoS protection
  * **0.6.7**: Performance optimizations, padding handling fixes, security fixes
  * **0.6.6**: Configurable field mappings for NetflowCommon
  * **0.6.5-0.6.0**: Performance optimizations, PCAP examples, string handling improvements

# 0.5.x Series - IPFIX Enhancements, Enterprise Fields
  * **0.5.9**: Multiple templates per flow, enterprise field types (Netscaler, NAT, YAF, VMware)
  * **0.5.8**: Cisco PEN fields, Application ID data type, protocol identifier fixes
  * **0.5.7-0.5.0**: Parsing improvements, fuzzing support, benchmarking, code cleanup

# 0.4.x Series - NetflowCommon, Type Improvements
  * **0.4.1**: NetflowCommon structure for cross-version field access
  * **0.4.4**: DataNumber downcasting to native types
  * **0.4.0-0.4.9**: Various bug fixes and optimizations

# 0.3.x and Earlier - Foundation
  * **0.3.3**: Re-export support (`to_be_bytes`), concrete error types
  * **0.3.0**: Reworked IPFIX/V9 parsing, `parse_unknown_fields` feature
  * **0.2.x**: Multi-flowset support, template processing improvements
  * **0.1.x**: Initial releases, basic V5/V7/V9/IPFIX support

