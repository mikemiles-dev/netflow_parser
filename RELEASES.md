# 1.0.0

 * **Breaking: `FieldValue::Duration` now wraps `DurationValue` instead of `std::time::Duration`**
   - New `DurationValue` enum preserves the original time unit (`Seconds`, `Millis`, `MicrosNtp`, `NanosNtp`), field width (4 or 8 bytes), and raw NTP fractional seconds
   - Enables lossless round-trip serialization — previously, unit and width information was lost during parsing
   - Use `DurationValue::as_duration()` to get a `std::time::Duration` for ergonomic access
   - JSON serialization output is unchanged (delegates to `Duration`)

 * **Breaking: `FieldValue::String` now wraps `StringValue` instead of `String`**
   - New `StringValue` struct contains `value: String` (cleaned display string) and `raw: Vec<u8>` (original wire bytes)
   - Enables lossless round-trip serialization — previously, lossy UTF-8 conversion, control character filtering, and P4 prefix stripping made the string non-invertible
   - `TryFrom<&FieldValue> for String` still returns the cleaned `value`
   - JSON serialization output is unchanged (serializes only the `value` field)

 * **New IPFIX field types for flags, bitmasks, and enumerations**
   - Added 12 new dedicated field types in `field_types` module, following the `ForwardingStatus` pattern:
     - **Bitmask/flag types:** `FragmentFlags` (field 197), `TcpControlBits` (field 6), `Ipv6ExtensionHeaders` (field 64), `Ipv4Options` (field 208), `TcpOptions` (field 209), `IsMulticast` (field 206), `MplsLabelExp` (fields 203, 237)
     - **Enumeration types:** `FlowEndReason` (field 136), `NatEvent` (field 230), `FirewallEvent` (field 233), `MplsTopLabelType` (field 46), `NatOriginatingAddressRealm` (field 229)
   - These fields were previously decoded as `UnsignedDataNumber` and now produce structured, self-describing values
   - All types support round-trip conversion (parse → typed value → raw bytes)
   - Each type has corresponding `FieldDataType` and `FieldValue` variants

 * **Bug fix: Corrected V9 field data type mappings**
   - `IfName` (82), `IfDesc` (83), `SamplerName` (84) now correctly map to `FieldDataType::String` instead of `UnsignedDataNumber`
   - `Layer2packetSectionData` (104) now correctly maps to `FieldDataType::Vec` instead of `UnsignedDataNumber`

 * **Bug fix: Typo in V9Field variant name**
   - Renamed `V9Field::ImpIpv6CodeValue` to `V9Field::IcmpIpv6CodeValue` (field ID 179)

 * **New V9 field types (IDs 128-175)**
   - Added 46 new `V9Field` variants from the IANA IPFIX Information Elements registry
   - Includes: `BgpNextAdjacentAsNumber`, `ExporterIpv4Address`, `ExporterIpv6Address`, `DroppedOctetDeltaCount`, `FlowEndReason`, `WlanSsid`, `FlowStartSeconds`, `FlowEndSeconds`, `FlowStartMicroseconds`, `FlowEndMicroseconds`, `FlowStartNanoseconds`, `FlowEndNanoseconds`, `DestinationIpv6Prefix`, `SourceIpv6Prefix`, and more
   - Each field has the correct `FieldDataType` mapping per the IANA registry

 * **New `field_types` module with `ForwardingStatus` enum**
   - Added `field_types::ForwardingStatus` — decodes field ID 89 (RFC 7270) into status category and reason code variants
   - Status categories: Unknown, Forwarded, Dropped, Consumed — with specific reason codes (e.g., `DroppedAclDeny`, `ForwardedFragmented`, `ConsumedTerminatedForUs`)
   - Added `FieldDataType::ForwardingStatus` and `FieldValue::ForwardingStatus` for automatic decoding in both V9 and IPFIX
   - `field_types` module is designed for future custom field type additions

 * **Safety and correctness fixes**
   - `UnallowedVersion` now carries the version number; `parse_bytes()` reports a `FilteredVersion` error instead of silently stopping
   - Versions >= 11 now correctly return `UnsupportedVersion` instead of being misclassified as `FilteredVersion`
   - `with_allowed_versions()` now rejects out-of-range version numbers via `ConfigError::InvalidAllowedVersion`
   - `ApplicationId` field parsing uses `checked_sub` instead of `saturating_sub` to properly error on zero-length fields
   - `Vec::with_capacity` for parsed records is capped at 1024 in V9 and IPFIX to prevent untrusted input from causing large allocations
   - V9 `Template::is_valid()` now rejects templates with empty fields or all-zero-length fields
   - V9 and IPFIX `OptionsTemplate` validation now rejects templates with zero scope fields (RFC 3954/7011 require at least one)
   - V9 `OptionsTemplate::is_valid()` now rejects `options_scope_length` and `options_length` that aren't multiples of 4
   - V9 templates embedded in IPFIX packets are now validated against parser limits (field count, total size, zero-length fields)
   - `NoTemplateInfo.truncated` field now correctly set to `true` when raw data is truncated to `max_error_sample_size`
   - Fixed `DurationNanosNTP` unit conversion bug — fractional NTP seconds were passed to `Duration::from_micros()` instead of `Duration::from_nanos()`, producing durations 1000x too large
   - Fixed IPFIX template serialization losing the enterprise bit — round-trip (parse → serialize) now correctly restores bit 15 of `field_type_number` for enterprise fields
   - Fixed `ScopeDataField` silently truncating scope field values to 4 bytes regardless of the template-declared `field_length`

 * **Performance: V5/V7 direct byte parsing**
   - Replaced nom-derive generated parsers with hand-written direct byte reads for V5 and V7
   - Fixed-layout protocols now use a single bounds check instead of per-field nom combinator calls
   - V5 parsing is ~2x faster at scale (e.g., 100 flows: 1,147ns → 626ns, -44%)
   - V7 parsing receives the same treatment (52-byte fixed flow records)
   - `Ipv4Addr` fields constructed directly from bytes instead of `be_u32` → `Ipv4Addr::from()`
   - `to_be_bytes()` now pre-allocates with `Vec::with_capacity()` based on known sizes
   - nom-derive `#[derive(Nom)]` removed from V5/V7 structs; `V5Parser::parse()` and `V7Parser::parse()` entry points unchanged

 * **Performance: Hot-path allocation reduction**
   - `FieldValue::MacAddr` now stores `[u8; 6]` instead of `String`, eliminating a heap allocation per MAC address field
   - Added `DataNumber::write_be_bytes()` and `FieldValue::write_be_bytes()` methods that write directly into a caller-provided buffer, avoiding per-field `Vec<u8>` allocations
   - Removed deprecated `to_be_bytes()` methods on `DataNumber` and `FieldValue` in favor of `write_be_bytes()`
   - `CacheMetrics` uses plain `u64` counters instead of `AtomicU64`, removing atomic overhead in the single-threaded parser
   - `TemplateMetadata::inserted_at` is now `Option<Instant>`, skipping `Instant::now()` when TTL is disabled
   - `allowed_versions` uses a `[bool; 11]` array lookup instead of `HashSet<u16>`, replacing hashing with a bounds-checked index
   - `calculate_padding()` returns `&'static [u8]` instead of allocating a `Vec<u8>`
   - `OptionsFieldParser` returns a flat `Vec<V9FieldPair>` instead of `Vec<Vec<V9FieldPair>>`
   - String parsing avoids a double allocation when stripping the `"P4"` prefix

 * **Dependency removal**
   - Removed `byteorder` crate — manual 3-byte big-endian serialization for u24/i24 types
   - Removed `mac_address` crate — MAC addresses parsed directly from raw bytes

 * **NoTemplateInfo hot-path optimization**
   - Removed `available_templates` field from `NoTemplateInfo` to avoid collecting template IDs on every cache miss
   - Added `V9Parser::available_template_ids()` and `IPFixParser::available_template_ids()` for on-demand querying

 * **Scoped parser optimization**
   - `AutoScopedParser::parse_from_source` and `iter_packets_from_source` no longer clone the parser builder on every call; builder is only cloned on cache miss

 * **Benchmarks**
   - Added `steady_state_bench` — V9 and IPFIX benchmarks with pre-warmed template cache (5, 10, 30, 100 flows)

 * **Refactor: Reduced code duplication between V9 and IPFIX parsers**
   - Extracted shared `calculate_padding()`, `NoTemplateInfo`, `get_valid_template()`, constants (`DEFAULT_MAX_TEMPLATE_CACHE_SIZE`, `MAX_FIELD_COUNT`, `TemplateId`) into `variable_versions` module
   - Consolidated `ParserConfig` trait with default method implementations for `add_config`, `set_max_template_cache_size`, `set_ttl_config`, `pending_flows_enabled`, `pending_flow_count`, and `clear_pending_flows`
   - Introduced `ParserFields` accessor trait to enable shared default implementations

 * **API hygiene**
   - `NetflowParser` fields (`v9_parser`, `ipfix_parser`, `allowed_versions`, `max_error_sample_size`) are now `pub(crate)` instead of `pub`. Use accessor methods: `v9_parser()`, `v9_parser_mut()`, `ipfix_parser()`, `ipfix_parser_mut()`, `allowed_versions()`, `is_version_allowed()`, `max_error_sample_size()`
   - `NetflowParserBuilder::build()` now returns `Result<NetflowParser, ConfigError>` instead of `Result<NetflowParser, String>`
   - Added `NetflowParserBuilder::validate()` for lightweight config validation without allocating parser internals
   - `ConfigError` now implements `std::error::Error`
   - `DataNumberError`, `FieldValueError`, and `NetflowCommonError` now implement `Display` and `std::error::Error`
   - `ProtocolTypes::Unknown` is now `Unknown(u8)`, carrying the original protocol number. `#[repr(u8)]` removed from `ProtocolTypes`. `PartialOrd`/`Ord` are now implemented manually based on protocol number (not enum declaration order)
   - Added `try_with_builder()` on `RouterScopedParser` and `AutoScopedParser` (returns `Result<Self, ConfigError>`). Deprecated `with_builder()` — calls `try_with_builder().expect(...)`
   - Added `try_multi_source()` on builder (returns `Result<AutoScopedParser, ConfigError>`). Deprecated `multi_source()` — calls `try_multi_source().expect(...)`

 * **Naming aliases**
   - Added Rust-idiomatic type aliases: `Ipfix`, `IpfixParser`, `IpfixField`, `IpfixFieldPair`, `IpfixFlowRecord`
   - Re-exported from crate root for convenience

 * **Documentation**
   - Added module-level `//!` docs to `v9/mod.rs`, `ipfix/mod.rs`, `ttl.rs`, and all integration test files
   - Added `///` docstrings to all undocumented public structs, enums, traits, and methods (`Config`, `V9`, `V9Parser`, `IPFix`, `IPFixParser`, `FlowSetBody`, `Header`, `FlowSet`, `Template`, `OptionsTemplate`, `TemplateField`, `CommonTemplate`, etc.)
   - Added `//` comments to all unit and integration test functions describing what they verify
   - Fixed malformed doc block where `build()` and `on_template_event()` docs were merged in `NetflowParserBuilder`
   - Fixed unclosed code fence in `ScopeDataField::parse` doc comment
   - Fixed doc link warning for `EnterpriseFieldRegistry` in `variable_versions` module docs

 * **Code cleanup**
   - Renamed `BpgIpv6NextHop` → `BgpIpv6NextHop` in the `V9Field` enum (typo fix)
   - Removed deprecated `NetflowPacketError` and `NetflowParseError` type aliases — use `NetflowError` directly
   - Split `v9.rs` into `v9/{mod.rs, parser.rs, serializer.rs}`
   - Split `ipfix.rs` into `ipfix/{mod.rs, parser.rs, serializer.rs}`
   - Renamed `data_number.rs` → `field_value.rs` (deprecated re-export module preserves backward compatibility)
   - Renamed `IpFixFlowRecord` → `IPFixFlowRecord` for consistent casing with `IPFixFieldPair`, `IPFix`, etc. (deprecated alias preserves backward compatibility)
   - Removed unused `enterprise_registry` field from `V9Parser` (was `#[allow(dead_code)]`)
   - Replaced `contains_key` + `unwrap` pattern in `AutoScopedParser` with `entry()` API
   - Added compile-time assertion for `DEFAULT_MAX_TEMPLATE_CACHE_SIZE > 0`
   - Deleted orphaned snapshot file

 * **Testing**
   - Added concurrent parsing tests (`Arc<Mutex<RouterScopedParser>>` shared across threads, independent parsers per thread)
   - Added memory bounds tests (cache stats within configured limits, error sample size bounded)

 * **BREAKING CHANGES:**
   - `FieldValue::MacAddr` now wraps `[u8; 6]` instead of `String`. Serialization output is unchanged (`"aa:bb:cc:dd:ee:ff"` format).
   - `NoTemplateInfo` no longer has an `available_templates` field. Use `parser.v9_available_template_ids()` or `parser.ipfix_available_template_ids()` instead.
   - `CacheMetrics` methods (`record_hit`, `record_miss`, etc.) now require `&mut self` instead of `&self`.
   - `with_allowed_versions()` now takes `&[u16]` instead of `HashSet<u16>`. The `allowed_versions` field is now `pub(crate) [bool; 11]`; use `allowed_versions()` or `is_version_allowed()` accessors.
   - `NetflowParser` fields `v9_parser`, `ipfix_parser`, `allowed_versions`, `max_error_sample_size` are now `pub(crate)`. Use the corresponding accessor methods instead.
   - `NetflowParserBuilder::build()` returns `ConfigError` instead of `String` on failure.
   - `ProtocolTypes::Unknown` is now `Unknown(u8)` instead of a unit variant. Pattern matching on `Unknown` must use `Unknown(_)` or `Unknown(v)`. `#[repr(u8)]` removed; use `u8::from(protocol)` instead of `protocol as u8`. `PartialOrd`/`Ord` now compare by protocol number value, not enum declaration order.
   - `with_builder()` on `RouterScopedParser` and `AutoScopedParser` is deprecated. Use `try_with_builder()`.
   - `multi_source()` on `NetflowParserBuilder` is deprecated. Use `try_multi_source()`.
   - `DataNumber::to_be_bytes()` and `FieldValue::to_be_bytes()` removed; use `write_be_bytes()` instead.
   - V5 and V7 structs (`V5`, `Header`, `FlowSet`) no longer derive `Nom`. Code calling `V5::parse()` or `V7::parse()` via the nom-derive `Parse` trait must use `V5::parse_direct()` / `V7::parse_direct()` instead. The `V5Parser::parse()` and `V7Parser::parse()` entry points are unchanged.
   - `V9Field::BpgIpv6NextHop` renamed to `V9Field::BgpIpv6NextHop`. Code matching on this variant must update the name.
   - `NetflowPacketError` and `NetflowParseError` type aliases removed. Use `NetflowError` directly.
   - V9 `OptionsDataFields.options_fields` changed from `Vec<Vec<V9FieldPair>>` to `Vec<V9FieldPair>`. Code that iterates nested Vecs must flatten.
   - Module `variable_versions::data_number` renamed to `variable_versions::field_value`. A deprecated re-export module preserves backward compatibility but will be removed in a future release.
   - `IpFixFlowRecord` renamed to `IPFixFlowRecord` for consistent casing. A deprecated alias preserves backward compatibility.
   - `V9Field::ImpIpv6CodeValue` renamed to `V9Field::IcmpIpv6CodeValue` (field ID 179). Code matching on this variant must update the name.
   - `NoTemplateInfo` gains a `truncated: bool` field. Code that destructures `NoTemplateInfo` must include the new field (or use `..`).
   - `ConfigError` gains an `InvalidAllowedVersion(u16)` variant. Exhaustive matches on `ConfigError` must add this arm.
   - `NetflowParserBuilder::build()` now calls `validate()` and rejects out-of-range version numbers in `allowed_versions`.
   - `FieldValue::Duration` now wraps `DurationValue` instead of `std::time::Duration`. Use `DurationValue::as_duration()` to get a `std::time::Duration`. JSON output is unchanged.
   - `FieldValue::String` now wraps `StringValue` instead of `String`. Access the cleaned string via `.value`. `TryFrom<&FieldValue> for String` still works. JSON output is unchanged.

# 0.9.0

 * **New Feature: Pending Flow Caching**
   - Flows arriving before their template are now cached and automatically replayed when the template arrives
   - Configurable LRU cache with optional TTL expiration per pending entry
   - Disabled by default; enable via builder: `with_pending_flows()`, `with_v9_pending_flows()`, or `with_ipfix_pending_flows()`
   - New `PendingFlowsConfig` struct for controlling `max_pending_flows` (default 256), `max_entries_per_template` (default 1024), `max_entry_size_bytes` (default 65535), and `ttl`
   - Pending flow metrics tracked: `pending_cached`, `pending_replayed`, `pending_dropped`, `pending_replay_failed`
   - New methods: `clear_v9_pending_flows()`, `clear_ipfix_pending_flows()`
   - When caching is enabled, successfully-cached `NoTemplate` flowsets are removed from the parsed output; entries dropped by the cache (size/cap/LRU limits) keep their `NoTemplate` flowset in the output for diagnostics
   - Oversized flowset bodies (exceeding `max_entry_size_bytes`) are truncated to `max_error_sample_size` at parse time, avoiding a full allocation before the cache can reject them

 * **Security:** `NoTemplate` raw_data is truncated to `max_error_sample_size` when pending flow caching is disabled
   - Prevents large allocations from missing-template traffic when caching is not in use
   - Full raw data is only retained when pending flow caching is enabled and the entry is within `max_entry_size_bytes`

 * **Fix:** `to_be_bytes()` now recomputes header length/count from actually-serialized flowsets
   - V9 `header.count` and IPFIX `header.length` are written based on emitted flowsets, not the struct field
   - Previously, skipped `NoTemplate`/`Empty` flowsets caused a mismatch between the header and serialized body
   - Returns an error if V9 flowset count or IPFIX message length exceeds `u16::MAX`, instead of silently truncating
   - IPFIX `serialize_flowset_body()` now handles all `FlowSetBody` variants (`V9Templates`, `OptionsTemplates`, `V9OptionsTemplates`); previously these fell through to a catch-all that produced empty bodies

 * **BREAKING CHANGES:**
   - **V9 `FlowSetBody`** gains a `NoTemplate(NoTemplateInfo)` variant. V9 now continues parsing remaining flowsets when a template is missing, matching IPFIX behavior. Previously, a missing template would stop parsing the entire packet. Code with exhaustive `match` on `v9::FlowSetBody` must add a `NoTemplate(_)` arm.
   - **`ConfigError`** gains an `InvalidPendingCacheSize(usize)` variant, returned when `PendingFlowsConfig::max_pending_flows` is 0. Exhaustive matches on `ConfigError` must add this arm.
   - **`CacheStats`** gains a `pending_flow_count: usize` field. Code that destructures `CacheStats` must include the new field (or use `..`).
   - **`CacheMetrics`** and **`CacheMetricsSnapshot`** gain four fields: `pending_cached`, `pending_replayed`, `pending_dropped`, `pending_replay_failed`. Code that destructures either struct must include the new fields (or use `..`).

# 0.8.4
 * **BREAKING CHANGE:** Replaced tuple returns with named `ParserCacheStats` struct
   - Functions `get_source_stats()`, `all_stats()`, `ipfix_stats()`, `v9_stats()`, and `legacy_stats()` now return `ParserCacheStats` with `.v9` and `.ipfix` fields instead of `(CacheStats, CacheStats)` tuples
   - This eliminates ambiguity about which positional element is V9 vs IPFIX
   - Migration: Replace `(key, v9_stats, ipfix_stats)` destructuring with `(key, stats)` and access `stats.v9` / `stats.ipfix`
 * General code cleanup
 * Performance improvements: Optimized template caching using Arc for reduced cloning and added inlining hints for hot-path functions
 * Fixed CI workflow: cargo-deny/cargo-audit install now skips if binary already exists (prevents cache conflict errors)

# 0.8.3
 * Simplified docs.rs README updates.

# 0.8.2
 * Update missing docs.rs information.

# 0.8.1

  * **Bug Fixes:**
    * Fixed collision detection to only count true collisions (same template ID, different definition)
      - Previously, any template retransmission was incorrectly counted as a collision
      - RFC 7011 (IPFIX) and RFC 3954 (NetFlow v9) recommend sending templates multiple times at startup for reliability
      - Retransmitting the same template (same ID, identical definition) is now correctly handled as a template refresh
      - Only templates with the same ID but different definitions are now counted as collisions
      - Uses `LruCache::peek()` to check existing templates without affecting LRU ordering
    * **Impact:** Collision metrics will now accurately reflect actual template conflicts
    * **Migration:** No code changes required - metrics will automatically be more accurate

# 0.8.0

  * **Security Enhancements:**
    * Enhanced template validation with three layers of protection:
      - Field count limits (configurable, default 10,000)
      - Total size limits (default u16::MAX, prevents memory exhaustion)
      - Duplicate field detection (rejects malformed templates)
    * Templates validated before caching; invalid templates rejected immediately
    * Added public `is_valid()` methods for IPFIX templates
    * Removed unsafe unwrap operations in field parsing
    * Improved buffer boundary validation

  * **Bug Fixes:**
    * Fixed compilation error in `parse_bytes_as_netflow_common_flowsets()`
    * Fixed unreachable pattern warning in `NetflowCommon::try_from()`
    * Fixed `max_error_sample_size` configuration inconsistency
      - Added `max_error_sample_size` field to `Config` struct
      - Now properly propagates from builder to V9Parser and IPFixParser
      - Previously, builder setting only affected main parser, not internal parsers
      - `with_max_error_sample_size()` now correctly updates all parser instances

  * **BREAKING CHANGES:**
    * `parse_bytes()` now returns `ParseResult` instead of `Vec<NetflowPacket>`
      - Preserves successfully parsed packets even when errors occur mid-stream
      - Access packets via `.packets` field and errors via `.error` field
      - Use `.is_ok()` and `.is_err()` to check parsing status
    * `NetflowPacket::Error` variant removed from the enum
      - Errors are no longer inline with successful packets
      - Use `iter_packets()` which now yields `Result<NetflowPacket, NetflowError>`
      - Or use `parse_bytes()` and check the `.error` field of `ParseResult`
    * `iter_packets()` now yields `Result<NetflowPacket, NetflowError>` instead of `NetflowPacket`
      - Change from: `for packet in iter { match packet { NetflowPacket::Error(e) => ... } }`
      - Change to: `for result in iter { match result { Ok(packet) => ..., Err(e) => ... } }`
    * `FlowSetBody::NoTemplate` variant changed from `Vec<u8>` to `NoTemplateInfo` struct
      - Provides template ID, available templates list, and raw data for debugging
    * See README for detailed migration examples

  * **New Features:**
    * **AutoScopedParser** - RFC-compliant automatic template scoping
      - V9: `(source_addr, source_id)` per RFC 3954
      - IPFIX: `(source_addr, observation_domain_id)` per RFC 7011
      - Prevents template collisions in multi-router deployments
    * **RouterScopedParser** - Generic multi-source parser with per-source template caches
    * **Template Cache Metrics** - Performance tracking with atomic counters
      - Accessible via `v9_cache_stats()` and `ipfix_cache_stats()`
      - Tracks hits, misses, evictions, collisions, expirations
    * **Template Event Hooks** - Callback system for monitoring template lifecycle
      - Events: Learned, Collision, Evicted, Expired, MissingTemplate

  * **Documentation:**
    * New "Template Management Guide" in README covering multi-source deployments
    * RFC compliance documentation (RFC 3954 for V9, RFC 7011 for IPFIX)
    * New examples: `template_management_demo.rs`, `multi_source_comparison.rs`, `template_hooks.rs`
    * Updated UDP listener examples to use AutoScopedParser/RouterScopedParser
    * Added CI status, crates.io version, and docs.rs badges to README

# 0.7.4

  * **Fixed critical bug in protocol.rs:**
    * Fixed `impl From<u8> for ProtocolTypes` mapping that was off-by-one
    * Added missing case for `0` → `ProtocolTypes::Hopopt`
    * Fixed case `1` from `Hopopt` to `Icmp` (correct mapping)
    * Fixed case `144` from `Reserved` to `Aggfrag` (correct mapping)
    * Added missing case for `255` → `ProtocolTypes::Reserved`
    * **Impact:** Protocol field will now correctly identify protocol types
    * **Migration:** No code changes required, just update dependency version

# 0.7.3

  * Fixed several re-export issues in documentation
  * Corrected static_versions module imports
  * All types now properly accessible through documented paths
  * Documentation builds successfully with correct type links

# 0.7.2

  * Re-exports `lru` crate at crate root for easier access
  * Fixes broken doc links for LRU types in template cache documentation

# 0.7.1

  * Added complete serde support for all public types
  * Fixed missing Serialize/Deserialize derives on several structs
  * All NetFlow packet types can now be serialized to JSON/other formats
  * No breaking changes - purely additive

# 0.7.0

  * **BREAKING CHANGE:** Removed packet-based and combined TTL modes
  * Only time-based TTL is now supported via `TtlConfig`
  * Simplified TTL API reduces complexity and maintenance burden
  * Time-based TTL remains for handling template expiration
  * Migration: Replace `TtlMode::Packets` with time-based `TtlConfig` (see README)

# 0.6.0

  * Added Template TTL (Time-to-Live) support
  * Templates can now expire based on time or packet count
  * Configurable per-parser via builder pattern
  * New `TtlConfig` and `TtlMode` types
  * See README for usage examples
