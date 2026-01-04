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
