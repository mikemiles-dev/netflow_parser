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
    * **CRITICAL:** Fixed compilation error in `parse_bytes_as_netflow_common_flowsets()`
    * Fixed unreachable pattern warning in `NetflowCommon::try_from()`

  * **BREAKING CHANGES:**
    * `parse_bytes()` now returns `ParseResult` instead of `Result<Vec<NetflowPacket>, NetflowError>`
      - Preserves successfully parsed packets even when errors occur mid-stream
      - Use `.into_result()` for backward compatibility (fail-fast behavior)
    * `FlowSetBody::NoTemplate` variant changed from `Vec<u8>` to `NoTemplateInfo` struct
      - Provides template ID, available templates list, and raw data for debugging

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

  * **Testing & Benchmarks:**
    * New comprehensive DoS/edge case test suite with 15+ security tests
    * New packet size benchmark suite (V5/V9/IPFIX, various flow counts)
    * Added CI job for `netflow_common` feature validation
    * Added 48 integration tests across 7 test files

  * **Performance:**
    * Optimized enterprise field registration (reduced cloning)

  * **Documentation:**
    * New "Template Management Guide" in README covering multi-source deployments
    * RFC compliance documentation (RFC 3954 for V9, RFC 7011 for IPFIX)
    * New examples: `template_management_demo.rs`, `multi_source_comparison.rs`, `template_hooks.rs`
    * Updated UDP listener examples to use AutoScopedParser/RouterScopedParser
    * Added CI status, crates.io version, and docs.rs badges to README

  * **Migration Notes (from 0.7.x):**
    * Use `.into_result()` on ParseResult for fail-fast behavior
    * Update `FlowSetBody::NoTemplate` pattern matches to use `NoTemplateInfo` struct
    * Consider migrating to `AutoScopedParser` for multi-router deployments
    * See README for detailed migration examples

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
