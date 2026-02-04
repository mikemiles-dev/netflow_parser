//! Variable-length NetFlow protocols (V9 and IPFIX).
//!
//! This module provides parsers and data structures for NetFlow V9 and IPFIX protocols,
//! which use template-based field definitions for flexible flow record formats.
//!
//! # Architecture
//!
//! NetFlow V9 and IPFIX are template-based protocols where:
//! 1. **Templates** define the structure of data records (field types and lengths)
//! 2. **Data Records** contain the actual flow information
//! 3. **Templates are cached** and reused across multiple data records
//!
//! ## Key Differences: V9 vs IPFIX
//!
//! | Feature | NetFlow V9 | IPFIX |
//! |---------|-----------|-------|
//! | Standard | Cisco proprietary | IETF standard (RFC 7011) |
//! | Template IDs | 256-65535 | 256-65535 |
//! | Enterprise Fields | Limited support | Full enterprise field support |
//! | Variable Length | Fixed length only | Variable length fields supported |
//!
//! # Template Caching
//!
//! Both V9 and IPFIX parsers maintain an LRU cache of templates to avoid
//! reprocessing template definitions. Configure cache size via [`Config`]:
//!
//! ```
//! use netflow_parser::variable_versions::Config;
//!
//! let config = Config::new(10000, None);
//! ```
//!
//! # Enterprise Fields
//!
//! IPFIX supports vendor-specific fields through enterprise IDs. Common vendors:
//!
//! | Vendor | Enterprise ID | Module |
//! |--------|---------------|--------|
//! | IANA (standard) | 0 | [`ipfix_lookup::IANAIPFixField`] |
//! | Cisco | 9 | [`ipfix_lookup::CiscoIPFixField`] |
//! | NetScaler | 5951 | [`ipfix_lookup::NetscalerIPFixField`] |
//! | YAF | 6871 | [`ipfix_lookup::YafIPFixField`] |
//! | VMware | 6876 | [`ipfix_lookup::VMWareIPFixField`] |
//!
//! Register custom enterprise fields using [`EnterpriseFieldRegistry`]:
//!
//! ```
//! use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
//!
//! let mut registry = EnterpriseFieldRegistry::new();
//! // Register your custom fields...
//! ```
//!
//! # TTL (Template Expiration)
//!
//! Templates can be configured to expire after a certain time using [`TtlConfig`].
//! This is useful for long-running parsers to avoid stale template issues.
//!
//! # Modules
//!
//! - [`v9`] - NetFlow V9 parser and data structures
//! - [`ipfix`] - IPFIX parser and data structures
//! - [`v9_lookup`] - V9 field type definitions
//! - [`ipfix_lookup`] - IPFIX field type definitions (IANA and enterprise)
//! - [`data_number`] - Field value types and parsing
//! - [`enterprise_registry`] - Custom enterprise field registration
//! - [`ttl`] - Template expiration configuration
//! - [`metrics`] - Template cache performance metrics

pub mod data_number;
pub mod enterprise_registry;
pub mod ipfix;
pub mod ipfix_lookup;
pub mod metrics;
pub mod ttl;
pub mod v9;
pub mod v9_lookup;

use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::metrics::CacheMetrics;
use crate::variable_versions::ttl::TtlConfig;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// Configuration for pending flow caching.
///
/// When enabled, flows that arrive before their template are cached.
/// When the template later arrives, cached flows are automatically
/// re-parsed and included in the output.
///
/// Disabled by default; enable via the builder pattern.
#[derive(Debug, Clone)]
pub struct PendingFlowsConfig {
    /// Maximum number of template IDs to track in the LRU pending cache.
    pub max_pending_flows: usize,
    /// Maximum number of pending flow entries per template ID.
    /// Prevents unbounded memory growth from a flood of data for a single unknown template.
    pub max_entries_per_template: usize,
    /// Maximum size in bytes of a single pending flow entry's raw data.
    /// Entries exceeding this limit are dropped to prevent memory exhaustion
    /// from oversized flowset bodies. Default: 65535 (u16::MAX).
    pub max_entry_size_bytes: usize,
    /// TTL for pending flows. `None` means pending flows never expire
    /// (only evicted by LRU or per-template cap).
    pub ttl: Option<Duration>,
}

impl Default for PendingFlowsConfig {
    fn default() -> Self {
        Self {
            max_pending_flows: 256,
            max_entries_per_template: 1024,
            max_entry_size_bytes: u16::MAX as usize,
            ttl: None,
        }
    }
}

impl PendingFlowsConfig {
    /// Create a new PendingFlowsConfig with the given capacity.
    pub fn new(max_pending_flows: usize) -> Self {
        Self {
            max_pending_flows,
            max_entries_per_template: 1024,
            max_entry_size_bytes: u16::MAX as usize,
            ttl: None,
        }
    }

    /// Create a new PendingFlowsConfig with capacity and TTL.
    pub fn with_ttl(max_pending_flows: usize, ttl: Duration) -> Self {
        Self {
            max_pending_flows,
            max_entries_per_template: 1024,
            max_entry_size_bytes: u16::MAX as usize,
            ttl: Some(ttl),
        }
    }
}

/// Entry in the pending flows cache, storing raw data with a timestamp.
#[derive(Debug, Clone)]
pub(crate) struct PendingFlowEntry {
    pub(crate) raw_data: Vec<u8>,
    pub(crate) cached_at: Instant,
}

/// LRU cache for pending flows keyed by template ID.
///
/// Provides caching, draining with TTL expiration, and per-template-ID entry limits.
#[derive(Debug)]
pub(crate) struct PendingFlowCache {
    cache: LruCache<u16, Vec<PendingFlowEntry>>,
    config: PendingFlowsConfig,
}

impl PendingFlowCache {
    /// Maximum size in bytes that this cache will accept for a single entry.
    pub(crate) fn max_entry_size_bytes(&self) -> usize {
        self.config.max_entry_size_bytes
    }

    /// Best-effort check whether the cache would accept a new entry for
    /// `template_id`.  Returns `false` when the per-template cap is already
    /// reached, avoiding a full clone that would be immediately rejected.
    ///
    /// Uses `peek` so the query does not promote the key in the LRU.
    pub(crate) fn would_accept(&self, template_id: u16) -> bool {
        match self.cache.peek(&template_id) {
            Some(entries) => entries.len() < self.config.max_entries_per_template,
            None => true,
        }
    }

    /// Create a new PendingFlowCache from the given configuration.
    ///
    /// # Errors
    /// Returns `ConfigError::InvalidPendingCacheSize` if `max_pending_flows` is 0.
    pub(crate) fn new(config: PendingFlowsConfig) -> Result<Self, ConfigError> {
        let size = NonZeroUsize::new(config.max_pending_flows).ok_or(
            ConfigError::InvalidPendingCacheSize(config.max_pending_flows),
        )?;
        Ok(Self {
            cache: LruCache::new(size),
            config,
        })
    }

    /// Cache a pending flow for later replay when its template arrives.
    ///
    /// Returns `None` if the entry was successfully cached.
    /// Returns `Some(raw_data)` if the entry was dropped (due to size limits,
    /// per-template cap, or LRU eviction), returning ownership of the data
    /// so the caller can preserve it for diagnostic output.
    ///
    /// When a TTL is configured, expired entries for the touched `template_id`
    /// are pruned before checking capacity. If the cache is at its template-ID
    /// limit, a global expired-entry sweep runs before falling back to LRU
    /// eviction, so stale entries don't displace valid ones.
    pub(crate) fn cache(
        &mut self,
        template_id: u16,
        raw_data: Vec<u8>,
        metrics: &CacheMetrics,
    ) -> Option<Vec<u8>> {
        if raw_data.len() > self.config.max_entry_size_bytes {
            metrics.record_pending_dropped();
            return Some(raw_data);
        }

        // Prune expired entries for this template before checking capacity.
        self.prune_expired_for_template(template_id, metrics);

        if let Some(entries) = self.cache.peek_mut(&template_id) {
            if entries.len() >= self.config.max_entries_per_template {
                // Reject without promoting the key in the LRU so a
                // hot-but-full template can still be evicted.
                metrics.record_pending_dropped();
                return Some(raw_data);
            }
            entries.push(PendingFlowEntry {
                raw_data,
                cached_at: Instant::now(),
            });
            // Promote only after a successful insert.
            self.cache.promote(&template_id);
        } else {
            // Before LRU eviction, sweep all expired entries to free space.
            if self.cache.len() >= self.cache.cap().get() {
                self.purge_expired(metrics);
            }
            // If still at capacity after purging, evict LRU.
            if self.cache.len() >= self.cache.cap().get()
                && let Some((_, evicted)) = self.cache.pop_lru()
            {
                for _ in 0..evicted.len() {
                    metrics.record_pending_dropped();
                }
            }
            self.cache.put(
                template_id,
                vec![PendingFlowEntry {
                    raw_data,
                    cached_at: Instant::now(),
                }],
            );
        }
        metrics.record_pending_cached();
        None
    }

    /// Drain pending flows for a given template ID, filtering expired entries.
    pub(crate) fn drain(
        &mut self,
        template_id: u16,
        metrics: &CacheMetrics,
    ) -> Vec<PendingFlowEntry> {
        let Some(entries) = self.cache.pop(&template_id) else {
            return Vec::new();
        };

        if let Some(ttl_duration) = self.config.ttl {
            let (valid, expired): (Vec<_>, Vec<_>) = entries
                .into_iter()
                .partition(|e| e.cached_at.elapsed() < ttl_duration);
            for _ in 0..expired.len() {
                metrics.record_pending_dropped();
            }
            valid
        } else {
            entries
        }
    }

    /// Remove expired entries from a single template's vector.
    /// If all entries expire, the key is removed from the cache.
    fn prune_expired_for_template(&mut self, template_id: u16, metrics: &CacheMetrics) {
        let Some(ttl) = self.config.ttl else { return };
        // Use peek_mut so pruning alone doesn't promote the key.
        let should_remove = self
            .cache
            .peek_mut(&template_id)
            .is_some_and(|entries| Self::drop_expired_entries(entries, ttl, metrics));
        if should_remove {
            self.cache.pop(&template_id);
        }
    }

    /// Remove expired entries from every template in the cache.
    /// Empty keys are removed so their slots can be reused.
    fn purge_expired(&mut self, metrics: &CacheMetrics) {
        let Some(ttl) = self.config.ttl else { return };
        let keys: Vec<u16> = self.cache.iter().map(|(&k, _)| k).collect();
        for key in keys {
            // Use peek_mut so sweeping doesn't disturb LRU ordering.
            let should_remove = self
                .cache
                .peek_mut(&key)
                .is_some_and(|entries| Self::drop_expired_entries(entries, ttl, metrics));
            if should_remove {
                self.cache.pop(&key);
            }
        }
    }

    /// Retain only non-expired entries, recording `pending_dropped` for each
    /// removed entry. Returns `true` when the vector is now empty.
    fn drop_expired_entries(
        entries: &mut Vec<PendingFlowEntry>,
        ttl: Duration,
        metrics: &CacheMetrics,
    ) -> bool {
        let before = entries.len();
        entries.retain(|e| e.cached_at.elapsed() < ttl);
        let expired = before - entries.len();
        for _ in 0..expired {
            metrics.record_pending_dropped();
        }
        entries.is_empty()
    }

    /// Returns the total number of pending flow entries across all template IDs.
    pub(crate) fn count(&self) -> usize {
        self.cache.iter().map(|(_, entries)| entries.len()).sum()
    }

    /// Clear all pending flows.
    pub(crate) fn clear(&mut self) {
        self.cache.clear();
    }

    /// Resize the LRU cache, recording `pending_dropped` for every entry
    /// evicted when the new capacity is smaller than the current size.
    ///
    /// Also enforces the new `max_entries_per_template` and
    /// `max_entry_size_bytes` limits on already-cached entries, dropping
    /// any that exceed the new bounds.
    ///
    /// # Errors
    /// Returns `ConfigError::InvalidPendingCacheSize` if `max_pending_flows` is 0.
    pub(crate) fn resize(
        &mut self,
        config: PendingFlowsConfig,
        metrics: &CacheMetrics,
    ) -> Result<(), ConfigError> {
        let size = NonZeroUsize::new(config.max_pending_flows).ok_or(
            ConfigError::InvalidPendingCacheSize(config.max_pending_flows),
        )?;
        // Manually evict LRU entries that exceed the new capacity so each
        // individual pending flow entry is reflected in pending_dropped.
        while self.cache.len() > size.get() {
            if let Some((_, evicted)) = self.cache.pop_lru() {
                for _ in 0..evicted.len() {
                    metrics.record_pending_dropped();
                }
            }
        }
        self.cache.resize(size);

        // Enforce new per-entry and per-template limits on remaining entries.
        Self::trim_existing_entries(&mut self.cache, &config, metrics);

        self.config = config;
        Ok(())
    }

    /// Drop entries that violate `max_entry_size_bytes` and truncate
    /// per-template vectors that exceed `max_entries_per_template`,
    /// recording `pending_dropped` for each removed entry.
    fn trim_existing_entries(
        cache: &mut LruCache<u16, Vec<PendingFlowEntry>>,
        config: &PendingFlowsConfig,
        metrics: &CacheMetrics,
    ) {
        // Collect keys first to avoid borrowing issues during iteration.
        let keys: Vec<u16> = cache.iter().map(|(&k, _)| k).collect();
        for key in keys {
            // Use peek_mut so trimming doesn't disturb LRU ordering.
            let Some(entries) = cache.peek_mut(&key) else {
                continue;
            };

            // Drop entries whose raw_data exceeds the new size limit.
            let before = entries.len();
            entries.retain(|e| e.raw_data.len() <= config.max_entry_size_bytes);
            let oversize_dropped = before - entries.len();
            for _ in 0..oversize_dropped {
                metrics.record_pending_dropped();
            }

            // Truncate to the new per-template cap (keep oldest = front).
            if entries.len() > config.max_entries_per_template {
                let excess = entries.len() - config.max_entries_per_template;
                entries.truncate(config.max_entries_per_template);
                for _ in 0..excess {
                    metrics.record_pending_dropped();
                }
            }

            // Remove the key entirely if no entries remain.
            if entries.is_empty() {
                cache.pop(&key);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub max_template_cache_size: usize,
    pub max_field_count: usize,
    /// Maximum total size (in bytes) of all fields in a template.
    /// This prevents DoS attacks via templates with excessive total field lengths.
    /// Default: u16::MAX
    pub max_template_total_size: usize,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
    pub ttl_config: Option<TtlConfig>,
    pub enterprise_registry: EnterpriseFieldRegistry,
    /// Configuration for pending flow caching. `None` means disabled (default).
    pub pending_flows_config: Option<PendingFlowsConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Template cache size must be greater than 0
    InvalidCacheSize(usize),
    /// Pending flow cache size must be greater than 0
    InvalidPendingCacheSize(usize),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidCacheSize(size) => {
                write!(
                    f,
                    "Invalid template cache size: {}. Must be greater than 0.",
                    size
                )
            }
            ConfigError::InvalidPendingCacheSize(size) => {
                write!(
                    f,
                    "Invalid pending flow cache size: {}. Must be greater than 0.",
                    size
                )
            }
        }
    }
}

impl Config {
    pub fn new(max_template_cache_size: usize, ttl_config: Option<TtlConfig>) -> Self {
        Self {
            max_template_cache_size,
            max_field_count: usize::from(ipfix::MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config,
            enterprise_registry: EnterpriseFieldRegistry::new(),
            pending_flows_config: None,
        }
    }

    pub fn with_enterprise_registry(
        max_template_cache_size: usize,
        ttl_config: Option<TtlConfig>,
        enterprise_registry: EnterpriseFieldRegistry,
    ) -> Self {
        Self {
            max_template_cache_size,
            max_field_count: usize::from(ipfix::MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config,
            enterprise_registry,
            pending_flows_config: None,
        }
    }
}

/// Trait for parsers that support template caching and TTL configuration
pub trait ParserConfig {
    /// Add or update the parser's configuration
    fn add_config(&mut self, config: Config) -> Result<(), ConfigError>;

    /// Set the maximum template cache size
    fn set_max_template_cache_size(&mut self, size: usize) -> Result<(), ConfigError>;

    /// Set the TTL configuration for templates
    fn set_ttl_config(&mut self, ttl_config: Option<TtlConfig>) -> Result<(), ConfigError>;

    /// Set the pending flows configuration
    ///
    /// # Errors
    /// Returns `ConfigError::InvalidPendingCacheSize` if `max_pending_flows` is 0.
    fn set_pending_flows_config(
        &mut self,
        config: Option<PendingFlowsConfig>,
    ) -> Result<(), ConfigError>;

    /// Internal helper: resize all template caches to the given size
    fn resize_template_caches(&mut self, cache_size: NonZeroUsize);
}
