//! Pending flow cache for flows arriving before their template.
//!
//! When enabled, flows that reference an unknown template ID are cached in an LRU
//! structure keyed by template ID. When the template later arrives, cached flows
//! are drained and re-parsed.

use super::config::ConfigError;
use super::metrics::CacheMetrics;
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
    /// from oversized flowset bodies. Default: 65531 (u16::MAX - 4).
    /// Must not exceed 65531 to fit within the 16-bit FlowSet length field.
    pub max_entry_size_bytes: usize,
    /// Maximum total bytes across all pending flow entries.
    /// When exceeded, LRU template entries are evicted until under the limit.
    /// Default: 67,108,864 (64 MB).
    pub max_total_bytes: usize,
    /// TTL for pending flows. `None` means pending flows never expire
    /// (only evicted by LRU or per-template cap).
    pub ttl: Option<Duration>,
}

/// Default total byte limit: 64 MB
const DEFAULT_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Maximum allowed entry size in bytes. The FlowSet header is 4 bytes, so the
/// data portion must fit in `u16::MAX - 4` to avoid overflow in the 16-bit
/// FlowSet length field on replay.
const MAX_ENTRY_SIZE_LIMIT: usize = u16::MAX as usize - 4;

impl Default for PendingFlowsConfig {
    fn default() -> Self {
        Self {
            max_pending_flows: 256,
            max_entries_per_template: 1024,
            max_entry_size_bytes: MAX_ENTRY_SIZE_LIMIT,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
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
            max_entry_size_bytes: MAX_ENTRY_SIZE_LIMIT,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            ttl: None,
        }
    }

    /// Create a new PendingFlowsConfig with capacity and TTL.
    pub fn with_ttl(max_pending_flows: usize, ttl: Duration) -> Self {
        Self {
            max_pending_flows,
            max_entries_per_template: 1024,
            max_entry_size_bytes: MAX_ENTRY_SIZE_LIMIT,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
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
    total_bytes: usize,
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
    /// When TTL is configured, only non-expired entries count toward the cap
    /// so the decision matches what `cache()` would do after pruning.
    pub(crate) fn would_accept(&self, template_id: u16) -> bool {
        match self.cache.peek(&template_id) {
            Some(entries) => {
                let live = match self.config.ttl {
                    Some(ttl) => entries
                        .iter()
                        .filter(|e| e.cached_at.elapsed() < ttl)
                        .count(),
                    None => entries.len(),
                };
                live < self.config.max_entries_per_template
            }
            None => true,
        }
    }

    /// Validates pending flow configuration without allocating.
    pub(crate) fn validate_config(config: &PendingFlowsConfig) -> Result<(), ConfigError> {
        NonZeroUsize::new(config.max_pending_flows).ok_or(
            ConfigError::InvalidPendingCacheSize(config.max_pending_flows),
        )?;
        if config.max_entries_per_template == 0 {
            return Err(ConfigError::InvalidEntriesPerTemplate(0));
        }
        if config.max_entry_size_bytes == 0
            || config.max_entry_size_bytes > MAX_ENTRY_SIZE_LIMIT
        {
            return Err(ConfigError::InvalidEntrySize(config.max_entry_size_bytes));
        }
        if config.max_total_bytes == 0 {
            return Err(ConfigError::InvalidPendingCacheSize(0));
        }
        Ok(())
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
            total_bytes: 0,
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
        metrics: &mut CacheMetrics,
    ) -> Option<Vec<u8>> {
        if raw_data.len() > self.config.max_entry_size_bytes {
            metrics.record_pending_dropped();
            return Some(raw_data);
        }

        // Enforce total byte limit: evict LRU templates until under budget.
        while self.total_bytes.saturating_add(raw_data.len()) > self.config.max_total_bytes {
            if let Some((_, evicted)) = self.cache.pop_lru() {
                let evicted_bytes: usize = evicted.iter().map(|e| e.raw_data.len()).sum();
                self.total_bytes = self.total_bytes.saturating_sub(evicted_bytes);
                metrics.record_pending_dropped_n(evicted.len() as u64);
            } else {
                // Cache is empty but single entry exceeds total limit
                metrics.record_pending_dropped();
                return Some(raw_data);
            }
        }

        // Prune expired entries for this template before checking capacity.
        self.prune_expired_for_template(template_id, metrics);

        // The peek_mut borrow must be released before we call promote(),
        // so we resolve the entire if/else in one expression and promote
        // afterward based on the returned flag.
        let entry_size = raw_data.len();
        let needs_promote = if let Some(entries) = self.cache.peek_mut(&template_id) {
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
            true
        } else {
            // Before LRU eviction, sweep all expired entries to free space.
            if self.cache.len() >= self.cache.cap().get() {
                self.purge_expired(metrics);
            }
            // If still at capacity after purging, evict LRU.
            if self.cache.len() >= self.cache.cap().get()
                && let Some((_, evicted)) = self.cache.pop_lru()
            {
                let evicted_bytes: usize = evicted.iter().map(|e| e.raw_data.len()).sum();
                self.total_bytes = self.total_bytes.saturating_sub(evicted_bytes);
                metrics.record_pending_dropped_n(evicted.len() as u64);
            }
            self.cache.put(
                template_id,
                vec![PendingFlowEntry {
                    raw_data,
                    cached_at: Instant::now(),
                }],
            );
            false
        };
        if needs_promote {
            self.cache.promote(&template_id);
        }
        self.total_bytes = self.total_bytes.saturating_add(entry_size);
        metrics.record_pending_cached();
        None
    }

    /// Drain pending flows for a given template ID, filtering expired entries.
    pub(crate) fn drain(
        &mut self,
        template_id: u16,
        metrics: &mut CacheMetrics,
    ) -> Vec<PendingFlowEntry> {
        let Some(entries) = self.cache.pop(&template_id) else {
            return Vec::new();
        };

        let popped_bytes: usize = entries.iter().map(|e| e.raw_data.len()).sum();
        self.total_bytes = self.total_bytes.saturating_sub(popped_bytes);

        if let Some(ttl_duration) = self.config.ttl {
            let (valid, expired): (Vec<_>, Vec<_>) = entries
                .into_iter()
                .partition(|e| e.cached_at.elapsed() < ttl_duration);
            metrics.record_pending_dropped_n(expired.len() as u64);
            valid
        } else {
            entries
        }
    }

    /// Remove expired entries from a single template's vector.
    /// If all entries expire, the key is removed from the cache.
    fn prune_expired_for_template(&mut self, template_id: u16, metrics: &mut CacheMetrics) {
        let Some(ttl) = self.config.ttl else { return };
        // Use peek_mut so pruning alone doesn't promote the key.
        let result = self
            .cache
            .peek_mut(&template_id)
            .map(|entries| Self::drop_expired_entries(entries, ttl, metrics));
        if let Some((is_empty, freed)) = result {
            self.total_bytes = self.total_bytes.saturating_sub(freed);
            if is_empty {
                self.cache.pop(&template_id);
            }
        }
    }

    /// Remove expired entries from every template in the cache.
    /// Empty keys are removed so their slots can be reused.
    fn purge_expired(&mut self, metrics: &mut CacheMetrics) {
        let Some(ttl) = self.config.ttl else { return };
        let keys: Vec<u16> = self.cache.iter().map(|(&k, _)| k).collect();
        for key in keys {
            // Use peek_mut so sweeping doesn't disturb LRU ordering.
            let result = self
                .cache
                .peek_mut(&key)
                .map(|entries| Self::drop_expired_entries(entries, ttl, metrics));
            if let Some((is_empty, freed)) = result {
                self.total_bytes = self.total_bytes.saturating_sub(freed);
                if is_empty {
                    self.cache.pop(&key);
                }
            }
        }
    }

    /// Retain only non-expired entries, recording `pending_dropped` for each
    /// removed entry. Returns `(is_empty, freed_bytes)`.
    fn drop_expired_entries(
        entries: &mut Vec<PendingFlowEntry>,
        ttl: Duration,
        metrics: &mut CacheMetrics,
    ) -> (bool, usize) {
        let before_len = entries.len();
        let before_bytes: usize = entries.iter().map(|e| e.raw_data.len()).sum();
        entries.retain(|e| e.cached_at.elapsed() < ttl);
        let after_bytes: usize = entries.iter().map(|e| e.raw_data.len()).sum();
        metrics.record_pending_dropped_n((before_len - entries.len()) as u64);
        (entries.is_empty(), before_bytes - after_bytes)
    }

    /// Returns the total number of pending flow entries across all template IDs.
    pub(crate) fn count(&self) -> usize {
        self.cache.iter().map(|(_, entries)| entries.len()).sum()
    }

    /// Clear all pending flows.
    pub(crate) fn clear(&mut self) {
        self.cache.clear();
        self.total_bytes = 0;
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
        metrics: &mut CacheMetrics,
    ) -> Result<(), ConfigError> {
        let size = NonZeroUsize::new(config.max_pending_flows).ok_or(
            ConfigError::InvalidPendingCacheSize(config.max_pending_flows),
        )?;
        // Manually evict LRU entries that exceed the new capacity so each
        // individual pending flow entry is reflected in pending_dropped.
        while self.cache.len() > size.get() {
            if let Some((_, evicted)) = self.cache.pop_lru() {
                let evicted_bytes: usize = evicted.iter().map(|e| e.raw_data.len()).sum();
                self.total_bytes = self.total_bytes.saturating_sub(evicted_bytes);
                metrics.record_pending_dropped_n(evicted.len() as u64);
            }
        }
        self.cache.resize(size);

        // Enforce new per-entry and per-template limits on remaining entries.
        let freed = Self::trim_existing_entries(&mut self.cache, &config, metrics);
        self.total_bytes = self.total_bytes.saturating_sub(freed);

        self.config = config;
        Ok(())
    }

    /// Drop entries that violate `max_entry_size_bytes` and truncate
    /// per-template vectors that exceed `max_entries_per_template`,
    /// recording `pending_dropped` for each removed entry.
    /// Returns the total number of bytes freed.
    fn trim_existing_entries(
        cache: &mut LruCache<u16, Vec<PendingFlowEntry>>,
        config: &PendingFlowsConfig,
        metrics: &mut CacheMetrics,
    ) -> usize {
        let mut freed = 0usize;
        // Collect keys first to avoid borrowing issues during iteration.
        let keys: Vec<u16> = cache.iter().map(|(&k, _)| k).collect();
        for key in keys {
            // Use peek_mut so trimming doesn't disturb LRU ordering.
            let Some(entries) = cache.peek_mut(&key) else {
                continue;
            };

            // Drop entries whose raw_data exceeds the new size limit.
            let before_len = entries.len();
            let before_bytes: usize = entries.iter().map(|e| e.raw_data.len()).sum();
            entries.retain(|e| e.raw_data.len() <= config.max_entry_size_bytes);
            metrics.record_pending_dropped_n((before_len - entries.len()) as u64);

            // Truncate to the new per-template cap (keep oldest = front).
            if entries.len() > config.max_entries_per_template {
                let excess = entries.len() - config.max_entries_per_template;
                entries.truncate(config.max_entries_per_template);
                metrics.record_pending_dropped_n(excess as u64);
            }

            let after_bytes: usize = entries.iter().map(|e| e.raw_data.len()).sum();
            freed += before_bytes - after_bytes;

            // Remove the key entirely if no entries remain.
            if entries.is_empty() {
                cache.pop(&key);
            }
        }
        freed
    }
}
