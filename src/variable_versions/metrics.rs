//! Template cache metrics for monitoring parser performance

/// Metrics for tracking template cache performance.
///
/// All counters use plain u64 fields. The parser itself is not thread-safe
/// and should not be shared across threads.
#[derive(Debug, Default, Clone, Copy)]
pub struct CacheMetrics {
    /// Number of successful template lookups (cache hits)
    pub hits: u64,
    /// Number of failed template lookups (cache misses)
    pub misses: u64,
    /// Number of templates evicted due to LRU policy
    pub evictions: u64,
    /// Number of templates that expired due to TTL
    pub expired: u64,
    /// Number of template insertions (including replacements)
    pub insertions: u64,
    /// Number of template ID collisions (same ID, different definition)
    pub collisions: u64,
    /// Number of flows cached as pending (awaiting template)
    pub pending_cached: u64,
    /// Number of pending flows successfully replayed after template arrived
    pub pending_replayed: u64,
    /// Number of pending flows dropped (expired or evicted)
    pub pending_dropped: u64,
    /// Number of pending flows that failed to replay (parse error after template arrived)
    pub pending_replay_failed: u64,
}

impl CacheMetrics {
    /// Create a new metrics instance with all counters at zero
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache hit
    #[inline]
    pub(crate) fn record_hit(&mut self) {
        self.hits = self.hits.saturating_add(1);
    }

    /// Record a cache miss
    #[inline]
    pub(crate) fn record_miss(&mut self) {
        self.misses = self.misses.saturating_add(1);
    }

    /// Record a template eviction
    #[inline]
    pub(crate) fn record_eviction(&mut self) {
        self.evictions = self.evictions.saturating_add(1);
    }

    /// Record a template expiration
    #[inline]
    pub(crate) fn record_expiration(&mut self) {
        self.expired = self.expired.saturating_add(1);
    }

    /// Record a template insertion
    #[inline]
    pub(crate) fn record_insertion(&mut self) {
        self.insertions = self.insertions.saturating_add(1);
    }

    /// Record a template collision (same ID, different definition)
    #[inline]
    pub(crate) fn record_collision(&mut self) {
        self.collisions = self.collisions.saturating_add(1);
    }

    /// Record a flow cached as pending (awaiting template)
    #[inline]
    pub(crate) fn record_pending_cached(&mut self) {
        self.pending_cached = self.pending_cached.saturating_add(1);
    }

    /// Record a pending flow successfully replayed
    #[inline]
    pub(crate) fn record_pending_replayed(&mut self) {
        self.pending_replayed = self.pending_replayed.saturating_add(1);
    }

    /// Record a pending flow dropped (expired or evicted)
    #[inline]
    pub(crate) fn record_pending_dropped(&mut self) {
        self.pending_dropped = self.pending_dropped.saturating_add(1);
    }

    /// Record multiple pending flows dropped at once
    #[inline]
    pub(crate) fn record_pending_dropped_n(&mut self, n: u64) {
        self.pending_dropped = self.pending_dropped.saturating_add(n);
    }

    /// Record a pending flow that failed to replay (parse error)
    #[inline]
    pub(crate) fn record_pending_replay_failed(&mut self) {
        self.pending_replay_failed = self.pending_replay_failed.saturating_add(1);
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> CacheMetricsSnapshot {
        CacheMetricsSnapshot {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            expired: self.expired,
            insertions: self.insertions,
            collisions: self.collisions,
            pending_cached: self.pending_cached,
            pending_replayed: self.pending_replayed,
            pending_dropped: self.pending_dropped,
            pending_replay_failed: self.pending_replay_failed,
        }
    }
}

/// A point-in-time snapshot of cache metrics.
///
/// This provides a consistent view of metrics without requiring atomic operations
/// for each field access.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheMetricsSnapshot {
    /// Number of successful template lookups (cache hits)
    pub hits: u64,
    /// Number of failed template lookups (cache misses)
    pub misses: u64,
    /// Number of templates evicted due to LRU policy
    pub evictions: u64,
    /// Number of templates that expired due to TTL
    pub expired: u64,
    /// Number of template insertions (including replacements)
    pub insertions: u64,
    /// Number of template ID collisions (same ID, different definition)
    pub collisions: u64,
    /// Number of flows cached as pending (awaiting template)
    pub pending_cached: u64,
    /// Number of pending flows successfully replayed after template arrived
    pub pending_replayed: u64,
    /// Number of pending flows dropped (expired or evicted)
    pub pending_dropped: u64,
    /// Number of pending flows that failed to replay (parse error after template arrived)
    pub pending_replay_failed: u64,
}

impl CacheMetricsSnapshot {
    /// Calculate the cache hit rate (0.0 to 1.0)
    ///
    /// Returns `None` if there have been no lookups yet.
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            None
        } else {
            Some(self.hits as f64 / total as f64)
        }
    }

    /// Calculate the cache miss rate (0.0 to 1.0)
    ///
    /// Returns `None` if there have been no lookups yet.
    pub fn miss_rate(&self) -> Option<f64> {
        self.hit_rate().map(|hr| 1.0 - hr)
    }

    /// Total number of template lookups (hits + misses)
    pub fn total_lookups(&self) -> u64 {
        self.hits.saturating_add(self.misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify each record method increments the correct counter in the snapshot
    #[test]
    fn test_metrics_recording() {
        let mut metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();
        metrics.record_eviction();
        metrics.record_expiration();
        metrics.record_insertion();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.hits, 2);
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.evictions, 1);
        assert_eq!(snapshot.expired, 1);
        assert_eq!(snapshot.insertions, 1);
    }

    // Verify hit_rate and miss_rate calculations, including None when no lookups exist
    #[test]
    fn test_hit_rate() {
        let mut metrics = CacheMetrics::new();

        // No lookups yet
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.hit_rate(), None);

        // Record some hits and misses
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.hit_rate(), Some(0.75));
        assert_eq!(snapshot.miss_rate(), Some(0.25));
        assert_eq!(snapshot.total_lookups(), 4);
    }
}
