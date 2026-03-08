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
    pub fn record_hit(&mut self) {
        self.hits += 1;
    }

    /// Record a cache miss
    #[inline]
    pub fn record_miss(&mut self) {
        self.misses += 1;
    }

    /// Record a template eviction
    #[inline]
    pub fn record_eviction(&mut self) {
        self.evictions += 1;
    }

    /// Record a template expiration
    #[inline]
    pub fn record_expiration(&mut self) {
        self.expired += 1;
    }

    /// Record a template insertion
    #[inline]
    pub fn record_insertion(&mut self) {
        self.insertions += 1;
    }

    /// Record a template collision (same ID, different definition)
    #[inline]
    pub fn record_collision(&mut self) {
        self.collisions += 1;
    }

    /// Record a flow cached as pending (awaiting template)
    #[inline]
    pub fn record_pending_cached(&mut self) {
        self.pending_cached += 1;
    }

    /// Record a pending flow successfully replayed
    #[inline]
    pub fn record_pending_replayed(&mut self) {
        self.pending_replayed += 1;
    }

    /// Record a pending flow dropped (expired or evicted)
    #[inline]
    pub fn record_pending_dropped(&mut self) {
        self.pending_dropped += 1;
    }

    /// Record a pending flow that failed to replay (parse error)
    #[inline]
    pub fn record_pending_replay_failed(&mut self) {
        self.pending_replay_failed += 1;
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

    /// Reset all metrics to zero
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// A point-in-time snapshot of cache metrics.
///
/// This provides a consistent view of metrics without requiring atomic operations
/// for each field access.
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
        let total = self.hits + self.misses;
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
        self.hits + self.misses
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

    // Verify reset zeroes all counters
    #[test]
    fn test_reset() {
        let mut metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_miss();
        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.hits, 0);
        assert_eq!(snapshot.misses, 0);
    }
}
