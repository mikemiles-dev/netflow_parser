//! Template cache metrics for monitoring parser performance

use std::sync::atomic::{AtomicU64, Ordering};

/// Event type for template collision detection
#[derive(Debug, Clone)]
pub enum TemplateEvent {
    /// A template was replaced with a different definition for the same ID
    TemplateReplaced {
        template_id: u16,
        collision_count: u64,
    },
}

/// Metrics for tracking template cache performance.
///
/// All counters use atomic operations for thread-safe reads, though
/// the parser itself is not thread-safe and should not be shared across threads.
#[derive(Debug, Default)]
pub struct CacheMetrics {
    /// Number of successful template lookups (cache hits)
    pub hits: AtomicU64,
    /// Number of failed template lookups (cache misses)
    pub misses: AtomicU64,
    /// Number of templates evicted due to LRU policy
    pub evictions: AtomicU64,
    /// Number of templates that expired due to TTL
    pub expired: AtomicU64,
    /// Number of template insertions (including replacements)
    pub insertions: AtomicU64,
    /// Number of template ID collisions (same ID, different definition)
    pub collisions: AtomicU64,
}

impl CacheMetrics {
    /// Create a new metrics instance with all counters at zero
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache hit
    #[inline]
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    #[inline]
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a template eviction
    #[inline]
    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a template expiration
    #[inline]
    pub fn record_expiration(&self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a template insertion
    #[inline]
    pub fn record_insertion(&self) {
        self.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a template collision (same ID, different definition)
    #[inline]
    pub fn record_collision(&self) {
        self.collisions.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> CacheMetricsSnapshot {
        CacheMetricsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            insertions: self.insertions.load(Ordering::Relaxed),
            collisions: self.collisions.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.expired.store(0, Ordering::Relaxed);
        self.insertions.store(0, Ordering::Relaxed);
        self.collisions.store(0, Ordering::Relaxed);
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

    #[test]
    fn test_metrics_recording() {
        let metrics = CacheMetrics::new();

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

    #[test]
    fn test_hit_rate() {
        let metrics = CacheMetrics::new();

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

    #[test]
    fn test_reset() {
        let metrics = CacheMetrics::new();

        metrics.record_hit();
        metrics.record_miss();
        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.hits, 0);
        assert_eq!(snapshot.misses, 0);
    }
}
