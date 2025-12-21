use std::time::{Duration, Instant};

/// TTL (Time-to-Live) strategy for template expiration
#[derive(Debug, Clone)]
pub enum TtlStrategy {
    /// Evict templates after a duration (e.g., 2 hours)
    TimeBased { duration: Duration },

    /// Evict templates after N packets processed
    PacketBased { packet_interval: u64 },

    /// Evict based on either condition (whichever comes first)
    Combined {
        duration: Duration,
        packet_interval: u64,
    },
}

/// Configuration for template TTL
#[derive(Debug, Clone)]
pub struct TtlConfig {
    pub strategy: TtlStrategy,
}

impl TtlConfig {
    /// Create a time-based TTL configuration
    pub fn time_based(duration: Duration) -> Self {
        Self {
            strategy: TtlStrategy::TimeBased { duration },
        }
    }

    /// Create a packet-based TTL configuration
    pub fn packet_based(interval: u64) -> Self {
        Self {
            strategy: TtlStrategy::PacketBased {
                packet_interval: interval,
            },
        }
    }

    /// Create a combined TTL configuration (time OR packet-based, whichever expires first)
    pub fn combined(duration: Duration, interval: u64) -> Self {
        Self {
            strategy: TtlStrategy::Combined {
                duration,
                packet_interval: interval,
            },
        }
    }

    /// Default time-based configuration: 2 hours
    pub fn default_time_based() -> Self {
        Self::time_based(Duration::from_secs(2 * 60 * 60))
    }

    /// Default packet-based configuration: 100 packets
    pub fn default_packet_based() -> Self {
        Self::packet_based(100)
    }
}

/// Metadata for tracking template insertion time and packet count
#[derive(Debug, Clone)]
pub struct TemplateMetadata {
    pub inserted_at: Instant,
    pub packet_count_at_insert: u64,
}

impl TemplateMetadata {
    /// Create new metadata with current timestamp and packet count
    pub fn new(packet_count: u64) -> Self {
        Self {
            inserted_at: Instant::now(),
            packet_count_at_insert: packet_count,
        }
    }

    /// Check if this template has expired based on TTL configuration
    pub fn is_expired(&self, config: &TtlConfig, current_packet_count: u64) -> bool {
        match &config.strategy {
            TtlStrategy::TimeBased { duration } => self.inserted_at.elapsed() >= *duration,
            TtlStrategy::PacketBased { packet_interval } => {
                current_packet_count.saturating_sub(self.packet_count_at_insert)
                    >= *packet_interval
            }
            TtlStrategy::Combined {
                duration,
                packet_interval,
            } => {
                self.inserted_at.elapsed() >= *duration
                    || current_packet_count.saturating_sub(self.packet_count_at_insert)
                        >= *packet_interval
            }
        }
    }
}

/// Wrapper for templates with TTL metadata
#[derive(Debug, Clone)]
pub struct TemplateWithTtl<T> {
    pub template: T,
    pub metadata: TemplateMetadata,
}

impl<T> TemplateWithTtl<T> {
    /// Create a new template wrapper with current metadata
    pub fn new(template: T, packet_count: u64) -> Self {
        Self {
            template,
            metadata: TemplateMetadata::new(packet_count),
        }
    }

    /// Check if this template has expired based on TTL configuration
    pub fn is_expired(&self, config: &TtlConfig, current_packet_count: u64) -> bool {
        self.metadata.is_expired(config, current_packet_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_time_based_expiration() {
        let config = TtlConfig::time_based(Duration::from_millis(100));
        let metadata = TemplateMetadata::new(0);

        assert!(!metadata.is_expired(&config, 0));
        thread::sleep(Duration::from_millis(150));
        assert!(metadata.is_expired(&config, 0));
    }

    #[test]
    fn test_packet_based_expiration() {
        let config = TtlConfig::packet_based(10);
        let metadata = TemplateMetadata::new(5);

        assert!(!metadata.is_expired(&config, 10));
        assert!(!metadata.is_expired(&config, 14));
        assert!(metadata.is_expired(&config, 15));
        assert!(metadata.is_expired(&config, 20));
    }

    #[test]
    fn test_combined_expiration_packet_first() {
        let config = TtlConfig::combined(Duration::from_secs(3600), 10);
        let metadata = TemplateMetadata::new(0);

        // Should expire via packet count before time
        assert!(!metadata.is_expired(&config, 5));
        assert!(metadata.is_expired(&config, 10));
    }

    #[test]
    fn test_combined_expiration_time_first() {
        let config = TtlConfig::combined(Duration::from_millis(100), 1000);
        let metadata = TemplateMetadata::new(0);

        // Should expire via time before packet count
        assert!(!metadata.is_expired(&config, 5));
        thread::sleep(Duration::from_millis(150));
        assert!(metadata.is_expired(&config, 5));
    }

    #[test]
    fn test_template_with_ttl_wrapper() {
        let template = 42u32; // Mock template
        let wrapped = TemplateWithTtl::new(template, 0);

        assert_eq!(wrapped.template, 42);
        assert_eq!(wrapped.metadata.packet_count_at_insert, 0);

        let config = TtlConfig::packet_based(5);
        assert!(!wrapped.is_expired(&config, 4));
        assert!(wrapped.is_expired(&config, 5));
    }

    #[test]
    fn test_default_configs() {
        let time_config = TtlConfig::default_time_based();
        match time_config.strategy {
            TtlStrategy::TimeBased { duration } => {
                assert_eq!(duration, Duration::from_secs(2 * 60 * 60));
            }
            _ => panic!("Expected TimeBased strategy"),
        }

        let packet_config = TtlConfig::default_packet_based();
        match packet_config.strategy {
            TtlStrategy::PacketBased { packet_interval } => {
                assert_eq!(packet_interval, 100);
            }
            _ => panic!("Expected PacketBased strategy"),
        }
    }

    #[test]
    fn test_packet_count_overflow_protection() {
        let config = TtlConfig::packet_based(10);
        let metadata = TemplateMetadata::new(u64::MAX - 5);

        // Should use saturating_sub to prevent overflow
        // Only 5 packets have passed (u64::MAX - (u64::MAX - 5) = 5), so not expired yet
        assert!(!metadata.is_expired(&config, u64::MAX));

        // But should expire after 10+ packets total
        let metadata2 = TemplateMetadata::new(u64::MAX - 15);
        assert!(metadata2.is_expired(&config, u64::MAX));
    }
}
