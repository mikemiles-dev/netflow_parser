use std::time::{Duration, Instant};

/// Configuration for template TTL (Time-to-Live)
#[derive(Debug, Clone)]
pub struct TtlConfig {
    pub duration: Duration,
}

impl TtlConfig {
    /// Create a new TTL configuration with the specified duration
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }
}

impl Default for TtlConfig {
    /// Default TTL configuration: 2 hours
    fn default() -> Self {
        Self::new(Duration::from_secs(2 * 60 * 60))
    }
}

/// Metadata for tracking template insertion time
#[derive(Debug, Clone)]
pub struct TemplateMetadata {
    pub inserted_at: Instant,
}

impl TemplateMetadata {
    /// Create new metadata with current timestamp
    pub fn new() -> Self {
        Self {
            inserted_at: Instant::now(),
        }
    }

    /// Check if this template has expired based on TTL configuration
    pub fn is_expired(&self, config: &TtlConfig) -> bool {
        self.inserted_at.elapsed() >= config.duration
    }
}

impl Default for TemplateMetadata {
    fn default() -> Self {
        Self::new()
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
    pub fn new(template: T) -> Self {
        Self {
            template,
            metadata: TemplateMetadata::new(),
        }
    }

    /// Check if this template has expired based on TTL configuration
    pub fn is_expired(&self, config: &TtlConfig) -> bool {
        self.metadata.is_expired(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_time_based_expiration() {
        let config = TtlConfig::new(Duration::from_millis(100));
        let metadata = TemplateMetadata::new();

        assert!(!metadata.is_expired(&config));
        thread::sleep(Duration::from_millis(150));
        assert!(metadata.is_expired(&config));
    }

    #[test]
    fn test_template_with_ttl_wrapper() {
        let template = 42u32; // Mock template
        let wrapped = TemplateWithTtl::new(template);

        assert_eq!(wrapped.template, 42);

        let config = TtlConfig::new(Duration::from_millis(100));
        assert!(!wrapped.is_expired(&config));
        thread::sleep(Duration::from_millis(150));
        assert!(wrapped.is_expired(&config));
    }

    #[test]
    fn test_default_config() {
        let config = TtlConfig::default();
        assert_eq!(config.duration, Duration::from_secs(2 * 60 * 60));
    }
}
