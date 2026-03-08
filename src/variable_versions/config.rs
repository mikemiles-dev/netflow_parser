//! Parser configuration, traits, and constants for V9 and IPFIX parsers.

use super::pending_flows::{PendingFlowCache, PendingFlowsConfig};
use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::ttl::TtlConfig;
use std::num::NonZeroUsize;

/// Default maximum number of templates to cache per parser
pub const DEFAULT_MAX_TEMPLATE_CACHE_SIZE: usize = 1000;

pub(crate) type TemplateId = u16;

/// Default maximum number of fields allowed per template to prevent DoS attacks
/// A reasonable limit that should accommodate legitimate use cases
/// This can be configured per-parser via the Config struct
pub const MAX_FIELD_COUNT: u16 = 10000;

/// Configuration for V9 and IPFIX parsers.
///
/// Controls template cache size, field limits, TTL, enterprise field definitions,
/// and pending flow caching. Use [`Config::new`] for defaults or construct directly
/// for full control.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum number of templates to keep in the LRU cache.
    pub max_template_cache_size: usize,
    /// Maximum number of fields allowed per template. Default: 10,000.
    pub max_field_count: usize,
    /// Maximum total size (in bytes) of all fields in a template.
    /// This prevents DoS attacks via templates with excessive total field lengths.
    /// Default: u16::MAX
    pub max_template_total_size: usize,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
    /// Optional TTL configuration for template expiration.
    pub ttl_config: Option<TtlConfig>,
    /// Registry of custom enterprise-specific field definitions for IPFIX.
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
    /// Creates a new `Config` with the given cache size and optional TTL.
    /// Other fields use defaults (field count: 10,000, no enterprise registry, no pending flows).
    pub fn new(max_template_cache_size: usize, ttl_config: Option<TtlConfig>) -> Self {
        Self {
            max_template_cache_size,
            max_field_count: usize::from(MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config,
            enterprise_registry: EnterpriseFieldRegistry::new(),
            pending_flows_config: None,
        }
    }

    /// Creates a new `Config` with a custom enterprise field registry.
    /// Useful for IPFIX parsers that need to decode vendor-specific information elements.
    pub fn with_enterprise_registry(
        max_template_cache_size: usize,
        ttl_config: Option<TtlConfig>,
        enterprise_registry: EnterpriseFieldRegistry,
    ) -> Self {
        Self {
            max_template_cache_size,
            max_field_count: usize::from(MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config,
            enterprise_registry,
            pending_flows_config: None,
        }
    }
}

/// Internal accessor trait for shared parser fields.
///
/// Both V9Parser and IPFixParser share the same config/state fields. This trait
/// provides access so that `ParserConfig` can supply default implementations.
pub(crate) trait ParserFields {
    fn set_max_template_cache_size_field(&mut self, size: usize);
    fn set_max_field_count_field(&mut self, count: usize);
    fn set_max_template_total_size_field(&mut self, size: usize);
    fn set_max_error_sample_size_field(&mut self, size: usize);
    fn set_ttl_config_field(&mut self, config: Option<TtlConfig>);
    fn pending_flows(&self) -> &Option<PendingFlowCache>;
    fn pending_flows_mut(&mut self) -> &mut Option<PendingFlowCache>;
}

/// Trait for parsers that support template caching and TTL configuration
#[allow(private_bounds)]
pub trait ParserConfig: ParserFields {
    /// Internal helper: resize all template caches to the given size
    fn resize_template_caches(&mut self, cache_size: NonZeroUsize);

    /// Add or update the parser's configuration
    fn add_config(&mut self, config: Config) -> Result<(), ConfigError> {
        self.set_max_template_cache_size_field(config.max_template_cache_size);
        self.set_max_field_count_field(config.max_field_count);
        self.set_max_template_total_size_field(config.max_template_total_size);
        self.set_max_error_sample_size_field(config.max_error_sample_size);
        self.set_ttl_config_field(config.ttl_config);
        self.set_pending_flows_config(config.pending_flows_config)?;

        let cache_size = NonZeroUsize::new(config.max_template_cache_size).ok_or(
            ConfigError::InvalidCacheSize(config.max_template_cache_size),
        )?;

        self.resize_template_caches(cache_size);
        Ok(())
    }

    /// Set the maximum template cache size
    fn set_max_template_cache_size(&mut self, size: usize) -> Result<(), ConfigError> {
        let cache_size = NonZeroUsize::new(size).ok_or(ConfigError::InvalidCacheSize(size))?;
        self.set_max_template_cache_size_field(size);
        self.resize_template_caches(cache_size);
        Ok(())
    }

    /// Set the TTL configuration for templates
    fn set_ttl_config(&mut self, ttl_config: Option<TtlConfig>) -> Result<(), ConfigError> {
        self.set_ttl_config_field(ttl_config);
        Ok(())
    }

    /// Set the pending flows configuration
    ///
    /// # Errors
    /// Returns `ConfigError::InvalidPendingCacheSize` if `max_pending_flows` is 0.
    fn set_pending_flows_config(
        &mut self,
        config: Option<PendingFlowsConfig>,
    ) -> Result<(), ConfigError>;

    /// Returns whether pending flow caching is enabled.
    fn pending_flows_enabled(&self) -> bool {
        self.pending_flows().is_some()
    }

    /// Returns the total number of pending flow entries across all template IDs.
    fn pending_flow_count(&self) -> usize {
        self.pending_flows()
            .as_ref()
            .map(|cache| cache.count())
            .unwrap_or(0)
    }

    /// Clear all pending flows.
    fn clear_pending_flows(&mut self) {
        if let Some(cache) = self.pending_flows_mut() {
            cache.clear();
        }
    }
}
