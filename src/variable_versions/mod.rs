pub mod data_number;
pub mod ipfix;
pub mod ipfix_lookup;
pub mod ttl;
pub mod v9;
pub mod v9_lookup;

use crate::variable_versions::ttl::{TtlConfig, TtlStrategy};
use std::num::NonZeroUsize;

pub struct Config {
    pub max_template_cache_size: usize,
    pub ttl_config: Option<TtlConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Template cache size must be greater than 0
    InvalidCacheSize(usize),
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
        }
    }
}

impl Config {
    pub fn new(max_template_cache_size: usize, ttl_config: Option<TtlConfig>) -> Self {
        Self {
            max_template_cache_size,
            ttl_config,
        }
    }
}

/// Trait for parsers that support template caching and TTL configuration
pub trait ParserConfig {
    /// Add or update the parser's configuration
    fn add_config(&mut self, config: Config) -> Result<(), ConfigError>;

    /// Set the maximum template cache size
    fn set_max_template_cache_size(&mut self, size: usize) -> Result<(), ConfigError>;

    /// Set the TTL strategy for templates
    fn set_ttl_strategy(&mut self, strategy: TtlStrategy) -> Result<(), ConfigError>;

    /// Internal helper: resize all template caches to the given size
    fn resize_template_caches(&mut self, cache_size: NonZeroUsize);
}
