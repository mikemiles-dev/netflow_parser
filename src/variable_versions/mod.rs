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
use crate::variable_versions::ttl::TtlConfig;
use std::num::NonZeroUsize;

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
            max_field_count: usize::from(ipfix::MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config,
            enterprise_registry: EnterpriseFieldRegistry::new(),
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

    /// Internal helper: resize all template caches to the given size
    fn resize_template_caches(&mut self, cache_size: NonZeroUsize);
}
