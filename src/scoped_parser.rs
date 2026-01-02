//! Scoped parser for managing multiple NetFlow sources.
//!
//! This module provides a convenient wrapper for handling NetFlow data from multiple
//! sources (routers/exporters), ensuring template isolation per source.

use crate::{CacheStats, NetflowPacket, NetflowParser, NetflowParserBuilder};
use std::collections::HashMap;
use std::hash::Hash;

/// A parser that maintains separate template caches for each NetFlow source.
///
/// This is the recommended pattern for multi-source deployments where different
/// routers may use the same template IDs for different field definitions. By keeping
/// separate parser instances per source, templates are properly isolated.
///
/// # Type Parameter
///
/// * `K` - The key type used to identify sources. Commonly `SocketAddr` for UDP sources,
///   but can be any hashable type (e.g., `String` for named sources, `u32` for
///   observation domain IDs, etc.)
///
/// # Examples
///
/// ## Basic usage with SocketAddr
///
/// ```rust
/// use netflow_parser::RouterScopedParser;
/// use std::net::SocketAddr;
///
/// let mut scoped_parser = RouterScopedParser::<SocketAddr>::new();
///
/// // Parse packet from source 1
/// let source1 = "192.168.1.1:2055".parse().unwrap();
/// let data1 = vec![/* netflow data */];
/// let packets = scoped_parser.parse_from_source(source1, &data1);
///
/// // Parse packet from source 2 (separate template cache)
/// let source2 = "192.168.1.2:2055".parse().unwrap();
/// let data2 = vec![/* netflow data */];
/// let packets = scoped_parser.parse_from_source(source2, &data2);
/// ```
///
/// ## Custom source keys
///
/// ```rust
/// use netflow_parser::RouterScopedParser;
///
/// // Use string identifiers for sources
/// let mut scoped_parser = RouterScopedParser::<String>::new();
///
/// # let data = vec![0u8; 100];
/// let packets = scoped_parser.parse_from_source(
///     "router-nyc-01".to_string(),
///     &data
/// );
/// ```
#[derive(Debug)]
pub struct RouterScopedParser<K: Hash + Eq> {
    /// Map from source identifier to parser instance
    parsers: HashMap<K, NetflowParser>,
    /// Optional builder for creating new parsers with custom configuration
    parser_builder: Option<NetflowParserBuilder>,
}

impl<K: Hash + Eq> Default for RouterScopedParser<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq> RouterScopedParser<K> {
    /// Create a new scoped parser with default configuration.
    ///
    /// Each new source will get a parser with default settings.
    pub fn new() -> Self {
        Self {
            parsers: HashMap::new(),
            parser_builder: None,
        }
    }

    /// Create a new scoped parser with a custom parser builder.
    ///
    /// The builder will be used to create new parser instances for each source.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::{RouterScopedParser, NetflowParser};
    /// use netflow_parser::variable_versions::ttl::TtlConfig;
    /// use std::time::Duration;
    /// use std::net::SocketAddr;
    ///
    /// let builder = NetflowParser::builder()
    ///     .with_cache_size(5000)
    ///     .with_ttl(TtlConfig::new(Duration::from_secs(3600)));
    ///
    /// let scoped_parser = RouterScopedParser::<SocketAddr>::with_builder(builder);
    /// ```
    pub fn with_builder(builder: NetflowParserBuilder) -> Self {
        Self {
            parsers: HashMap::new(),
            parser_builder: Some(builder),
        }
    }

    /// Parse NetFlow data from a specific source.
    ///
    /// This will automatically create a new parser instance for new sources,
    /// or reuse the existing parser for known sources.
    ///
    /// # Arguments
    ///
    /// * `source` - The source identifier (e.g., SocketAddr)
    /// * `data` - The raw NetFlow packet data
    ///
    /// # Returns
    ///
    /// A vector of parsed NetFlow packets from the given data.
    pub fn parse_from_source(&mut self, source: K, data: &[u8]) -> Vec<NetflowPacket>
    where
        K: Clone,
    {
        let parser = self.parsers.entry(source).or_insert_with(|| {
            if let Some(ref builder) = self.parser_builder {
                builder
                    .clone()
                    .build()
                    .expect("Failed to build parser from builder")
            } else {
                NetflowParser::default()
            }
        });

        parser.parse_bytes(data)
    }

    /// Parse NetFlow data from a source using the iterator API.
    ///
    /// This is more efficient than `parse_from_source` when you don't need
    /// all packets in a Vec.
    ///
    /// # Arguments
    ///
    /// * `source` - The source identifier
    /// * `data` - The raw NetFlow packet data
    ///
    /// # Returns
    ///
    /// An iterator over parsed NetFlow packets.
    pub fn iter_packets_from_source<'a>(
        &'a mut self,
        source: K,
        data: &'a [u8],
    ) -> impl Iterator<Item = NetflowPacket> + 'a
    where
        K: Clone,
    {
        let parser = self.parsers.entry(source).or_insert_with(|| {
            if let Some(ref builder) = self.parser_builder {
                builder
                    .clone()
                    .build()
                    .expect("Failed to build parser from builder")
            } else {
                NetflowParser::default()
            }
        });

        parser.iter_packets(data)
    }

    /// Get statistics for a specific source's template cache.
    ///
    /// Returns `None` if the source hasn't sent any packets yet.
    pub fn get_source_stats(&self, source: &K) -> Option<(CacheStats, CacheStats)> {
        self.parsers
            .get(source)
            .map(|parser| (parser.v9_cache_stats(), parser.ipfix_cache_stats()))
    }

    /// Get the number of registered sources.
    pub fn source_count(&self) -> usize {
        self.parsers.len()
    }

    /// List all registered source identifiers.
    pub fn sources(&self) -> Vec<&K> {
        self.parsers.keys().collect()
    }

    /// Get statistics for all sources.
    ///
    /// Returns a vector of tuples: (source, v9_stats, ipfix_stats)
    pub fn all_stats(&self) -> Vec<(&K, CacheStats, CacheStats)>
    where
        K: Clone,
    {
        self.parsers
            .iter()
            .map(|(source, parser)| {
                (source, parser.v9_cache_stats(), parser.ipfix_cache_stats())
            })
            .collect()
    }

    /// Clear templates for a specific source.
    ///
    /// This is useful for testing or when you need to force template re-learning
    /// for a specific source.
    pub fn clear_source_templates(&mut self, source: &K) {
        if let Some(parser) = self.parsers.get_mut(source) {
            parser.clear_v9_templates();
            parser.clear_ipfix_templates();
        }
    }

    /// Clear templates for all sources.
    pub fn clear_all_templates(&mut self) {
        for parser in self.parsers.values_mut() {
            parser.clear_v9_templates();
            parser.clear_ipfix_templates();
        }
    }

    /// Remove a source and its parser.
    ///
    /// This is useful for cleaning up parsers for sources that are no longer active.
    pub fn remove_source(&mut self, source: &K) -> Option<NetflowParser> {
        self.parsers.remove(source)
    }

    /// Get a reference to a specific source's parser.
    ///
    /// Returns `None` if the source hasn't sent any packets yet.
    pub fn get_parser(&self, source: &K) -> Option<&NetflowParser> {
        self.parsers.get(source)
    }

    /// Get a mutable reference to a specific source's parser.
    ///
    /// Returns `None` if the source hasn't sent any packets yet.
    pub fn get_parser_mut(&mut self, source: &K) -> Option<&mut NetflowParser> {
        self.parsers.get_mut(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_scoped_parser_basic() {
        let mut scoped = RouterScopedParser::<SocketAddr>::new();

        // Initially no sources
        assert_eq!(scoped.source_count(), 0);

        // Parse from first source
        let source1: SocketAddr = "192.168.1.1:2055".parse().unwrap();
        let data = vec![0u8; 100];
        let _ = scoped.parse_from_source(source1, &data);

        // Now we have one source
        assert_eq!(scoped.source_count(), 1);
        assert!(scoped.get_source_stats(&source1).is_some());

        // Parse from second source
        let source2: SocketAddr = "192.168.1.2:2055".parse().unwrap();
        let _ = scoped.parse_from_source(source2, &data);

        // Now we have two sources
        assert_eq!(scoped.source_count(), 2);
        assert!(scoped.get_source_stats(&source2).is_some());
    }

    #[test]
    fn test_scoped_parser_with_string_keys() {
        let mut scoped = RouterScopedParser::<String>::new();

        let router1 = "router-nyc-01".to_string();
        let router2 = "router-sfo-02".to_string();

        let data = vec![0u8; 100];
        let _ = scoped.parse_from_source(router1.clone(), &data);
        let _ = scoped.parse_from_source(router2.clone(), &data);

        assert_eq!(scoped.source_count(), 2);
        assert!(scoped.sources().contains(&&router1));
        assert!(scoped.sources().contains(&&router2));
    }

    #[test]
    fn test_remove_source() {
        let mut scoped = RouterScopedParser::<String>::new();

        let router = "router-1".to_string();
        let data = vec![0u8; 100];
        let _ = scoped.parse_from_source(router.clone(), &data);

        assert_eq!(scoped.source_count(), 1);

        scoped.remove_source(&router);
        assert_eq!(scoped.source_count(), 0);
    }

    #[test]
    fn test_clear_templates() {
        let mut scoped = RouterScopedParser::<String>::new();

        let router = "router-1".to_string();
        let data = vec![0u8; 100];
        let _ = scoped.parse_from_source(router.clone(), &data);

        scoped.clear_source_templates(&router);
        scoped.clear_all_templates();
    }
}
