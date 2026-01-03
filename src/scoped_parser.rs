//! Scoped parser for managing multiple NetFlow sources.
//!
//! This module provides a convenient wrapper for handling NetFlow data from multiple
//! sources (routers/exporters), ensuring template isolation per source.

use crate::{CacheStats, NetflowError, NetflowPacket, NetflowParser, NetflowParserBuilder};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;

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
    pub fn parse_from_source(
        &mut self,
        source: K,
        data: &[u8],
    ) -> Result<Vec<NetflowPacket>, NetflowError>
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

        parser.parse_bytes(data).into_result()
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
    ) -> impl Iterator<Item = Result<NetflowPacket, NetflowError>> + 'a
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

/// Information extracted from NetFlow packet headers for RFC-compliant scoping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopingInfo {
    /// NetFlow v9 packet with source ID
    V9 { source_id: u32 },
    /// IPFIX packet with observation domain ID
    IPFix { observation_domain_id: u32 },
    /// NetFlow v5 or v7 (no scoping ID in these versions)
    Legacy,
    /// Unable to determine version (invalid or truncated packet)
    Unknown,
}

/// RFC-compliant source key for IPFIX flows.
///
/// Combines the source address with the observation domain ID as specified in RFC 7011:
/// "Collecting Processes must use the Transport Session and Observation Domain ID field
/// to separate different export streams that originate from the same Exporting Process."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpfixSourceKey {
    /// Network address of the exporter
    pub addr: SocketAddr,
    /// Observation domain ID from IPFIX header
    pub observation_domain_id: u32,
}

/// RFC-compliant source key for NetFlow v9 flows.
///
/// Combines the source address with the source ID as specified in RFC 3954:
/// "Collector devices should use the combination of the source IP address plus the
/// Source ID field to associate an incoming NetFlow export packet with a unique
/// instance of NetFlow on a particular device."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct V9SourceKey {
    /// Network address of the exporter
    pub addr: SocketAddr,
    /// Source ID from NetFlow v9 header
    pub source_id: u32,
}

/// Extract scoping information from a NetFlow packet header without full parsing.
///
/// This function performs a lightweight parse of just the packet header to extract
/// the scoping identifiers needed for RFC-compliant template isolation.
///
/// # Arguments
///
/// * `data` - Raw NetFlow packet data
///
/// # Returns
///
/// Returns `ScopingInfo` indicating the packet type and scoping identifier, or
/// `Unknown` if the packet is too short or has an invalid version.
///
/// # Examples
///
/// ```
/// use netflow_parser::scoped_parser::{extract_scoping_info, ScopingInfo};
///
/// # let data = vec![0u8; 20];
/// match extract_scoping_info(&data) {
///     ScopingInfo::IPFix { observation_domain_id } => {
///         println!("IPFIX packet with domain ID: {}", observation_domain_id);
///     }
///     ScopingInfo::V9 { source_id } => {
///         println!("NetFlow v9 packet with source ID: {}", source_id);
///     }
///     ScopingInfo::Legacy => {
///         println!("NetFlow v5 or v7 (no scoping ID)");
///     }
///     ScopingInfo::Unknown => {
///         println!("Invalid or truncated packet");
///     }
/// }
/// ```
pub fn extract_scoping_info(data: &[u8]) -> ScopingInfo {
    if data.len() < 2 {
        return ScopingInfo::Unknown;
    }

    // Version is first 2 bytes (big-endian)
    let version = u16::from_be_bytes([data[0], data[1]]);

    match version {
        5 | 7 => ScopingInfo::Legacy,
        9 => {
            // NetFlow v9 header is 20 bytes
            // source_id is at offset 16-19
            if data.len() < 20 {
                return ScopingInfo::Unknown;
            }
            let source_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            ScopingInfo::V9 { source_id }
        }
        10 => {
            // IPFIX header is 16 bytes
            // observation_domain_id is at offset 12-15
            if data.len() < 16 {
                return ScopingInfo::Unknown;
            }
            let observation_domain_id =
                u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            ScopingInfo::IPFix {
                observation_domain_id,
            }
        }
        _ => ScopingInfo::Unknown,
    }
}

/// Automatically scoped parser that handles RFC-compliant template isolation.
///
/// This parser automatically extracts scoping identifiers from NetFlow packet headers
/// and maintains separate template caches per source according to RFC specifications:
///
/// - **NetFlow v9**: Uses `(source_addr, source_id)` per RFC 3954
/// - **IPFIX**: Uses `(source_addr, observation_domain_id)` per RFC 7011
/// - **NetFlow v5/v7**: Uses `source_addr` only (these versions have no scoping IDs)
///
/// This is the recommended parser for production deployments as it automatically handles
/// the complexity of RFC-compliant scoping without requiring manual key management.
///
/// # Examples
///
/// ```
/// use netflow_parser::scoped_parser::AutoScopedParser;
/// use std::net::SocketAddr;
///
/// let mut parser = AutoScopedParser::new();
///
/// let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();
/// # let data = vec![0u8; 100];
///
/// // Parser automatically uses RFC-compliant scoping
/// let packets = parser.parse_from_source(source, &data);
/// ```
///
/// ## Thread Safety
///
/// Like `NetflowParser`, `AutoScopedParser` is not thread-safe. Use external synchronization
/// (e.g., `Arc<Mutex<AutoScopedParser>>`) when sharing across threads.
#[derive(Debug)]
pub struct AutoScopedParser {
    /// Parsers for IPFIX sources (scoped by addr + observation_domain_id)
    ipfix_parsers: HashMap<IpfixSourceKey, NetflowParser>,
    /// Parsers for NetFlow v9 sources (scoped by addr + source_id)
    v9_parsers: HashMap<V9SourceKey, NetflowParser>,
    /// Parsers for legacy NetFlow v5/v7 (scoped by addr only)
    legacy_parsers: HashMap<SocketAddr, NetflowParser>,
    /// Optional builder for creating new parsers with custom configuration
    parser_builder: Option<NetflowParserBuilder>,
}

impl Default for AutoScopedParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoScopedParser {
    /// Create a new auto-scoped parser with default configuration.
    ///
    /// Each new source will get a parser with default settings.
    pub fn new() -> Self {
        Self {
            ipfix_parsers: HashMap::new(),
            v9_parsers: HashMap::new(),
            legacy_parsers: HashMap::new(),
            parser_builder: None,
        }
    }

    /// Create a new auto-scoped parser with a custom parser builder.
    ///
    /// The builder will be used to create new parser instances for each source.
    ///
    /// # Examples
    ///
    /// ```
    /// use netflow_parser::scoped_parser::AutoScopedParser;
    /// use netflow_parser::NetflowParser;
    /// use netflow_parser::variable_versions::ttl::TtlConfig;
    /// use std::time::Duration;
    ///
    /// let builder = NetflowParser::builder()
    ///     .with_cache_size(5000)
    ///     .with_ttl(TtlConfig::new(Duration::from_secs(3600)));
    ///
    /// let parser = AutoScopedParser::with_builder(builder);
    /// ```
    pub fn with_builder(builder: NetflowParserBuilder) -> Self {
        Self {
            ipfix_parsers: HashMap::new(),
            v9_parsers: HashMap::new(),
            legacy_parsers: HashMap::new(),
            parser_builder: Some(builder),
        }
    }

    /// Parse NetFlow data from a source with automatic RFC-compliant scoping.
    ///
    /// This method automatically:
    /// 1. Extracts the scoping identifier from the packet header
    /// 2. Routes to the appropriate scoped parser
    /// 3. Creates new parser instances as needed
    ///
    /// # Arguments
    ///
    /// * `source` - The network address of the exporter
    /// * `data` - The raw NetFlow packet data
    ///
    /// # Returns
    ///
    /// A vector of parsed NetFlow packets from the given data.
    ///
    /// # Examples
    ///
    /// ```
    /// use netflow_parser::scoped_parser::AutoScopedParser;
    /// use std::net::SocketAddr;
    ///
    /// let mut parser = AutoScopedParser::new();
    /// let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();
    /// # let data = vec![0u8; 100];
    ///
    /// let packets = parser.parse_from_source(source, &data);
    /// ```
    pub fn parse_from_source(
        &mut self,
        source: SocketAddr,
        data: &[u8],
    ) -> Result<Vec<NetflowPacket>, NetflowError> {
        match extract_scoping_info(data) {
            ScopingInfo::IPFix {
                observation_domain_id,
            } => {
                let key = IpfixSourceKey {
                    addr: source,
                    observation_domain_id,
                };
                let builder = self.parser_builder.clone();
                let parser = self
                    .ipfix_parsers
                    .entry(key)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.parse_bytes(data).into_result()
            }
            ScopingInfo::V9 { source_id } => {
                let key = V9SourceKey {
                    addr: source,
                    source_id,
                };
                let builder = self.parser_builder.clone();
                let parser = self
                    .v9_parsers
                    .entry(key)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.parse_bytes(data).into_result()
            }
            ScopingInfo::Legacy => {
                let builder = self.parser_builder.clone();
                let parser = self
                    .legacy_parsers
                    .entry(source)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.parse_bytes(data).into_result()
            }
            ScopingInfo::Unknown => {
                // Still try to parse, might succeed or return error
                let builder = self.parser_builder.clone();
                let parser = self
                    .legacy_parsers
                    .entry(source)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.parse_bytes(data).into_result()
            }
        }
    }

    /// Parse NetFlow data from a source using the iterator API.
    ///
    /// This is more efficient than `parse_from_source` when you don't need
    /// all packets in a Vec.
    ///
    /// # Arguments
    ///
    /// * `source` - The network address of the exporter
    /// * `data` - The raw NetFlow packet data
    ///
    /// # Returns
    ///
    /// An iterator over parsed NetFlow packets.
    pub fn iter_packets_from_source<'a>(
        &'a mut self,
        source: SocketAddr,
        data: &'a [u8],
    ) -> impl Iterator<Item = Result<NetflowPacket, NetflowError>> + 'a {
        match extract_scoping_info(data) {
            ScopingInfo::IPFix {
                observation_domain_id,
            } => {
                let key = IpfixSourceKey {
                    addr: source,
                    observation_domain_id,
                };
                let builder = self.parser_builder.clone();
                let parser = self
                    .ipfix_parsers
                    .entry(key)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.iter_packets(data)
            }
            ScopingInfo::V9 { source_id } => {
                let key = V9SourceKey {
                    addr: source,
                    source_id,
                };
                let builder = self.parser_builder.clone();
                let parser = self
                    .v9_parsers
                    .entry(key)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.iter_packets(data)
            }
            ScopingInfo::Legacy | ScopingInfo::Unknown => {
                let builder = self.parser_builder.clone();
                let parser = self
                    .legacy_parsers
                    .entry(source)
                    .or_insert_with(|| Self::build_parser(builder.as_ref()));
                parser.iter_packets(data)
            }
        }
    }

    /// Get the total number of registered sources across all scoping types.
    pub fn source_count(&self) -> usize {
        self.ipfix_parsers.len() + self.v9_parsers.len() + self.legacy_parsers.len()
    }

    /// Get the number of IPFIX sources.
    pub fn ipfix_source_count(&self) -> usize {
        self.ipfix_parsers.len()
    }

    /// Get the number of NetFlow v9 sources.
    pub fn v9_source_count(&self) -> usize {
        self.v9_parsers.len()
    }

    /// Get the number of legacy (v5/v7) sources.
    pub fn legacy_source_count(&self) -> usize {
        self.legacy_parsers.len()
    }

    /// Clear templates for all sources.
    pub fn clear_all_templates(&mut self) {
        for parser in self.ipfix_parsers.values_mut() {
            parser.clear_v9_templates();
            parser.clear_ipfix_templates();
        }
        for parser in self.v9_parsers.values_mut() {
            parser.clear_v9_templates();
            parser.clear_ipfix_templates();
        }
        for parser in self.legacy_parsers.values_mut() {
            parser.clear_v9_templates();
            parser.clear_ipfix_templates();
        }
    }

    /// Get statistics for all IPFIX sources.
    ///
    /// Returns a vector of tuples: (source_key, v9_stats, ipfix_stats)
    pub fn ipfix_stats(&self) -> Vec<(&IpfixSourceKey, CacheStats, CacheStats)> {
        self.ipfix_parsers
            .iter()
            .map(|(key, parser)| (key, parser.v9_cache_stats(), parser.ipfix_cache_stats()))
            .collect()
    }

    /// Get statistics for all NetFlow v9 sources.
    ///
    /// Returns a vector of tuples: (source_key, v9_stats, ipfix_stats)
    pub fn v9_stats(&self) -> Vec<(&V9SourceKey, CacheStats, CacheStats)> {
        self.v9_parsers
            .iter()
            .map(|(key, parser)| (key, parser.v9_cache_stats(), parser.ipfix_cache_stats()))
            .collect()
    }

    /// Get statistics for all legacy sources.
    ///
    /// Returns a vector of tuples: (addr, v9_stats, ipfix_stats)
    pub fn legacy_stats(&self) -> Vec<(&SocketAddr, CacheStats, CacheStats)> {
        self.legacy_parsers
            .iter()
            .map(|(addr, parser)| (addr, parser.v9_cache_stats(), parser.ipfix_cache_stats()))
            .collect()
    }

    /// Create a new parser instance using the configured builder or default
    fn build_parser(builder: Option<&NetflowParserBuilder>) -> NetflowParser {
        if let Some(builder) = builder {
            builder
                .clone()
                .build()
                .expect("Failed to build parser from builder")
        } else {
            NetflowParser::default()
        }
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

    #[test]
    fn test_extract_scoping_info_v9() {
        // NetFlow v9 packet with source_id = 0x12345678
        let mut data = vec![0u8; 20];
        data[0] = 0x00;
        data[1] = 0x09; // Version 9
        data[16] = 0x12;
        data[17] = 0x34;
        data[18] = 0x56;
        data[19] = 0x78; // source_id

        let info = extract_scoping_info(&data);
        assert_eq!(
            info,
            ScopingInfo::V9 {
                source_id: 0x12345678
            }
        );
    }

    #[test]
    fn test_extract_scoping_info_ipfix() {
        // IPFIX packet with observation_domain_id = 0xABCDEF01
        let mut data = vec![0u8; 16];
        data[0] = 0x00;
        data[1] = 0x0A; // Version 10 (IPFIX)
        data[12] = 0xAB;
        data[13] = 0xCD;
        data[14] = 0xEF;
        data[15] = 0x01; // observation_domain_id

        let info = extract_scoping_info(&data);
        assert_eq!(
            info,
            ScopingInfo::IPFix {
                observation_domain_id: 0xABCDEF01
            }
        );
    }

    #[test]
    fn test_extract_scoping_info_v5() {
        // NetFlow v5 packet
        let mut data = vec![0u8; 24];
        data[0] = 0x00;
        data[1] = 0x05; // Version 5

        let info = extract_scoping_info(&data);
        assert_eq!(info, ScopingInfo::Legacy);
    }

    #[test]
    fn test_extract_scoping_info_truncated() {
        // Truncated packet
        let data = vec![0x00, 0x09]; // Version 9 but too short

        let info = extract_scoping_info(&data);
        assert_eq!(info, ScopingInfo::Unknown);
    }

    #[test]
    fn test_extract_scoping_info_unknown_version() {
        // Unknown version
        let data = vec![0x00, 0xFF];

        let info = extract_scoping_info(&data);
        assert_eq!(info, ScopingInfo::Unknown);
    }

    #[test]
    fn test_auto_scoped_parser_basic() {
        let parser = AutoScopedParser::new();

        // Initially no sources
        assert_eq!(parser.source_count(), 0);
        assert_eq!(parser.ipfix_source_count(), 0);
        assert_eq!(parser.v9_source_count(), 0);
        assert_eq!(parser.legacy_source_count(), 0);
    }

    #[test]
    fn test_auto_scoped_parser_routes_correctly() {
        let mut parser = AutoScopedParser::new();
        let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

        // Parse V9 packet
        let mut v9_data = vec![0u8; 20];
        v9_data[0] = 0x00;
        v9_data[1] = 0x09; // Version 9
        v9_data[16] = 0x00;
        v9_data[17] = 0x00;
        v9_data[18] = 0x00;
        v9_data[19] = 0x01; // source_id = 1

        let _ = parser.parse_from_source(source, &v9_data);
        assert_eq!(parser.v9_source_count(), 1);
        assert_eq!(parser.ipfix_source_count(), 0);

        // Parse IPFIX packet from same address but different observation domain
        let mut ipfix_data = vec![0u8; 16];
        ipfix_data[0] = 0x00;
        ipfix_data[1] = 0x0A; // Version 10 (IPFIX)
        ipfix_data[12] = 0x00;
        ipfix_data[13] = 0x00;
        ipfix_data[14] = 0x00;
        ipfix_data[15] = 0x02; // observation_domain_id = 2

        let _ = parser.parse_from_source(source, &ipfix_data);
        assert_eq!(parser.v9_source_count(), 1);
        assert_eq!(parser.ipfix_source_count(), 1);
        assert_eq!(parser.source_count(), 2);
    }

    #[test]
    fn test_auto_scoped_parser_multiple_domains() {
        let mut parser = AutoScopedParser::new();
        let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

        // Parse IPFIX packets with different observation domains
        for domain_id in 1..=3 {
            let mut data = vec![0u8; 16];
            data[0] = 0x00;
            data[1] = 0x0A; // Version 10 (IPFIX)
            data[12] = 0x00;
            data[13] = 0x00;
            data[14] = 0x00;
            data[15] = domain_id;

            let _ = parser.parse_from_source(source, &data);
        }

        // Should have 3 separate IPFIX parsers (one per observation domain)
        assert_eq!(parser.ipfix_source_count(), 3);
    }

    #[test]
    fn test_auto_scoped_parser_stats() {
        let mut parser = AutoScopedParser::new();
        let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

        // Add IPFIX source
        let mut ipfix_data = vec![0u8; 16];
        ipfix_data[0] = 0x00;
        ipfix_data[1] = 0x0A;
        ipfix_data[15] = 0x01;
        let _ = parser.parse_from_source(source, &ipfix_data);

        // Get stats
        let ipfix_stats = parser.ipfix_stats();
        assert_eq!(ipfix_stats.len(), 1);
        assert_eq!(ipfix_stats[0].0.observation_domain_id, 1);
    }

    #[test]
    fn test_auto_scoped_parser_clear_all() {
        let mut parser = AutoScopedParser::new();
        let source: SocketAddr = "192.168.1.1:2055".parse().unwrap();

        // Add some sources
        let mut ipfix_data = vec![0u8; 16];
        ipfix_data[0] = 0x00;
        ipfix_data[1] = 0x0A;
        let _ = parser.parse_from_source(source, &ipfix_data);

        parser.clear_all_templates();
        // Should still have the parser instances
        assert_eq!(parser.ipfix_source_count(), 1);
    }
}
