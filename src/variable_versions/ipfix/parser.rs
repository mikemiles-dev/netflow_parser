//! IPFixParser — template-cached IPFIX parser with pending flow support.
//!
//! Type definitions live in the parent `ipfix` module (`mod.rs`).

use super::{Data, FlowSet, FlowSetBody, FlowSetHeader, IPFix, IPFixParser, OptionsData};
use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::metrics::CacheMetrics;
use crate::variable_versions::ttl::TtlConfig;
use crate::variable_versions::v9::{Data as V9Data, OptionsData as V9OptionsData};
use crate::variable_versions::{
    Config, ConfigError, ParserConfig, ParserFields, PendingFlowCache, PendingFlowEntry,
    PendingFlowsConfig,
};
use crate::{NetflowError, NetflowPacket, ParsedNetflow};

use lru::LruCache;
use std::num::NonZeroUsize;

use super::{DEFAULT_MAX_TEMPLATE_CACHE_SIZE, MAX_FIELD_COUNT};

impl Default for IPFixParser {
    fn default() -> Self {
        // Safe to unwrap because DEFAULT_MAX_TEMPLATE_CACHE_SIZE is non-zero
        let config = Config {
            max_template_cache_size: DEFAULT_MAX_TEMPLATE_CACHE_SIZE,
            max_field_count: usize::from(MAX_FIELD_COUNT),
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
            pending_flows_config: None,
        };

        Self::try_new(config).unwrap()
    }
}

impl IPFixParser {
    /// Create a new IPFixParser with a custom template cache size and optional TTL configuration.
    ///
    /// # Arguments
    /// * `config` - Configuration struct containing max_template_cache_size and optional ttl_config
    ///
    /// # Errors
    /// Returns `ConfigError` if `max_template_cache_size` is 0
    pub fn try_new(config: Config) -> Result<Self, ConfigError> {
        let cache_size = NonZeroUsize::new(config.max_template_cache_size).ok_or(
            ConfigError::InvalidCacheSize(config.max_template_cache_size),
        )?;

        let pending_flows = config
            .pending_flows_config
            .map(PendingFlowCache::new)
            .transpose()?;

        Ok(Self {
            templates: LruCache::new(cache_size),
            v9_templates: LruCache::new(cache_size),
            ipfix_options_templates: LruCache::new(cache_size),
            v9_options_templates: LruCache::new(cache_size),
            ttl_config: config.ttl_config,
            max_template_cache_size: config.max_template_cache_size,
            max_field_count: config.max_field_count,
            max_template_total_size: config.max_template_total_size,
            max_error_sample_size: config.max_error_sample_size,
            enterprise_registry: config.enterprise_registry,
            metrics: CacheMetrics::new(),
            pending_flows,
        })
    }
}

impl ParserFields for IPFixParser {
    fn set_max_template_cache_size_field(&mut self, size: usize) {
        self.max_template_cache_size = size;
    }
    fn set_max_field_count_field(&mut self, count: usize) {
        self.max_field_count = count;
    }
    fn set_max_template_total_size_field(&mut self, size: usize) {
        self.max_template_total_size = size;
    }
    fn set_max_error_sample_size_field(&mut self, size: usize) {
        self.max_error_sample_size = size;
    }
    fn set_ttl_config_field(&mut self, config: Option<TtlConfig>) {
        self.ttl_config = config;
    }
    fn pending_flows(&self) -> &Option<PendingFlowCache> {
        &self.pending_flows
    }
    fn pending_flows_mut(&mut self) -> &mut Option<PendingFlowCache> {
        &mut self.pending_flows
    }
}

impl ParserConfig for IPFixParser {
    fn set_pending_flows_config(
        &mut self,
        config: Option<PendingFlowsConfig>,
    ) -> Result<(), ConfigError> {
        match config {
            Some(pf_config) => {
                if let Some(ref mut cache) = self.pending_flows {
                    cache.resize(pf_config, &mut self.metrics)?;
                } else {
                    self.pending_flows = Some(PendingFlowCache::new(pf_config)?);
                }
            }
            None => {
                self.pending_flows = None;
            }
        }
        Ok(())
    }

    fn resize_template_caches(&mut self, cache_size: NonZeroUsize) {
        self.templates.resize(cache_size);
        self.v9_templates.resize(cache_size);
        self.ipfix_options_templates.resize(cache_size);
        self.v9_options_templates.resize(cache_size);
    }
}

impl IPFixParser {
    /// Parse an IPFIX message from raw bytes, using cached templates to decode data records.
    pub fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match IPFix::parse(packet, self) {
            Ok((remaining, mut ipfix)) => {
                self.process_pending_flows(&mut ipfix);
                ParsedNetflow::Success {
                    packet: NetflowPacket::IPFix(ipfix),
                    remaining,
                }
            }
            Err(e) => ParsedNetflow::Error {
                error: NetflowError::Partial {
                    message: format!("IPFIX parse error: {}", e),
                },
            },
        }
    }

    fn process_pending_flows(&mut self, ipfix: &mut IPFix) {
        let Some(mut pending_cache) = self.pending_flows.take() else {
            return;
        };
        let learned = Self::cache_notemplate_ipfix_flowsets(
            ipfix,
            &mut pending_cache,
            &mut self.metrics,
            self.max_error_sample_size,
        );
        self.replay_ipfix_pending_flows(ipfix, &mut pending_cache, &learned);
        self.pending_flows = Some(pending_cache);
    }

    /// Single pass: cache NoTemplate raw data, collect learned template IDs,
    /// remove successfully-cached flowsets, and adjust header.length.
    fn cache_notemplate_ipfix_flowsets(
        ipfix: &mut IPFix,
        cache: &mut PendingFlowCache,
        metrics: &mut CacheMetrics,
        max_error_sample_size: usize,
    ) -> Vec<u16> {
        let mut learned_template_ids: Vec<u16> = Vec::new();
        let mut remove_mask: Vec<bool> = vec![false; ipfix.flowsets.len()];
        for (i, flowset) in ipfix.flowsets.iter_mut().enumerate() {
            match &mut flowset.body {
                FlowSetBody::NoTemplate(info) => {
                    // If raw_data was truncated at parse time (oversized
                    // entry), skip caching — the data can't be replayed.
                    let body_len = (flowset.header.length as usize).saturating_sub(4);
                    if info.raw_data.len() < body_len {
                        metrics.record_pending_dropped();
                        continue;
                    }
                    let raw_data = std::mem::take(&mut info.raw_data);
                    if let Some(mut returned) = cache.cache(info.template_id, raw_data, metrics)
                    {
                        // Truncate rejected data to diagnostic size so
                        // callers don't hold the full (potentially large)
                        // buffer that was not cached.
                        returned.truncate(max_error_sample_size);
                        info.raw_data = returned;
                    } else {
                        remove_mask[i] = true;
                    }
                }
                FlowSetBody::Template(t) => {
                    learned_template_ids.push(t.template_id);
                }
                FlowSetBody::Templates(ts) => {
                    for t in ts.iter() {
                        learned_template_ids.push(t.template_id);
                    }
                }
                FlowSetBody::V9Template(t) => {
                    learned_template_ids.push(t.template_id);
                }
                FlowSetBody::V9Templates(ts) => {
                    for t in ts.iter() {
                        learned_template_ids.push(t.template_id);
                    }
                }
                FlowSetBody::OptionsTemplate(t) => {
                    learned_template_ids.push(t.template_id);
                }
                FlowSetBody::OptionsTemplates(ts) => {
                    for t in ts.iter() {
                        learned_template_ids.push(t.template_id);
                    }
                }
                FlowSetBody::V9OptionsTemplate(t) => {
                    learned_template_ids.push(t.template_id);
                }
                FlowSetBody::V9OptionsTemplates(ts) => {
                    for t in ts.iter() {
                        learned_template_ids.push(t.template_id);
                    }
                }
                _ => {}
            }
        }
        // Subtract lengths of cached flowsets from header, then remove them.
        for (i, fs) in ipfix.flowsets.iter().enumerate() {
            if remove_mask[i] {
                ipfix.header.length = ipfix.header.length.saturating_sub(fs.header.length);
            }
        }
        let mut mask_iter = remove_mask.into_iter();
        ipfix
            .flowsets
            .retain(|_| !mask_iter.next().unwrap_or(false));
        learned_template_ids
    }

    /// Replay pending flows for each newly learned template.
    fn replay_ipfix_pending_flows(
        &mut self,
        ipfix: &mut IPFix,
        cache: &mut PendingFlowCache,
        learned: &[u16],
    ) {
        for &template_id in learned {
            for entry in cache.drain(template_id, &mut self.metrics) {
                let flowset_length =
                    u16::try_from(entry.raw_data.len().saturating_add(4)).unwrap_or(u16::MAX);
                let Some(new_header_length) = ipfix.header.length.checked_add(flowset_length)
                else {
                    self.metrics.record_pending_replay_failed();
                    continue;
                };
                if self.try_replay_ipfix_flow(&mut ipfix.flowsets, template_id, &entry) {
                    self.metrics.record_pending_replayed();
                    ipfix.header.length = new_header_length;
                } else {
                    self.metrics.record_pending_replay_failed();
                }
            }
        }
    }

    /// Try to replay a pending flow entry using available templates.
    fn try_replay_ipfix_flow(
        &mut self,
        flowsets: &mut Vec<FlowSet>,
        template_id: u16,
        entry: &PendingFlowEntry,
    ) -> bool {
        // Try IPFIX templates
        if let Some(template) = crate::variable_versions::get_valid_template(
            &mut self.templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) =
            Data::parse_with_registry(&entry.raw_data, &template, &self.enterprise_registry)
        {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::Data(data),
            });
            return true;
        }

        // Try IPFIX options templates
        if let Some(template) = crate::variable_versions::get_valid_template(
            &mut self.ipfix_options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = OptionsData::parse_with_registry(
            &entry.raw_data,
            &template,
            &self.enterprise_registry,
        ) {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::OptionsData(data),
            });
            return true;
        }

        // Try V9 templates
        if let Some(template) = crate::variable_versions::get_valid_template(
            &mut self.v9_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = V9Data::parse(&entry.raw_data, &template)
        {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::V9Data(data),
            });
            return true;
        }

        // Try V9 options templates
        if let Some(template) = crate::variable_versions::get_valid_template(
            &mut self.v9_options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = V9OptionsData::parse(&entry.raw_data, &template)
        {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::V9OptionsData(data),
            });
            return true;
        }

        false
    }

    /// Returns a sorted, deduplicated list of all available template IDs.
    pub fn available_template_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self
            .templates
            .iter()
            .map(|(&id, _)| id)
            .chain(self.v9_templates.iter().map(|(&id, _)| id))
            .chain(self.ipfix_options_templates.iter().map(|(&id, _)| id))
            .chain(self.v9_options_templates.iter().map(|(&id, _)| id))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}
