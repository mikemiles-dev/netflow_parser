//! V9Parser — template-cached NetFlow V9 parser with pending flow support.
//!
//! Type definitions live in the parent `v9` module (`mod.rs`).

use super::{
    Data, FlowSet, FlowSetBody, FlowSetHeader, OptionsData, OptionsTemplate, Template,
    TemplateId, V9,
};
use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::metrics::CacheMetrics;
use crate::variable_versions::ttl::{TemplateWithTtl, TtlConfig};
use crate::variable_versions::{
    Config, ConfigError, ParserConfig, PendingFlowCache, PendingFlowEntry, PendingFlowsConfig,
};
use crate::{NetflowError, NetflowPacket, ParsedNetflow};

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;

use super::{DEFAULT_MAX_TEMPLATE_CACHE_SIZE, MAX_FIELD_COUNT};

#[derive(Debug)]
pub struct V9Parser {
    pub templates: LruCache<TemplateId, TemplateWithTtl<Arc<Template>>>,
    pub options_templates: LruCache<TemplateId, TemplateWithTtl<Arc<OptionsTemplate>>>,
    /// Optional TTL configuration for template expiration
    pub ttl_config: Option<TtlConfig>,
    /// Maximum number of templates to cache. Defaults to 1000.
    pub max_template_cache_size: usize,
    /// Maximum number of fields allowed per template. Defaults to 10000.
    pub max_field_count: usize,
    /// Maximum total size (in bytes) of all fields in a template. Defaults to u16::MAX.
    pub max_template_total_size: usize,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
    /// Registry of custom enterprise field definitions
    pub enterprise_registry: EnterpriseFieldRegistry,
    /// Cache performance metrics
    pub metrics: CacheMetrics,
    /// Pending flow cache for flows awaiting their template
    pub(crate) pending_flows: Option<PendingFlowCache>,
}

impl Default for V9Parser {
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

impl V9Parser {
    /// Create a new V9 with a custom template cache size and optional TTL configuration.
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
            options_templates: LruCache::new(cache_size),
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

impl ParserConfig for V9Parser {
    /// Add or update the parser's configuration.
    /// # Arguments
    /// * `config` - Configuration struct containing max_template_cache_size and optional ttl_config
    /// # Errors
    /// Returns `ConfigError` if `max_template_cache_size` is 0
    fn add_config(&mut self, config: Config) -> Result<(), ConfigError> {
        self.max_template_cache_size = config.max_template_cache_size;
        self.max_field_count = config.max_field_count;
        self.max_template_total_size = config.max_template_total_size;
        self.max_error_sample_size = config.max_error_sample_size;
        self.ttl_config = config.ttl_config;
        self.set_pending_flows_config(config.pending_flows_config)?;

        let cache_size = NonZeroUsize::new(config.max_template_cache_size).ok_or(
            ConfigError::InvalidCacheSize(config.max_template_cache_size),
        )?;

        self.resize_template_caches(cache_size);
        Ok(())
    }

    fn set_max_template_cache_size(&mut self, size: usize) -> Result<(), ConfigError> {
        let cache_size = NonZeroUsize::new(size).ok_or(ConfigError::InvalidCacheSize(size))?;
        self.max_template_cache_size = size;
        self.resize_template_caches(cache_size);
        Ok(())
    }

    fn set_ttl_config(&mut self, ttl_config: Option<TtlConfig>) -> Result<(), ConfigError> {
        self.ttl_config = ttl_config;
        Ok(())
    }

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
        self.options_templates.resize(cache_size);
    }
}

impl V9Parser {
    pub fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match V9::parse(packet, self) {
            Ok((remaining, mut v9)) => {
                self.process_pending_flows(&mut v9);
                ParsedNetflow::Success {
                    packet: NetflowPacket::V9(v9),
                    remaining,
                }
            }
            Err(e) => ParsedNetflow::Error {
                error: NetflowError::Partial {
                    message: format!("V9 parse error: {}", e),
                },
            },
        }
    }

    fn process_pending_flows(&mut self, v9: &mut V9) {
        let Some(mut pending_cache) = self.pending_flows.take() else {
            return;
        };
        let learned = Self::cache_notemplate_v9_flowsets(
            v9,
            &mut pending_cache,
            &mut self.metrics,
            self.max_error_sample_size,
        );
        self.replay_v9_pending_flows(v9, &mut pending_cache, &learned);
        self.pending_flows = Some(pending_cache);
    }

    /// Single pass: cache NoTemplate raw data, collect learned template IDs,
    /// and remove successfully-cached flowsets from the output.
    fn cache_notemplate_v9_flowsets(
        v9: &mut V9,
        cache: &mut PendingFlowCache,
        metrics: &mut CacheMetrics,
        max_error_sample_size: usize,
    ) -> Vec<u16> {
        let mut learned_template_ids: Vec<u16> = Vec::new();
        let mut remove_mask: Vec<bool> = vec![false; v9.flowsets.len()];
        for (i, flowset) in v9.flowsets.iter_mut().enumerate() {
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
                FlowSetBody::Template(templates) => {
                    for t in &templates.templates {
                        learned_template_ids.push(t.template_id);
                    }
                }
                FlowSetBody::OptionsTemplate(templates) => {
                    for t in &templates.templates {
                        learned_template_ids.push(t.template_id);
                    }
                }
                _ => {}
            }
        }
        let mut mask_iter = remove_mask.into_iter();
        v9.flowsets.retain(|_| !mask_iter.next().unwrap_or(false));
        learned_template_ids
    }

    /// Replay pending flows for each newly learned template.
    fn replay_v9_pending_flows(
        &mut self,
        v9: &mut V9,
        cache: &mut PendingFlowCache,
        learned: &[u16],
    ) {
        for &template_id in learned {
            for entry in cache.drain(template_id, &mut self.metrics) {
                if v9.flowsets.len() >= u16::MAX as usize {
                    self.metrics.record_pending_replay_failed();
                    continue;
                }
                if self.try_replay_v9_flow(&mut v9.flowsets, template_id, &entry) {
                    self.metrics.record_pending_replayed();
                } else {
                    self.metrics.record_pending_replay_failed();
                }
            }
        }
        v9.header.count = u16::try_from(v9.flowsets.len()).unwrap_or(u16::MAX);
    }

    /// Try to replay a pending flow entry using available templates.
    fn try_replay_v9_flow(
        &mut self,
        flowsets: &mut Vec<FlowSet>,
        template_id: u16,
        entry: &PendingFlowEntry,
    ) -> bool {
        // Try regular template
        if let Some(template) = V9Parser::get_valid_template(
            &mut self.templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = Data::parse(&entry.raw_data, &template)
        {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    flowset_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::Data(data),
            });
            return true;
        }
        // Try options template
        if let Some(template) = V9Parser::get_valid_template(
            &mut self.options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, options_data)) = OptionsData::parse(&entry.raw_data, &template)
        {
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    flowset_id: template_id,
                    length: u16::try_from(entry.raw_data.len())
                        .unwrap_or(u16::MAX)
                        .saturating_add(4),
                },
                body: FlowSetBody::OptionsData(options_data),
            });
            return true;
        }
        false
    }

    /// Returns whether pending flow caching is enabled.
    pub fn pending_flows_enabled(&self) -> bool {
        self.pending_flows.is_some()
    }

    /// Returns the total number of pending flow entries across all template IDs.
    pub fn pending_flow_count(&self) -> usize {
        self.pending_flows
            .as_ref()
            .map(|cache| cache.count())
            .unwrap_or(0)
    }

    /// Clear all pending flows.
    pub fn clear_pending_flows(&mut self) {
        if let Some(ref mut cache) = self.pending_flows {
            cache.clear();
        }
    }

    /// Returns a sorted, deduplicated list of all available template IDs.
    pub fn available_template_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self
            .templates
            .iter()
            .map(|(&id, _)| id)
            .chain(self.options_templates.iter().map(|(&id, _)| id))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Helper method to get a valid template from cache, checking TTL if configured.
    /// Returns None if template doesn't exist or has expired.
    #[inline]
    pub(crate) fn get_valid_template<T: Clone>(
        cache: &mut LruCache<TemplateId, TemplateWithTtl<Arc<T>>>,
        id: &TemplateId,
        ttl_config: &Option<TtlConfig>,
        metrics: &mut CacheMetrics,
    ) -> Option<Arc<T>> {
        if let Some(wrapped) = cache.get(id) {
            metrics.record_hit();
            if let Some(config) = ttl_config
                && wrapped.is_expired(config)
            {
                cache.pop(id);
                metrics.record_expiration();
                return None;
            }
            return Some(Arc::clone(&wrapped.template));
        }
        None
    }
}
