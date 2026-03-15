//! IPFixParser — template-cached IPFIX parser with pending flow support.
//!
//! Type definitions live in the parent `ipfix` module (`mod.rs`).
//! Parsing impl blocks for IPFIX types (FlowSetBody, FieldParser, TemplateField, etc.)
//! are also defined here.

use super::{
    CommonTemplate, DATA_TEMPLATE_IPFIX_ID, DEFAULT_MAX_TEMPLATE_CACHE_SIZE, Data, FieldParser,
    FlowSet, FlowSetBody, FlowSetHeader, IPFix, IPFixFieldPair, IPFixParser, MAX_FIELD_COUNT,
    NoTemplateInfo, OPTIONS_TEMPLATE_IPFIX_ID, OptionsData, OptionsTemplate, Template,
    TemplateField,
};
use crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET;
use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::field_value::FieldValue;
use crate::variable_versions::metrics::CacheMetrics;
use crate::variable_versions::ttl::{TemplateWithTtl, TtlConfig};
use crate::variable_versions::v9::{
    DATA_TEMPLATE_V9_ID, Data as V9Data, OPTIONS_TEMPLATE_V9_ID, OptionsData as V9OptionsData,
    OptionsTemplate as V9OptionsTemplate, Template as V9Template,
};
use crate::variable_versions::{
    Config, ConfigError, ParserConfig, ParserFields, PendingFlowCache, PendingFlowEntry,
    PendingFlowsConfig,
};
use crate::{NetflowError, NetflowPacket, ParsedNetflow};

use lru::LruCache;
use nom::IResult;
use nom::combinator::complete;
use nom::multi::many0;
use nom::number::complete::{be_u8, be_u16};
use nom_derive::Parse;
use std::num::NonZeroUsize;
use std::sync::Arc;

impl Default for IPFixParser {
    fn default() -> Self {
        // Safe to unwrap because DEFAULT_MAX_TEMPLATE_CACHE_SIZE is non-zero
        let config = Config {
            max_template_cache_size: DEFAULT_MAX_TEMPLATE_CACHE_SIZE,
            max_field_count: MAX_FIELD_COUNT,
            max_template_total_size: usize::from(u16::MAX),
            max_error_sample_size: 256,
            max_records_per_flowset: DEFAULT_MAX_RECORDS_PER_FLOWSET,
            ttl_config: None,
            enterprise_registry: Arc::new(EnterpriseFieldRegistry::new()),
            pending_flows_config: None,
        };

        match Self::try_new(config) {
            Ok(parser) => parser,
            Err(e) => unreachable!("hardcoded default config must be valid: {e}"),
        }
    }
}

impl IPFixParser {
    /// Validates a configuration without allocating parser internals.
    pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
        config.validate()
    }

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
            max_records_per_flowset: config.max_records_per_flowset,
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
    fn set_max_records_per_flowset_field(&mut self, count: usize) {
        self.max_records_per_flowset = count;
    }
    fn set_ttl_config_field(&mut self, config: Option<TtlConfig>) {
        self.ttl_config = config;
    }
    fn set_enterprise_registry(&mut self, registry: Arc<EnterpriseFieldRegistry>) {
        self.enterprise_registry = registry;
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
                // Record all cached entries as dropped before discarding.
                if let Some(ref cache) = self.pending_flows {
                    let count = cache.count();
                    if count > 0 {
                        self.metrics.record_pending_dropped_n(count as u64);
                    }
                }
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
    pub(crate) fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
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
                    // The truncated flowset is kept in output as diagnostic
                    // data (truncated to max_error_sample_size).
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
                        let full_len = returned.len();
                        returned.truncate(max_error_sample_size);
                        if returned.len() < full_len {
                            info.truncated = true;
                        }
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
            let entries = cache.drain(template_id, &mut self.metrics);
            let total_entries = entries.len();
            for (processed, entry) in entries.iter().enumerate() {
                // Bound flowset count, consistent with V9 replay.
                if ipfix.flowsets.len() >= u16::MAX as usize {
                    let remaining = (total_entries - processed) as u64;
                    self.metrics.record_pending_replay_failed_n(remaining);
                    break;
                }
                let flowset_length =
                    u16::try_from(entry.raw_data.len().saturating_add(4)).unwrap_or(u16::MAX);
                let Some(new_header_length) = ipfix.header.length.checked_add(flowset_length)
                else {
                    // Count this entry plus all remaining as failed.
                    let remaining = (total_entries - processed) as u64;
                    self.metrics.record_pending_replay_failed_n(remaining);
                    break;
                };
                if self.try_replay_ipfix_flow(&mut ipfix.flowsets, template_id, entry) {
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
        // Use peek_valid_template to avoid false LRU promotion on failed parse.
        // Promote only after successful replay.

        // Try IPFIX templates
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = Data::parse_with_registry(
            &entry.raw_data,
            &template,
            &self.enterprise_registry,
            self.max_records_per_flowset,
        ) {
            // Don't record_hit() — the original flowset already recorded
            // a miss. Replay success is tracked via record_pending_replayed().
            self.templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
                },
                body: FlowSetBody::Data(data),
            });
            return true;
        }

        // Try IPFIX options templates
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.ipfix_options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = OptionsData::parse_with_registry(
            &entry.raw_data,
            &template,
            &self.enterprise_registry,
            self.max_records_per_flowset,
        ) {
            self.ipfix_options_templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
                },
                body: FlowSetBody::OptionsData(data),
            });
            return true;
        }

        // Try V9 templates
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.v9_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) =
            V9Data::parse_with_limit(&entry.raw_data, &template, self.max_records_per_flowset)
        {
            self.v9_templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
                },
                body: FlowSetBody::V9Data(data),
            });
            return true;
        }

        // Try V9 options templates
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.v9_options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) = V9OptionsData::parse_with_limit(
            &entry.raw_data,
            &template,
            self.max_records_per_flowset,
        ) {
            self.v9_options_templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    header_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
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

// ---------------------------------------------------------------------------
// Parsing impl blocks (moved from mod.rs)
// ---------------------------------------------------------------------------

/// Trait abstracting the template ID and field count accessors needed by the
/// generic insertion helper and template withdrawal detection.
trait HasTemplateId: Clone + PartialEq {
    fn template_id(&self) -> u16;
    /// Returns the declared field count. A field count of 0 signals template
    /// withdrawal per RFC 7011 Section 3.4.3.
    fn field_count(&self) -> u16;
}

impl HasTemplateId for Template {
    fn template_id(&self) -> u16 {
        self.template_id
    }
    fn field_count(&self) -> u16 {
        self.field_count
    }
}

impl HasTemplateId for OptionsTemplate {
    fn template_id(&self) -> u16 {
        self.template_id
    }
    fn field_count(&self) -> u16 {
        self.field_count
    }
}

impl HasTemplateId for V9Template {
    fn template_id(&self) -> u16 {
        self.template_id
    }
    fn field_count(&self) -> u16 {
        self.field_count
    }
}

impl HasTemplateId for V9OptionsTemplate {
    fn template_id(&self) -> u16 {
        self.template_id
    }
    fn field_count(&self) -> u16 {
        // V9 options templates don't support withdrawal
        // Return combined field count (non-zero for valid templates)
        let scope = self.options_scope_length / 4;
        let option = self.options_length / 4;
        scope.saturating_add(option)
    }
}

/// Insert templates into an LRU cache, recording collision/eviction/insertion metrics.
fn insert_templates<T: HasTemplateId>(
    cache: &mut LruCache<u16, TemplateWithTtl<Arc<T>>>,
    templates: &[T],
    ttl_enabled: bool,
    metrics: &mut CacheMetrics,
) {
    for t in templates {
        let arc_template = Arc::new(t.clone());
        let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
        if let Some(existing) = cache.peek(&t.template_id())
            && existing.template.as_ref() != t
        {
            metrics.record_collision();
        }
        // push() returns Some in two cases: (1) a different key was LRU-evicted
        // to make room, or (2) the same key existed and its value was replaced.
        // Only count case (1) as an eviction.
        if let Some((evicted_key, _evicted)) = cache.push(t.template_id(), wrapped)
            && evicted_key != t.template_id()
        {
            metrics.record_eviction();
        }
        metrics.record_insertion();
    }
}

impl IPFixParser {
    /// Add templates to the parser by cloning from slice.
    fn add_ipfix_templates(&mut self, templates: &[Template]) {
        let ttl_enabled = self.ttl_config.is_some();
        insert_templates(
            &mut self.templates,
            templates,
            ttl_enabled,
            &mut self.metrics,
        );
    }

    fn add_ipfix_options_templates(&mut self, templates: &[OptionsTemplate]) {
        let ttl_enabled = self.ttl_config.is_some();
        insert_templates(
            &mut self.ipfix_options_templates,
            templates,
            ttl_enabled,
            &mut self.metrics,
        );
    }

    fn add_v9_templates(&mut self, templates: &[V9Template]) {
        let ttl_enabled = self.ttl_config.is_some();
        insert_templates(
            &mut self.v9_templates,
            templates,
            ttl_enabled,
            &mut self.metrics,
        );
    }

    fn add_v9_options_templates(&mut self, templates: &[V9OptionsTemplate]) {
        let ttl_enabled = self.ttl_config.is_some();
        insert_templates(
            &mut self.v9_options_templates,
            templates,
            ttl_enabled,
            &mut self.metrics,
        );
    }

    /// Remove an IPFIX template by ID (RFC 7011 Section 8.1 template withdrawal).
    /// Also purges any pending flows cached under this template ID to prevent
    /// stale data from being replayed against a replacement template.
    ///
    /// Per RFC 7011 §8.1, template_id == DATA_TEMPLATE_IPFIX_ID (2) with
    /// field_count == 0 signals "withdraw ALL data templates". This method
    /// handles both individual and bulk withdrawal.
    fn withdraw_ipfix_template(&mut self, template_id: u16) {
        if template_id == DATA_TEMPLATE_IPFIX_ID {
            // "Withdraw all data templates" — clear entire data template
            // cache and drain pending flows only for those template IDs.
            // Pending flows for options template IDs are left untouched
            // since those templates remain valid.
            let ids: Vec<u16> = self.templates.iter().map(|(&id, _)| id).collect();
            for id in &ids {
                self.templates.pop(id);
            }
            if let Some(ref mut cache) = self.pending_flows {
                for &id in &ids {
                    let drained = cache.drain(id, &mut self.metrics);
                    let n = drained.len() as u64;
                    if n > 0 {
                        self.metrics.record_pending_dropped_n(n);
                    }
                }
            }
        } else {
            self.templates.pop(&template_id);
            if let Some(ref mut cache) = self.pending_flows {
                let drained = cache.drain(template_id, &mut self.metrics);
                let n = drained.len() as u64;
                if n > 0 {
                    self.metrics.record_pending_dropped_n(n);
                }
            }
        }
    }

    /// Remove an IPFIX options template by ID (template withdrawal).
    /// Also purges any pending flows cached under this template ID.
    ///
    /// Per RFC 7011 §8.1, template_id == OPTIONS_TEMPLATE_IPFIX_ID (3) with
    /// field_count == 0 signals "withdraw ALL options templates".
    fn withdraw_ipfix_options_template(&mut self, template_id: u16) {
        if template_id == OPTIONS_TEMPLATE_IPFIX_ID {
            // "Withdraw all options templates" — clear entire options template
            // cache and drain pending flows only for those template IDs.
            // Pending flows for data template IDs are left untouched.
            let ids: Vec<u16> = self
                .ipfix_options_templates
                .iter()
                .map(|(&id, _)| id)
                .collect();
            for id in &ids {
                self.ipfix_options_templates.pop(id);
            }
            if let Some(ref mut cache) = self.pending_flows {
                for &id in &ids {
                    let drained = cache.drain(id, &mut self.metrics);
                    let n = drained.len() as u64;
                    if n > 0 {
                        self.metrics.record_pending_dropped_n(n);
                    }
                }
            }
        } else {
            self.ipfix_options_templates.pop(&template_id);
            if let Some(ref mut cache) = self.pending_flows {
                let drained = cache.drain(template_id, &mut self.metrics);
                let n = drained.len() as u64;
                if n > 0 {
                    self.metrics.record_pending_dropped_n(n);
                }
            }
        }
    }
}

impl FlowSetBody {
    #[allow(clippy::too_many_arguments)]
    fn parse_templates<'a, T, F>(
        i: &'a [u8],
        parser: &mut IPFixParser,
        parse_fn: F,
        single_variant: fn(T) -> FlowSetBody,
        multi_variant: fn(Vec<T>) -> FlowSetBody,
        validate: fn(&T, &IPFixParser) -> bool,
        add_templates: fn(&mut IPFixParser, &[T]),
        withdraw_template: Option<fn(&mut IPFixParser, u16)>,
    ) -> IResult<&'a [u8], FlowSetBody>
    where
        T: Clone + HasTemplateId,
        F: Fn(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let (i, templates) = many0(complete(parse_fn))(i)?;

        // Handle template withdrawals (RFC 7011 Section 8.1):
        // Templates with field_count=0 signal withdrawal from the cache.
        // Skip withdrawal for IDs that also have a new definition in the
        // same flowset — the new definition will simply replace the old one
        // without needlessly draining pending flows.
        let mut had_withdrawals = false;
        if let Some(withdraw_fn) = withdraw_template {
            for t in &templates {
                if t.field_count() == 0 {
                    let id = t.template_id();
                    // "Withdraw all" IDs (2 for data, 3 for options) always
                    // take effect regardless of other templates in the batch.
                    let has_redefinition = id != DATA_TEMPLATE_IPFIX_ID
                        && id != OPTIONS_TEMPLATE_IPFIX_ID
                        && templates
                            .iter()
                            .any(|other| other.template_id() == id && other.field_count() > 0);
                    if !has_redefinition {
                        withdraw_fn(parser, id);
                    }
                    had_withdrawals = true;
                }
            }
        }

        // Filter to only valid templates (withdrawals will be filtered out
        // since they have empty fields, failing the is_valid check)
        let valid_templates: Vec<_> = templates
            .into_iter()
            .filter(|t| validate(t, parser))
            .collect();
        if valid_templates.is_empty() {
            // If we processed withdrawals, return Empty instead of error
            if had_withdrawals {
                return Ok((i, FlowSetBody::Empty));
            }
            return Err(nom::Err::Error(nom::error::Error::new(
                i,
                nom::error::ErrorKind::Verify,
            )));
        }
        // Pass slice to add_templates to clone only what's needed
        add_templates(parser, &valid_templates);
        match valid_templates.len() {
            1 => {
                if let Some(template) = valid_templates.into_iter().next() {
                    Ok((i, single_variant(template)))
                } else {
                    Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            }
            _ => Ok((i, multi_variant(valid_templates))),
        }
    }

    pub(super) fn parse<'a>(
        i: &'a [u8],
        parser: &mut IPFixParser,
        id: u16,
    ) -> IResult<&'a [u8], FlowSetBody> {
        match id {
            DATA_TEMPLATE_IPFIX_ID => Self::parse_templates(
                i,
                parser,
                Template::parse,
                FlowSetBody::Template,
                FlowSetBody::Templates,
                |t: &Template, p: &IPFixParser| t.is_valid(p),
                |parser, templates| parser.add_ipfix_templates(templates),
                Some(|parser: &mut IPFixParser, id| parser.withdraw_ipfix_template(id)),
            ),
            DATA_TEMPLATE_V9_ID => Self::parse_templates(
                i,
                parser,
                V9Template::parse,
                FlowSetBody::V9Template,
                FlowSetBody::V9Templates,
                |t: &V9Template, p: &IPFixParser| {
                    // Validate V9 templates using IPFIX parser limits.
                    // V9 does not support variable-length fields, so reject
                    // zero-length and the variable-length sentinel 65535.
                    usize::from(t.field_count) <= p.max_field_count
                        && !t.fields.is_empty()
                        && t.fields
                            .iter()
                            .all(|f| f.field_length > 0 && f.field_length != 65535)
                        && usize::from(t.get_total_size()) <= p.max_template_total_size
                        && !t.has_duplicate_fields()
                },
                |parser, templates| parser.add_v9_templates(templates),
                None, // V9 doesn't support template withdrawal
            ),
            OPTIONS_TEMPLATE_V9_ID => Self::parse_templates(
                i,
                parser,
                V9OptionsTemplate::parse,
                FlowSetBody::V9OptionsTemplate,
                FlowSetBody::V9OptionsTemplates,
                |t: &V9OptionsTemplate, p: &IPFixParser| {
                    let scope_count = usize::from(t.options_scope_length / 4);
                    let option_count = usize::from(t.options_length / 4);
                    t.options_scope_length.is_multiple_of(4)
                        && t.options_length.is_multiple_of(4)
                        && scope_count > 0
                        && scope_count <= p.max_field_count
                        && option_count <= p.max_field_count
                        && scope_count.saturating_add(option_count) <= p.max_field_count
                        && usize::from(t.get_total_size()) <= p.max_template_total_size
                        && !t.has_duplicate_scope_fields()
                        && !t.has_duplicate_option_fields()
                        // V9 does not support variable-length fields; reject any
                        // zero-length or variable-length sentinel (65535) fields,
                        // consistent with the V9 parser's own validation.
                        && t.scope_fields.iter().all(|f| f.field_length > 0 && f.field_length != 65535)
                        && t.option_fields.iter().all(|f| f.field_length > 0 && f.field_length != 65535)
                },
                |parser, templates| parser.add_v9_options_templates(templates),
                None, // V9 doesn't support template withdrawal
            ),
            OPTIONS_TEMPLATE_IPFIX_ID => Self::parse_templates(
                i,
                parser,
                OptionsTemplate::parse,
                FlowSetBody::OptionsTemplate,
                FlowSetBody::OptionsTemplates,
                |t: &OptionsTemplate, p: &IPFixParser| t.is_valid(p),
                |parser, templates| parser.add_ipfix_options_templates(templates),
                Some(|parser: &mut IPFixParser, id| parser.withdraw_ipfix_options_template(id)),
            ),
            // Parse Data
            _ => {
                // NOTE: Template ID collision across cache types is possible and
                // expected when both IPFIX and V9-style templates coexist in
                // the same parser (the IPFIX parser accepts both flavors).
                // The lookup order below defines priority: IPFIX templates >
                // IPFIX options > V9 templates > V9 options. If the same
                // template ID appears in multiple caches, only the first
                // match is used and others are silently shadowed.

                // Try IPFix templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    if template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    }
                    let (i, data) = Data::parse_with_registry(
                        i,
                        &template,
                        &parser.enterprise_registry,
                        parser.max_records_per_flowset,
                    )?;
                    return Ok((i, FlowSetBody::Data(data)));
                }

                // Try IPFix options templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.ipfix_options_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    if template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    }
                    let (i, data) = OptionsData::parse_with_registry(
                        i,
                        &template,
                        &parser.enterprise_registry,
                        parser.max_records_per_flowset,
                    )?;
                    return Ok((i, FlowSetBody::OptionsData(data)));
                }

                // Try V9 templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.v9_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    let (i, data) =
                        V9Data::parse_with_limit(i, &template, parser.max_records_per_flowset)?;
                    return Ok((i, FlowSetBody::V9Data(data)));
                }

                // Try V9 options templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.v9_options_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    let (i, data) = V9OptionsData::parse_with_limit(
                        i,
                        &template,
                        parser.max_records_per_flowset,
                    )?;
                    return Ok((i, FlowSetBody::V9OptionsData(data)));
                }

                // Template not found or expired — one miss per flowset,
                // symmetric with one hit per flowset above.
                parser.metrics.record_miss();
                if id > 255 {
                    // Store full raw data only when the pending cache is
                    // enabled, the entry fits the size limit, AND the
                    // per-template cap has room.  Otherwise truncate to
                    // max_error_sample_size to avoid large allocations
                    // that would be immediately rejected.
                    let (raw_data, truncated) = if parser
                        .pending_flows
                        .as_ref()
                        .is_some_and(|c| c.would_accept(id, i.len()))
                    {
                        (i.to_vec(), false)
                    } else {
                        let limit = i.len().min(parser.max_error_sample_size);
                        (i[..limit].to_vec(), limit < i.len())
                    };
                    let info = NoTemplateInfo {
                        template_id: id,
                        raw_data,
                        truncated,
                    };
                    Ok((&[] as &[u8], FlowSetBody::NoTemplate(info)))
                } else {
                    // Set IDs 4-255 are reserved per RFC 7011; skip gracefully
                    Ok((&[] as &[u8], FlowSetBody::Empty))
                }
            }
        }
    }
}

impl Template {
    /// Validate the template against parser configuration
    pub fn is_valid(&self, parser: &IPFixParser) -> bool {
        <Self as CommonTemplate>::is_valid(self, parser)
    }
}

impl OptionsTemplate {
    /// Validate the options template against parser configuration
    pub fn is_valid(&self, parser: &IPFixParser) -> bool {
        <Self as CommonTemplate>::is_valid(self, parser)
    }
}

/// Collect template field lengths only when at least one field is variable-length.
fn collect_varlen_field_lengths(fields: &[TemplateField]) -> Vec<u16> {
    if fields.iter().any(|f| f.field_length == 65535) {
        fields.iter().map(|f| f.field_length).collect()
    } else {
        Vec::new()
    }
}

impl Data {
    /// Parse Data using the enterprise registry to resolve custom enterprise fields
    pub(super) fn parse_with_registry<'a>(
        i: &'a [u8],
        template: &Template,
        registry: &EnterpriseFieldRegistry,
        max_records: usize,
    ) -> IResult<&'a [u8], Self> {
        let template_field_lengths = collect_varlen_field_lengths(template.get_fields());
        let (i, fields) = FieldParser::parse_with_registry(i, template, registry, max_records)?;
        Ok((
            i,
            Self {
                fields,
                padding: vec![],
                template_field_lengths,
            },
        ))
    }
}

impl OptionsData {
    /// Parse OptionsData using the enterprise registry to resolve custom enterprise fields
    pub(super) fn parse_with_registry<'a>(
        i: &'a [u8],
        template: &OptionsTemplate,
        registry: &EnterpriseFieldRegistry,
        max_records: usize,
    ) -> IResult<&'a [u8], Self> {
        let template_field_lengths = collect_varlen_field_lengths(template.get_fields());
        let (i, fields) = FieldParser::parse_with_registry(i, template, registry, max_records)?;
        Ok((
            i,
            Self {
                fields,
                padding: vec![],
                template_field_lengths,
            },
        ))
    }
}

impl<'a> FieldParser {
    /// Core parsing loop shared by `parse` and `parse_with_registry`.
    ///
    /// The `parse_field` closure controls how each template field is decoded —
    /// either using built-in field types or the enterprise registry.
    fn parse_inner<T: CommonTemplate, F>(
        mut i: &'a [u8],
        template: &T,
        max_records: usize,
        parse_field: F,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>>
    where
        F: Fn(&TemplateField, &'a [u8]) -> IResult<&'a [u8], FieldValue>,
    {
        let template_fields = template.get_fields();
        if template_fields.is_empty() {
            return Ok((i, Vec::new()));
        }

        // Estimate capacity based on input size and template field count.
        // Variable-length fields (field_length == 65535) are RFC 7011 markers,
        // not actual sizes — count them as 1 byte minimum for estimation.
        let template_size: usize = template_fields
            .iter()
            .map(|f| {
                if f.field_length == 65535 {
                    1
                } else {
                    usize::from(f.field_length)
                }
            })
            .sum();
        // template_fields is non-empty (checked above) and each contributes >= 1 byte,
        // so template_size is always > 0 here. Return error to match V9 behavior.
        if template_size == 0 {
            return Err(nom::Err::Error(nom::error::Error::new(
                i,
                nom::error::ErrorKind::Verify,
            )));
        }
        let estimated_records = (i.len() / template_size).min(max_records);
        let mut res = Vec::with_capacity(estimated_records);

        // Try to parse as much as we can, but if it fails, just return what we have so far.
        while !i.is_empty() && res.len() < max_records {
            let before = i;
            let mut vec = Vec::with_capacity(template_fields.len());
            for field in template_fields.iter() {
                match parse_field(field, i) {
                    Ok((remaining, field_value)) => {
                        vec.push((field.field_type, field_value));
                        i = remaining;
                    }
                    Err(_) => {
                        i = before;
                        return Ok((i, res));
                    }
                }
            }
            // Guard against infinite loops: if no bytes were consumed after
            // parsing a full record, stop to prevent CPU-bound DoS.
            if std::ptr::eq(i, before) {
                break;
            }
            res.push(vec);
        }
        Ok((i, res))
    }

    /// Takes a byte stream and a cached template.
    /// Fields get matched to static types.
    /// Returns BTree of IPFix Types & Fields or IResult Error.
    pub(super) fn parse<T: CommonTemplate>(
        i: &'a [u8],
        template: &T,
        max_records: usize,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>> {
        Self::parse_inner(i, template, max_records, |field, input| {
            field.parse_as_field_value(input)
        })
    }

    /// Same as parse but uses the enterprise registry to resolve custom enterprise fields
    fn parse_with_registry<T: CommonTemplate>(
        i: &'a [u8],
        template: &T,
        registry: &EnterpriseFieldRegistry,
        max_records: usize,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>> {
        Self::parse_inner(i, template, max_records, |field, input| {
            field.parse_as_field_value_with_registry(input, registry)
        })
    }
}

impl TemplateField {
    // If 65535, read 1 byte.
    // If that byte is < 255 that is the length.
    // If that byte is == 255 then read 2 bytes.  That is the length.
    // Otherwise, return the field length.
    fn parse_field_length<'a>(&self, i: &'a [u8]) -> IResult<&'a [u8], u16> {
        match self.field_length {
            65535 => {
                let (i, length) = be_u8(i)?;
                if length == 255 {
                    let (i, full_length) = be_u16(i)?;
                    // RFC 7011 Section 7: length values of 0 are not permitted
                    if full_length == 0 {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            i,
                            nom::error::ErrorKind::Verify,
                        )));
                    }
                    // Validate length doesn't exceed remaining buffer
                    if (full_length as usize) > i.len() {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            i,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                    Ok((i, full_length))
                } else {
                    // RFC 7011 Section 7: length values of 0 are not permitted
                    if length == 0 {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            i,
                            nom::error::ErrorKind::Verify,
                        )));
                    }
                    // Validate length doesn't exceed remaining buffer
                    if (length as usize) > i.len() {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            i,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                    Ok((i, u16::from(length)))
                }
            }
            length => Ok((i, length)),
        }
    }

    fn parse_as_field_value<'a>(&self, i: &'a [u8]) -> IResult<&'a [u8], FieldValue> {
        let (i, length) = self.parse_field_length(i)?;
        FieldValue::from_field_type(i, self.field_type.into(), length)
    }

    fn parse_as_field_value_with_registry<'a>(
        &self,
        i: &'a [u8],
        registry: &EnterpriseFieldRegistry,
    ) -> IResult<&'a [u8], FieldValue> {
        let (i, length) = self.parse_field_length(i)?;
        let field_type = self.field_type.to_field_data_type(registry);
        FieldValue::from_field_type(i, field_type, length)
    }
}
