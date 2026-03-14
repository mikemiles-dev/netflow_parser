//! V9Parser — template-cached NetFlow V9 parser with pending flow support.
//!
//! Type definitions live in the parent `v9` module (`mod.rs`).
//! Parsing impl blocks for V9 types (FlowSetBody, FlowSetParser, FieldParser, etc.)
//! are also defined here.

use super::lookup::ScopeFieldType;
use super::{
    DATA_TEMPLATE_V9_ID, DEFAULT_MAX_TEMPLATE_CACHE_SIZE, Data, FieldParser, FlowSet,
    FlowSetBody, FlowSetHeader, FlowSetParser, MAX_FIELD_COUNT, NoTemplateInfo,
    OPTIONS_TEMPLATE_V9_ID, OptionsData, OptionsFieldParser, OptionsTemplate,
    OptionsTemplateScopeField, OptionsTemplates, ScopeDataField, ScopeParser, Template,
    TemplateField, TemplateId, Templates, V9, V9FieldPair, V9FlowRecord,
};
use crate::variable_versions::config::DEFAULT_MAX_RECORDS_PER_FLOWSET;
use crate::variable_versions::enterprise_registry::EnterpriseFieldRegistry;
use crate::variable_versions::field_value::FieldValue;
use crate::variable_versions::metrics::CacheMetrics;
use crate::variable_versions::ttl::{TemplateWithTtl, TtlConfig};
use crate::variable_versions::{
    Config, ConfigError, ParserConfig, ParserFields, PendingFlowCache, PendingFlowEntry,
    PendingFlowsConfig,
};
use crate::{NetflowError, NetflowPacket, ParsedNetflow};

use lru::LruCache;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom_derive::Parse;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Stateful NetFlow V9 parser with LRU template caching and optional pending flow support.
#[derive(Debug)]
pub struct V9Parser {
    pub(crate) templates: LruCache<TemplateId, TemplateWithTtl<Arc<Template>>>,
    pub(crate) options_templates: LruCache<TemplateId, TemplateWithTtl<Arc<OptionsTemplate>>>,
    pub(crate) ttl_config: Option<TtlConfig>,
    pub(crate) max_template_cache_size: usize,
    pub(crate) max_field_count: usize,
    pub(crate) max_template_total_size: usize,
    pub(crate) max_error_sample_size: usize,
    pub(crate) max_records_per_flowset: usize,
    pub(crate) metrics: CacheMetrics,
    pub(crate) pending_flows: Option<PendingFlowCache>,
}

impl Default for V9Parser {
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

impl V9Parser {
    /// Validates a configuration without allocating parser internals.
    pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
        config.validate()
    }

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
            max_records_per_flowset: config.max_records_per_flowset,
            metrics: CacheMetrics::new(),
            pending_flows,
        })
    }
}

impl ParserFields for V9Parser {
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
    fn pending_flows(&self) -> &Option<PendingFlowCache> {
        &self.pending_flows
    }
    fn pending_flows_mut(&mut self) -> &mut Option<PendingFlowCache> {
        &mut self.pending_flows
    }
}

impl ParserConfig for V9Parser {
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
    /// Parse a NetFlow V9 packet from raw bytes, using cached templates to decode data records.
    pub(crate) fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
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
        // Try regular template (peek to avoid false LRU promotion on failed parse)
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, data)) =
            Data::parse_with_limit(&entry.raw_data, &template, self.max_records_per_flowset)
        {
            // Don't record_hit() here — the original flowset already
            // recorded a miss. Replay success is tracked separately
            // via record_pending_replayed() in the caller.
            self.templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    flowset_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
                },
                body: FlowSetBody::Data(data),
            });
            return true;
        }
        // Try options template (peek to avoid false LRU promotion on failed parse)
        if let Some(template) = crate::variable_versions::peek_valid_template(
            &mut self.options_templates,
            &template_id,
            &self.ttl_config,
            &mut self.metrics,
        ) && let Ok((_, options_data)) = OptionsData::parse_with_limit(
            &entry.raw_data,
            &template,
            self.max_records_per_flowset,
        ) {
            self.options_templates.promote(&template_id);
            flowsets.push(FlowSet {
                header: FlowSetHeader {
                    flowset_id: template_id,
                    length: u16::try_from(entry.raw_data.len().saturating_add(4))
                        .unwrap_or(u16::MAX),
                },
                body: FlowSetBody::OptionsData(options_data),
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
            .chain(self.options_templates.iter().map(|(&id, _)| id))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

// ---------------------------------------------------------------------------
// Parsing impl blocks (moved from mod.rs)
// ---------------------------------------------------------------------------

impl FlowSetBody {
    pub(super) fn parse<'a>(
        i: &'a [u8],
        parser: &mut V9Parser,
        id: u16,
    ) -> IResult<&'a [u8], FlowSetBody> {
        match id {
            DATA_TEMPLATE_V9_ID => {
                let (i, templates) = Templates::parse(i)?;
                // Filter to only valid templates; reject if none are valid
                let valid_templates: Vec<_> = templates
                    .templates
                    .iter()
                    .filter(|t| t.is_valid(parser))
                    .cloned()
                    .collect();
                if valid_templates.is_empty() {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                let ttl_enabled = parser.ttl_config.is_some();
                for template in &valid_templates {
                    let arc_template = Arc::new(template.clone());
                    let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
                    // Check for collision (same ID, different definition)
                    // Use peek() to avoid affecting LRU ordering
                    if let Some(existing) = parser.templates.peek(&template.template_id)
                        && existing.template.as_ref() != template
                    {
                        parser.metrics.record_collision();
                    }
                    // push() returns Some in two cases: (1) a different key was LRU-evicted
                    // to make room, or (2) the same key existed and its value was replaced.
                    // Only count case (1) as an eviction.
                    if let Some((evicted_key, _evicted)) =
                        parser.templates.push(template.template_id, wrapped)
                        && evicted_key != template.template_id
                    {
                        parser.metrics.record_eviction();
                    }
                    parser.metrics.record_insertion();
                }
                let result = Templates {
                    templates: valid_templates,
                    padding: templates.padding,
                };
                Ok((i, FlowSetBody::Template(result)))
            }
            OPTIONS_TEMPLATE_V9_ID => {
                let (i, options_templates) = OptionsTemplates::parse(i)?;
                // Filter to only valid templates; reject if none are valid
                let valid_templates: Vec<_> = options_templates
                    .templates
                    .iter()
                    .filter(|t| t.is_valid(parser))
                    .cloned()
                    .collect();
                if valid_templates.is_empty() {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                // Store templates efficiently using Arc for zero-cost sharing
                let ttl_enabled = parser.ttl_config.is_some();
                for template in &valid_templates {
                    let arc_template = Arc::new(template.clone());
                    let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
                    // Check for collision (same ID, different definition)
                    // Use peek() to avoid affecting LRU ordering
                    if let Some(existing) = parser.options_templates.peek(&template.template_id)
                        && existing.template.as_ref() != template
                    {
                        parser.metrics.record_collision();
                    }
                    // push() returns Some in two cases: (1) a different key was LRU-evicted
                    // to make room, or (2) the same key existed and its value was replaced.
                    // Only count case (1) as an eviction.
                    if let Some((evicted_key, _evicted)) =
                        parser.options_templates.push(template.template_id, wrapped)
                        && evicted_key != template.template_id
                    {
                        parser.metrics.record_eviction();
                    }
                    parser.metrics.record_insertion();
                }
                let result = OptionsTemplates {
                    templates: valid_templates,
                    padding: options_templates.padding,
                };
                Ok((i, FlowSetBody::OptionsTemplate(result)))
            }
            _ => {
                // Try regular templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    let (i, data) =
                        Data::parse_with_limit(i, &template, parser.max_records_per_flowset)?;
                    return Ok((i, FlowSetBody::Data(data)));
                }

                // Try options templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.options_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    parser.metrics.record_hit();
                    let (i, options_data) = OptionsData::parse_with_limit(
                        i,
                        &template,
                        parser.max_records_per_flowset,
                    )?;
                    return Ok((i, FlowSetBody::OptionsData(options_data)));
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
                    // Set IDs 2-255 are reserved per RFC 3954; skip gracefully
                    Ok((&[] as &[u8], FlowSetBody::Empty))
                }
            }
        }
    }
}

impl Template {
    /// Validate the template against parser configuration
    pub fn is_valid(&self, parser: &V9Parser) -> bool {
        // Check field count limit
        if usize::from(self.field_count) > parser.max_field_count {
            return false;
        }

        // Check fields are not empty and all fields have valid length
        // (V9 does not support variable-length fields, so every field must have a concrete size;
        // reject both zero-length and the variable-length sentinel 65535)
        if self.fields.is_empty()
            || self
                .fields
                .iter()
                .any(|f| f.field_length == 0 || f.field_length == 65535)
        {
            return false;
        }

        // Check total size limit
        let total_size = usize::from(self.get_total_size());
        if total_size > parser.max_template_total_size {
            return false;
        }

        // Check for duplicate field type numbers
        if self.has_duplicate_fields() {
            return false;
        }

        true
    }

    /// Returns the total fixed-length size of the template fields.
    /// Variable-length sentinel values (65535) are excluded since they
    /// are RFC 7011 markers, not actual sizes.
    pub fn get_total_size(&self) -> u16 {
        self.fields
            .iter()
            .filter(|f| f.field_length != 65535)
            .fold(0, |acc, i| acc.saturating_add(i.field_length))
    }

    /// Check if the template has duplicate field type numbers
    pub fn has_duplicate_fields(&self) -> bool {
        let mut seen = std::collections::HashSet::with_capacity(self.fields.len());
        for field in &self.fields {
            if !seen.insert(field.field_type_number) {
                return true; // Found duplicate
            }
        }
        false
    }
}

impl OptionsTemplate {
    /// Validate the options template against parser configuration
    pub fn is_valid(&self, parser: &V9Parser) -> bool {
        // Scope and option lengths must be multiples of 4 (each field is type_id:u16 + length:u16)
        if !self.options_scope_length.is_multiple_of(4)
            || !self.options_length.is_multiple_of(4)
        {
            return false;
        }
        let scope_count = usize::from(self.options_scope_length / 4);
        let option_count = usize::from(self.options_length / 4);

        // RFC 3954 requires at least one scope field
        if scope_count == 0 {
            return false;
        }

        // V9 does not support variable-length fields; reject zero-length
        // (would cause infinite loops) and the variable-length sentinel 65535.
        if self
            .scope_fields
            .iter()
            .any(|f| f.field_length == 0 || f.field_length == 65535)
            || self
                .option_fields
                .iter()
                .any(|f| f.field_length == 0 || f.field_length == 65535)
        {
            return false;
        }

        // Check field count limits (individually and combined)
        if scope_count > parser.max_field_count
            || option_count > parser.max_field_count
            || scope_count.saturating_add(option_count) > parser.max_field_count
        {
            return false;
        }

        // Check total size limit
        let total_size = usize::from(self.get_total_size());
        if total_size > parser.max_template_total_size {
            return false;
        }

        // Check for duplicate field type numbers in scope fields
        if self.has_duplicate_scope_fields() {
            return false;
        }

        // Check for duplicate field type numbers in option fields
        if self.has_duplicate_option_fields() {
            return false;
        }

        true
    }

    /// Returns the total fixed-length size of all fields in the options template.
    /// Variable-length sentinel values (65535) are excluded since they
    /// are RFC 7011 markers, not actual sizes.
    pub fn get_total_size(&self) -> u16 {
        let scope_size: u16 = self
            .scope_fields
            .iter()
            .filter(|f| f.field_length != 65535)
            .fold(0, |acc, f| acc.saturating_add(f.field_length));
        let option_size: u16 = self
            .option_fields
            .iter()
            .filter(|f| f.field_length != 65535)
            .fold(0, |acc, f| acc.saturating_add(f.field_length));
        scope_size.saturating_add(option_size)
    }

    /// Check if the template has duplicate scope field type numbers
    pub fn has_duplicate_scope_fields(&self) -> bool {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(self.scope_fields.len());
        for field in &self.scope_fields {
            if !seen.insert(field.field_type_number) {
                return true; // Found duplicate
            }
        }
        false
    }

    /// Check if the template has duplicate option field type numbers
    pub fn has_duplicate_option_fields(&self) -> bool {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(self.option_fields.len());
        for field in &self.option_fields {
            if !seen.insert(field.field_type_number) {
                return true; // Found duplicate
            }
        }
        false
    }
}

impl<'a> ScopeParser {
    pub(super) fn parse(
        input: &'a [u8],
        template: &OptionsTemplate,
    ) -> IResult<&'a [u8], Vec<ScopeDataField>> {
        let mut result = Vec::with_capacity(template.scope_fields.len());
        let mut remaining = input;
        for template_field in template.scope_fields.iter() {
            let (i, scope_field) = ScopeDataField::parse(remaining, template_field)?;
            remaining = i;
            result.push(scope_field);
        }
        Ok((remaining, result))
    }
}

impl<'a> OptionsFieldParser {
    pub(super) fn parse(
        input: &'a [u8],
        template: &OptionsTemplate,
    ) -> IResult<&'a [u8], Vec<V9FieldPair>> {
        let mut result = Vec::with_capacity(template.option_fields.len());
        let mut remaining = input;
        for template_field in template.option_fields.iter() {
            let (i, field_value) = template_field.parse_as_field_value(remaining)?;
            remaining = i;
            result.push((template_field.field_type, field_value));
        }
        Ok((remaining, result))
    }
}

impl ScopeDataField {
    pub(super) fn parse<'a>(
        input: &'a [u8],
        template_field: &OptionsTemplateScopeField,
    ) -> IResult<&'a [u8], ScopeDataField> {
        let (new_input, field_value) = take(template_field.field_length)(input)?;
        let buf = field_value.to_vec();

        match template_field.field_type {
            ScopeFieldType::System => Ok((new_input, ScopeDataField::System(buf))),
            ScopeFieldType::Interface => Ok((new_input, ScopeDataField::Interface(buf))),
            ScopeFieldType::LineCard => Ok((new_input, ScopeDataField::LineCard(buf))),
            ScopeFieldType::NetflowCache => Ok((new_input, ScopeDataField::NetFlowCache(buf))),
            ScopeFieldType::Template => Ok((new_input, ScopeDataField::Template(buf))),
            ScopeFieldType::Unknown(_) => Ok((
                new_input,
                ScopeDataField::Unknown(template_field.field_type_number, buf),
            )),
        }
    }
}

impl FlowSetParser {
    pub(super) fn parse_flowsets<'a>(
        i: &'a [u8],
        parser: &mut V9Parser,
        record_count: u16,
    ) -> IResult<&'a [u8], Vec<FlowSet>> {
        // Cap pre-allocation to avoid memory amplification from untrusted header.count
        let cap = (record_count as usize).min(64);
        let (remaining, flowsets) = (0..record_count).try_fold(
            (i, Vec::with_capacity(cap)),
            |(remaining, mut flowsets), _| {
                if remaining.is_empty() {
                    return Ok((remaining, flowsets));
                }
                let (i, flowset) = FlowSet::parse(remaining, parser)?;
                flowsets.push(flowset);
                Ok((i, flowsets))
            },
        )?;

        Ok((remaining, flowsets))
    }
}

impl<'a> FieldParser {
    pub(super) fn parse(
        mut input: &'a [u8],
        template: &Template,
        max_records: usize,
    ) -> IResult<&'a [u8], Vec<Vec<V9FieldPair>>> {
        // Estimate per-record size for capacity pre-allocation.
        // Variable-length fields (65535) are counted as 1 byte minimum
        // to avoid over-allocation from small fixed-size denominators.
        let template_total_size: usize = template
            .fields
            .iter()
            .map(|f| {
                if f.field_length == 65535 {
                    1
                } else {
                    usize::from(f.field_length)
                }
            })
            .sum();
        if template_total_size == 0 {
            return Err(nom::Err::Error(NomError::new(input, ErrorKind::Verify)));
        }

        // Calculate how many complete records we can parse based on input length
        let record_count = (input.len() / template_total_size).min(max_records);
        let mut res = Vec::with_capacity(record_count);

        for _ in 0..record_count {
            let before = input;
            match Self::parse_data_fields(input, template) {
                Ok((remaining, record)) => {
                    input = remaining;
                    res.push(record);
                }
                Err(_) => {
                    input = before;
                    return Ok((input, res));
                }
            };
            // Guard against infinite loops: if no bytes were consumed after
            // parsing a full record, stop to prevent CPU-bound DoS.
            if std::ptr::eq(input, before) {
                break;
            }
        }

        Ok((input, res))
    }

    fn parse_data_fields(
        mut input: &'a [u8],
        template: &Template,
    ) -> IResult<&'a [u8], V9FlowRecord> {
        let mut res = Vec::with_capacity(template.fields.len());

        for template_field in template.fields.iter() {
            let (new_input, field_value) = template_field.parse_as_field_value(input)?;
            input = new_input;
            res.push((template_field.field_type, field_value));
        }

        Ok((input, res))
    }
}

impl TemplateField {
    #[inline]
    pub fn parse_as_field_value<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], FieldValue> {
        FieldValue::from_field_type(input, self.field_type.into(), self.field_length)
    }
}
