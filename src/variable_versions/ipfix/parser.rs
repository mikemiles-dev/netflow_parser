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
    /// Validates a configuration without allocating parser internals.
    pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
        NonZeroUsize::new(config.max_template_cache_size).ok_or(
            ConfigError::InvalidCacheSize(config.max_template_cache_size),
        )?;
        if config.max_field_count == 0 {
            return Err(ConfigError::InvalidFieldCount(0));
        }
        if config.max_template_total_size == 0 {
            return Err(ConfigError::InvalidTemplateTotalSize(0));
        }
        if let Some(ref ttl) = config.ttl_config {
            if ttl.duration.is_zero() {
                return Err(ConfigError::InvalidTtlDuration);
            }
        }
        if let Some(ref pf) = config.pending_flows_config {
            PendingFlowCache::validate_config(pf)?;
        }
        Ok(())
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

// ---------------------------------------------------------------------------
// Parsing impl blocks (moved from mod.rs)
// ---------------------------------------------------------------------------

impl IPFixParser {
    /// Add templates to the parser by cloning from slice.
    fn add_ipfix_templates(&mut self, templates: &[Template]) {
        let ttl_enabled = self.ttl_config.is_some();
        for t in templates {
            let arc_template = Arc::new(t.clone());
            let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
            if let Some(existing) = self.templates.peek(&t.template_id) {
                if existing.template.as_ref() != t {
                    self.metrics.record_collision();
                }
            } else if self.templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_ipfix_options_templates(&mut self, templates: &[OptionsTemplate]) {
        let ttl_enabled = self.ttl_config.is_some();
        for t in templates {
            let arc_template = Arc::new(t.clone());
            let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
            if let Some(existing) = self.ipfix_options_templates.peek(&t.template_id) {
                if existing.template.as_ref() != t {
                    self.metrics.record_collision();
                }
            } else if self.ipfix_options_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.ipfix_options_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_v9_templates(&mut self, templates: &[V9Template]) {
        let ttl_enabled = self.ttl_config.is_some();
        for t in templates {
            let arc_template = Arc::new(t.clone());
            let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
            if let Some(existing) = self.v9_templates.peek(&t.template_id) {
                if existing.template.as_ref() != t {
                    self.metrics.record_collision();
                }
            } else if self.v9_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.v9_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_v9_options_templates(&mut self, templates: &[V9OptionsTemplate]) {
        let ttl_enabled = self.ttl_config.is_some();
        for t in templates {
            let arc_template = Arc::new(t.clone());
            let wrapped = TemplateWithTtl::new(arc_template, ttl_enabled);
            if let Some(existing) = self.v9_options_templates.peek(&t.template_id) {
                if existing.template.as_ref() != t {
                    self.metrics.record_collision();
                }
            } else if self.v9_options_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.v9_options_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }
}

impl FlowSetBody {
    fn parse_templates<'a, T, F>(
        i: &'a [u8],
        parser: &mut IPFixParser,
        parse_fn: F,
        single_variant: fn(T) -> FlowSetBody,
        multi_variant: fn(Vec<T>) -> FlowSetBody,
        validate: fn(&T, &IPFixParser) -> bool,
        add_templates: fn(&mut IPFixParser, &[T]),
    ) -> IResult<&'a [u8], FlowSetBody>
    where
        T: Clone,
        F: Fn(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let (i, templates) = many0(complete(parse_fn))(i)?;
        if templates.is_empty() || templates.iter().any(|t| !validate(t, parser)) {
            return Err(nom::Err::Error(nom::error::Error::new(
                i,
                nom::error::ErrorKind::Verify,
            )));
        }
        // Pass slice to add_templates to clone only what's needed
        add_templates(parser, &templates);
        match templates.len() {
            1 => {
                if let Some(template) = templates.into_iter().next() {
                    Ok((i, single_variant(template)))
                } else {
                    Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            }
            _ => Ok((i, multi_variant(templates))),
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
            ),
            DATA_TEMPLATE_V9_ID => Self::parse_templates(
                i,
                parser,
                V9Template::parse,
                FlowSetBody::V9Template,
                FlowSetBody::V9Templates,
                |t: &V9Template, p: &IPFixParser| {
                    // Validate V9 templates using IPFIX parser limits
                    usize::from(t.field_count) <= p.max_field_count
                        && !t.fields.is_empty()
                        && t.fields.iter().any(|f| f.field_length > 0)
                        && usize::from(t.get_total_size()) <= p.max_template_total_size
                        && !t.has_duplicate_fields()
                },
                |parser, templates| parser.add_v9_templates(templates),
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
                        && usize::from(t.get_total_size()) <= p.max_template_total_size
                        && !t.has_duplicate_scope_fields()
                        && !t.has_duplicate_option_fields()
                },
                |parser, templates| parser.add_v9_options_templates(templates),
            ),
            OPTIONS_TEMPLATE_IPFIX_ID => Self::parse_templates(
                i,
                parser,
                OptionsTemplate::parse,
                FlowSetBody::OptionsTemplate,
                FlowSetBody::OptionsTemplates,
                |t: &OptionsTemplate, p: &IPFixParser| t.is_valid(p),
                |parser, templates| parser.add_ipfix_options_templates(templates),
            ),
            // Parse Data
            _ => {
                // Try IPFix templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    if template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    }
                    let (i, data) =
                        Data::parse_with_registry(i, &template, &parser.enterprise_registry)?;
                    return Ok((i, FlowSetBody::Data(data)));
                }

                // Try IPFix options templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.ipfix_options_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    if template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    }
                    let (i, data) = OptionsData::parse_with_registry(
                        i,
                        &template,
                        &parser.enterprise_registry,
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
                    let (i, data) = V9Data::parse(i, &template)?;
                    return Ok((i, FlowSetBody::V9Data(data)));
                }

                // Try V9 options templates
                if let Some(template) = crate::variable_versions::get_valid_template(
                    &mut parser.v9_options_templates,
                    &id,
                    &parser.ttl_config,
                    &mut parser.metrics,
                ) {
                    let (i, data) = V9OptionsData::parse(i, &template)?;
                    return Ok((i, FlowSetBody::V9OptionsData(data)));
                }

                // Template not found or expired
                parser.metrics.record_miss();
                if id > 255 {
                    // Store full raw data only when the pending cache is
                    // enabled, the entry fits the size limit, AND the
                    // per-template cap has room.  Otherwise truncate to
                    // max_error_sample_size to avoid large allocations
                    // that would be immediately rejected.
                    let (raw_data, truncated) =
                        if parser.pending_flows.as_ref().is_some_and(|c| {
                            i.len() <= c.max_entry_size_bytes() && c.would_accept(id)
                        }) {
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
                    Ok((i, FlowSetBody::NoTemplate(info)))
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

impl Data {
    /// Parse Data using the enterprise registry to resolve custom enterprise fields
    pub(super) fn parse_with_registry<'a>(
        i: &'a [u8],
        template: &Template,
        registry: &EnterpriseFieldRegistry,
    ) -> IResult<&'a [u8], Self> {
        let (i, fields) = FieldParser::parse_with_registry(i, template, registry)?;
        Ok((
            i,
            Self {
                fields,
                padding: vec![],
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
    ) -> IResult<&'a [u8], Self> {
        let (i, fields) = FieldParser::parse_with_registry(i, template, registry)?;
        Ok((
            i,
            Self {
                fields,
                padding: vec![],
            },
        ))
    }
}

impl<'a> FieldParser {
    /// Takes a byte stream and a cached template.
    /// Fields get matched to static types.
    /// Returns BTree of IPFix Types & Fields or IResult Error.
    pub(super) fn parse<T: CommonTemplate>(
        mut i: &'a [u8],
        template: &T,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>> {
        let template_fields = template.get_fields();
        if template_fields.is_empty() {
            return Ok((i, Vec::new()));
        }

        // Estimate capacity based on input size and template field count.
        // Skip variable-length fields (field_length == 65535) which are just
        // markers, not actual sizes.
        let template_size: usize = template_fields
            .iter()
            .filter(|f| f.field_length != 65535)
            .map(|f| usize::from(f.field_length))
            .sum();
        let estimated_records = if template_size > 0 {
            (i.len() / template_size).min(1024)
        } else {
            0
        };
        let mut res = Vec::with_capacity(estimated_records);

        // Try to parse as much as we can, but if it fails, just return what we have so far.
        while !i.is_empty() {
            let before = i;
            let mut vec = Vec::with_capacity(template_fields.len());
            for field in template_fields.iter() {
                match field.parse_as_field_value(i) {
                    Ok((remaining, field_value)) => {
                        vec.push((field.field_type, field_value));
                        i = remaining;
                    }
                    Err(_) => {
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

    /// Same as parse but uses the enterprise registry to resolve custom enterprise fields
    fn parse_with_registry<T: CommonTemplate>(
        mut i: &'a [u8],
        template: &T,
        registry: &EnterpriseFieldRegistry,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>> {
        let template_fields = template.get_fields();
        if template_fields.is_empty() {
            return Ok((i, Vec::new()));
        }

        // Estimate capacity based on input size and template field count.
        // Skip variable-length fields (field_length == 65535) which are just
        // markers, not actual sizes.
        let template_size: usize = template_fields
            .iter()
            .filter(|f| f.field_length != 65535)
            .map(|f| usize::from(f.field_length))
            .sum();
        let estimated_records = if template_size > 0 {
            (i.len() / template_size).min(1024)
        } else {
            0
        };
        let mut res = Vec::with_capacity(estimated_records);

        // Try to parse as much as we can, but if it fails, just return what we have so far.
        while !i.is_empty() {
            let before = i;
            let mut vec = Vec::with_capacity(template_fields.len());
            for field in template_fields.iter() {
                match field.parse_as_field_value_with_registry(i, registry) {
                    Ok((remaining, field_value)) => {
                        vec.push((field.field_type, field_value));
                        i = remaining;
                    }
                    Err(_) => {
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
                    // Validate length doesn't exceed remaining buffer
                    // Note: full_length is u16, so max is 65535 (u16::MAX)
                    if (full_length as usize) > i.len() {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            i,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                    Ok((i, full_length))
                } else {
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
