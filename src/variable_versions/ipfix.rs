//! # IPFix
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::data_number::FieldValue;
use super::enterprise_registry::EnterpriseFieldRegistry;
use super::metrics::CacheMetrics;
use super::ttl::{TemplateWithTtl, TtlConfig};
use super::{Config, ParserConfig};
use crate::variable_versions::ConfigError;
use crate::variable_versions::ipfix_lookup::IPFixField;
use crate::{NetflowError, NetflowPacket, ParsedNetflow};

use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::complete;
use nom::combinator::map_res;
use nom::multi::{count, many0};
use nom::number::complete::{be_u8, be_u16};
use nom_derive::{Nom, Parse};
use serde::Serialize;

use crate::variable_versions::v9::{
    DATA_TEMPLATE_V9_ID, Data as V9Data, OPTIONS_TEMPLATE_V9_ID, OptionsData as V9OptionsData,
    OptionsTemplate as V9OptionsTemplate, ScopeDataField as V9ScopeDataField,
    Template as V9Template,
};

use lru::LruCache;
use std::num::NonZeroUsize;

const DATA_TEMPLATE_IPFIX_ID: u16 = 2;
const OPTIONS_TEMPLATE_IPFIX_ID: u16 = 3;

/// Default maximum number of templates to cache per parser
pub const DEFAULT_MAX_TEMPLATE_CACHE_SIZE: usize = 1000;

/// Default maximum number of fields allowed per template to prevent DoS attacks
/// A reasonable limit that should accommodate legitimate use cases
/// This can be configured per-parser via the Config struct
pub const MAX_FIELD_COUNT: u16 = 10000;

type TemplateId = u16;
pub type IPFixFieldPair = (IPFixField, FieldValue);
pub type IpFixFlowRecord = Vec<IPFixFieldPair>;

/// Calculate padding needed to align to 4-byte boundary.
/// Returns a Vec of zero bytes with the appropriate length.
fn calculate_padding(content_size: usize) -> Vec<u8> {
    const PADDING_SIZES: [usize; 4] = [0, 3, 2, 1];
    let padding_len = PADDING_SIZES[content_size % 4];
    vec![0u8; padding_len]
}

#[derive(Debug)]
pub struct IPFixParser {
    pub templates: LruCache<TemplateId, TemplateWithTtl<Template>>,
    pub v9_templates: LruCache<TemplateId, TemplateWithTtl<V9Template>>,
    pub ipfix_options_templates: LruCache<TemplateId, TemplateWithTtl<OptionsTemplate>>,
    pub v9_options_templates: LruCache<TemplateId, TemplateWithTtl<V9OptionsTemplate>>,
    /// Optional TTL configuration for template expiration
    pub ttl_config: Option<TtlConfig>,
    /// Maximum number of templates to cache. Defaults to 1000.
    pub max_template_cache_size: usize,
    /// Maximum number of fields allowed per template. Defaults to 10000.
    pub max_field_count: usize,
    /// Maximum number of bytes to include in error samples to prevent memory exhaustion.
    /// Defaults to 256 bytes.
    pub max_error_sample_size: usize,
    /// Registry of custom enterprise field definitions
    pub enterprise_registry: EnterpriseFieldRegistry,
    /// Cache performance metrics
    pub metrics: CacheMetrics,
}

impl Default for IPFixParser {
    fn default() -> Self {
        // Safe to unwrap because DEFAULT_MAX_TEMPLATE_CACHE_SIZE is non-zero
        let config = Config {
            max_template_cache_size: DEFAULT_MAX_TEMPLATE_CACHE_SIZE,
            max_field_count: usize::from(MAX_FIELD_COUNT),
            ttl_config: None,
            enterprise_registry: EnterpriseFieldRegistry::new(),
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

        Ok(Self {
            templates: LruCache::new(cache_size),
            v9_templates: LruCache::new(cache_size),
            ipfix_options_templates: LruCache::new(cache_size),
            v9_options_templates: LruCache::new(cache_size),
            ttl_config: config.ttl_config,
            max_template_cache_size: config.max_template_cache_size,
            max_field_count: config.max_field_count,
            max_error_sample_size: 256,
            enterprise_registry: config.enterprise_registry,
            metrics: CacheMetrics::new(),
        })
    }
}

impl ParserConfig for IPFixParser {
    /// Add or update the parser's configuration.
    /// # Arguments
    /// * `config` - Configuration struct containing max_template_cache_size and optional ttl_config
    /// # Errors
    /// Returns `ConfigError` if `max_template_cache_size` is 0
    fn add_config(&mut self, config: Config) -> Result<(), ConfigError> {
        self.max_template_cache_size = config.max_template_cache_size;
        self.max_field_count = config.max_field_count;
        self.ttl_config = config.ttl_config;

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

    fn resize_template_caches(&mut self, cache_size: NonZeroUsize) {
        self.templates.resize(cache_size);
        self.v9_templates.resize(cache_size);
        self.ipfix_options_templates.resize(cache_size);
        self.v9_options_templates.resize(cache_size);
    }
}

impl IPFixParser {
    pub fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match IPFix::parse(packet, self) {
            Ok((remaining, ipfix)) => ParsedNetflow::Success {
                packet: NetflowPacket::IPFix(ipfix),
                remaining,
            },
            Err(e) => ParsedNetflow::Error {
                error: NetflowError::Partial {
                    message: format!("IPFIX parse error: {}", e),
                    offset: 0,
                },
            },
        }
    }

    /// Add templates to the parser by cloning from slice.
    fn add_ipfix_templates(&mut self, templates: &[Template]) {
        for t in templates {
            let wrapped = TemplateWithTtl::new(t.clone());
            // Check for collision (replacing existing template)
            if self.templates.contains(&t.template_id) {
                self.metrics.record_collision();
            }
            // Check if we're evicting an old template
            else if self.templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_ipfix_options_templates(&mut self, templates: &[OptionsTemplate]) {
        for t in templates {
            let wrapped = TemplateWithTtl::new(t.clone());
            // Check for collision (replacing existing template)
            if self.ipfix_options_templates.contains(&t.template_id) {
                self.metrics.record_collision();
            }
            // Check if we're evicting an old template
            else if self.ipfix_options_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.ipfix_options_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_v9_templates(&mut self, templates: &[V9Template]) {
        for t in templates {
            let wrapped = TemplateWithTtl::new(t.clone());
            // Check for collision (replacing existing template)
            if self.v9_templates.contains(&t.template_id) {
                self.metrics.record_collision();
            }
            // Check if we're evicting an old template
            else if self.v9_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.v9_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }

    fn add_v9_options_templates(&mut self, templates: &[V9OptionsTemplate]) {
        for t in templates {
            let wrapped = TemplateWithTtl::new(t.clone());
            // Check for collision (replacing existing template)
            if self.v9_options_templates.contains(&t.template_id) {
                self.metrics.record_collision();
            }
            // Check if we're evicting an old template
            else if self.v9_options_templates.len() >= self.max_template_cache_size {
                self.metrics.record_eviction();
            }
            self.v9_options_templates.put(t.template_id, wrapped);
            self.metrics.record_insertion();
        }
    }
}

#[derive(Nom, Debug, PartialEq, Clone, Serialize)]
#[nom(ExtraArgs(parser: &mut IPFixParser))]
pub struct IPFix {
    /// IPFix Header
    pub header: Header,
    /// Sets
    #[nom(
        PreExec = "let length = header.length.saturating_sub(16);",
        Parse = "map_res(take(length), |i| {
            many0(complete(|i| FlowSet::parse(i, parser)
                .map(|(i, flow_set)| (i, flow_set))
            ))(i)
            .map(|(_, flow_sets)| flow_sets) // Extract the Vec<FlowSet>
        })"
    )]
    pub flowsets: Vec<FlowSet>,
}

/// Information about a data flowset that couldn't be parsed due to missing template.
///
/// This provides context to help diagnose template-related issues.
#[derive(Debug, Clone, Serialize)]
pub struct NoTemplateInfo {
    /// The template ID that was requested but not found
    pub template_id: u16,
    /// List of currently available template IDs in the cache
    pub available_templates: Vec<u16>,
    /// The unparsed flowset data (for potential retry after template arrives)
    pub raw_data: Vec<u8>,
}

impl NoTemplateInfo {
    /// Create a new NoTemplateInfo with the given template ID and raw data
    pub fn new(template_id: u16, raw_data: Vec<u8>) -> Self {
        Self {
            template_id,
            available_templates: Vec::new(),
            raw_data,
        }
    }

    /// Create a NoTemplateInfo with available templates from the parser
    pub fn with_available_templates(
        template_id: u16,
        raw_data: Vec<u8>,
        parser: &IPFixParser,
    ) -> Self {
        let mut available = Vec::new();

        // Collect all template IDs
        for (id, _) in parser.templates.iter() {
            available.push(*id);
        }
        for (id, _) in parser.v9_templates.iter() {
            available.push(*id);
        }
        for (id, _) in parser.ipfix_options_templates.iter() {
            available.push(*id);
        }
        for (id, _) in parser.v9_options_templates.iter() {
            available.push(*id);
        }

        available.sort_unstable();
        available.dedup();

        Self {
            template_id,
            available_templates: available,
            raw_data,
        }
    }
}

impl PartialEq for NoTemplateInfo {
    fn eq(&self, other: &Self) -> bool {
        self.template_id == other.template_id && self.raw_data == other.raw_data
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum FlowSetBody {
    Template(Template),
    Templates(Vec<Template>),
    V9Template(V9Template),
    V9Templates(Vec<V9Template>),
    OptionsTemplate(OptionsTemplate),
    OptionsTemplates(Vec<OptionsTemplate>),
    V9OptionsTemplate(V9OptionsTemplate),
    V9OptionsTemplates(Vec<V9OptionsTemplate>),
    Data(Data),
    OptionsData(OptionsData),
    V9Data(V9Data),
    V9OptionsData(V9OptionsData),
    NoTemplate(NoTemplateInfo),
    Empty,
}

/// Parses a FlowSetBody from the input byte slice based on the provided flowset ID.
///
/// The behavior of this function depends on the value of `id`:
/// - If `id` is less than a defined minimum range and not equal to `OPTIONS_TEMPLATE_ID`, it treats
///   the input as a regular template:
///   - The template is parsed using `Template::parse`.
///   - If the parsed template is invalid, an error is returned.
///   - The valid template is stored in the parser's template map before being returned as a `FlowSetBody::Template`.
/// - If `id` equals `OPTIONS_TEMPLATE_ID`, it treats the input as an options template:
///   - The options template is parsed using `OptionsTemplate::parse`.
///   - An invalid options template results in an error.
///   - The valid options template is stored in the parser's options template map and returned as a `FlowSetBody::OptionsTemplate`.
/// - If `id` is already registered in the parser's template map, the input is interpreted as data for that template:
///   - It is parsed using `Data::parse` and returned as `FlowSetBody::Data`.
/// - If `id` is registered in the parser's options template map, the input is interpreted as options data:
///   - It is parsed using `OptionsData::parse` and returned as `FlowSetBody::OptionsData`.
/// - Otherwise, if none of the conditions match, the function returns an error indicating a verification failure.
///
/// # Parameters
///
/// - `i`: A byte slice (`&[u8]`) representing the input data to be parsed.
/// - `parser`: A mutable reference to an `IPFixParser` instance, which maintains the state including
///   registered templates and options templates.
/// - `id`: A 16-bit unsigned integer (`u16`) representing the identifier for the flowset to be parsed.
///
/// # Returns
///
/// Returns a `nom::IResult` wrapping a tuple of:
/// - The remaining byte slice after parsing.
/// - A `FlowSetBody` instance representing the parsed flowset, which may be a Template, OptionsTemplate,
///   Data, or OptionsData.
///
/// In case of any parsing or validation error, a `nom::Err::Error` is returned with an appropriate error kind.
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

    fn parse<'a>(
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
                |_t: &V9Template, _p: &IPFixParser| true,
                |parser, templates| parser.add_v9_templates(templates),
            ),
            OPTIONS_TEMPLATE_V9_ID => Self::parse_templates(
                i,
                parser,
                V9OptionsTemplate::parse,
                FlowSetBody::V9OptionsTemplate,
                FlowSetBody::V9OptionsTemplates,
                |_t: &V9OptionsTemplate, _p: &IPFixParser| true,
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
                if let Some(wrapped_template) = parser.templates.get(&id) {
                    parser.metrics.record_hit();
                    // Check TTL if configured
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            parser.templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else if wrapped_template.template.get_fields().is_empty() {
                            return Ok((i, FlowSetBody::Empty));
                        } else {
                            let (i, data) = Data::parse_with_registry(
                                i,
                                &wrapped_template.template,
                                &parser.enterprise_registry,
                            )?;
                            return Ok((i, FlowSetBody::Data(data)));
                        }
                    } else if wrapped_template.template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    } else {
                        let (i, data) = Data::parse_with_registry(
                            i,
                            &wrapped_template.template,
                            &parser.enterprise_registry,
                        )?;
                        return Ok((i, FlowSetBody::Data(data)));
                    }
                }

                // Try IPFix options templates
                if let Some(wrapped_template) = parser.ipfix_options_templates.get(&id) {
                    parser.metrics.record_hit();
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            parser.ipfix_options_templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else if wrapped_template.template.get_fields().is_empty() {
                            return Ok((i, FlowSetBody::Empty));
                        } else {
                            let (i, data) = OptionsData::parse_with_registry(
                                i,
                                &wrapped_template.template,
                                &parser.enterprise_registry,
                            )?;
                            return Ok((i, FlowSetBody::OptionsData(data)));
                        }
                    } else if wrapped_template.template.get_fields().is_empty() {
                        return Ok((i, FlowSetBody::Empty));
                    } else {
                        let (i, data) = OptionsData::parse_with_registry(
                            i,
                            &wrapped_template.template,
                            &parser.enterprise_registry,
                        )?;
                        return Ok((i, FlowSetBody::OptionsData(data)));
                    }
                }

                // Try V9 templates
                if let Some(wrapped_template) = parser.v9_templates.get(&id) {
                    parser.metrics.record_hit();
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            parser.v9_templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else {
                            let (i, data) = V9Data::parse(i, &wrapped_template.template)?;
                            return Ok((i, FlowSetBody::V9Data(data)));
                        }
                    } else {
                        let (i, data) = V9Data::parse(i, &wrapped_template.template)?;
                        return Ok((i, FlowSetBody::V9Data(data)));
                    }
                }

                // Try V9 options templates
                if let Some(wrapped_template) = parser.v9_options_templates.get(&id) {
                    parser.metrics.record_hit();
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            parser.v9_options_templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else {
                            let (i, data) =
                                V9OptionsData::parse(i, &wrapped_template.template)?;
                            return Ok((i, FlowSetBody::V9OptionsData(data)));
                        }
                    } else {
                        let (i, data) = V9OptionsData::parse(i, &wrapped_template.template)?;
                        return Ok((i, FlowSetBody::V9OptionsData(data)));
                    }
                }

                // Template not found or expired
                parser.metrics.record_miss();
                if id > 255 {
                    let info = NoTemplateInfo::with_available_templates(id, i.to_vec(), parser);
                    Ok((i, FlowSetBody::NoTemplate(info)))
                } else {
                    Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// Version of Flow Record format that is exported in this message. The value of this
    /// field is 0x000a for the current version, incrementing by one the version that is
    /// used in the NetFlow services export version 9
    #[nom(Value = "10")]
    pub version: u16,
    /// Total length of the IPFIX Message, which is measured in octets, including Message
    /// Header and Sets.
    pub length: u16,
    /// Time, in seconds, since 0000 Coordinated Universal Time Jan 1, 1970, at which the
    /// IPFIX Message Header leaves the Exporter.
    pub export_time: u32,
    /// Incremental sequence counter-modulo 2^32 of all IPFIX Data Records sent on this PR-SCTP
    /// stream from the current Observation Domain by the Exporting Process. Check the specific
    /// meaning of this field in the subsections of Section 10 when UDP or TCP is selected as the
    /// transport protocol. This value must be used by the Collecting Process to identify whether
    /// any IPFIX Data Records are missed. Template and Options Template Records do not increase
    /// the Sequence Number.
    pub sequence_number: u32,
    /// A 32-bit identifier of the Observation Domain that is locally unique to the Exporting Process.
    /// The Exporting Process uses the Observation Domain ID to uniquely identify to the Collector.
    /// Process the Observation Domain that metered the Flows. It is recommended that this identifier
    /// is unique per IPFIX Device. Collecting Processes must use the Transport Session.  Observation
    /// Domain ID field to separate different export streams that originate from the same Exporting Process.
    /// The Observation Domain ID must be 0 when no specific Observation Domain ID is relevant for the
    /// entire IPFIX Message. For example, when the Exporting Process Statistics are exported, or in a hierarchy
    /// of Collectors when aggregated Data Records are exported.
    pub observation_domain_id: u32,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser))]
pub struct FlowSet {
    pub header: FlowSetHeader,
    #[nom(
        PreExec = "let length = header.length.saturating_sub(4);",
        Parse = "map_res(take(length),
                  |i| FlowSetBody::parse(i, parser, header.header_id)
                      .map(|(_, flow_set)| flow_set))"
    )]
    pub body: FlowSetBody,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct FlowSetHeader {
    /// Set ID value identifies the Set. A value of 2 is reserved for the Template Set.
    /// A value of 3 is reserved for the Option Template Set. All other values 4-255 are
    /// reserved for future use. Values more than 255 are used for Data Sets. The Set ID
    /// values of 0 and 1 are not used for historical reasons
    pub header_id: u16,
    /// Total length of the Set, in octets, including the Set Header, all records, and the
    /// optional padding. Because an individual Set MAY contain multiple records, the Length
    /// value must be used to determine the position of the next Set.
    pub length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &Template))]
pub struct Data {
    #[nom(
        ErrorIf = "template.get_fields().is_empty() ",
        Parse = "{ |i| FieldParser::parse::<Template>(i, template) }"
    )]
    pub fields: Vec<IpFixFlowRecord>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

impl Data {
    /// Creates a new Data instance with the given fields.
    /// The padding field is automatically set to an empty vector and will be
    /// calculated during export for manually created packets.
    pub fn new(fields: Vec<IpFixFlowRecord>) -> Self {
        Self {
            fields,
            padding: vec![],
        }
    }

    /// Parse Data using the enterprise registry to resolve custom enterprise fields
    fn parse_with_registry<'a>(
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

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &OptionsTemplate))]
pub struct OptionsData {
    #[nom(
        ErrorIf = "template.get_fields().is_empty() ",
        Parse = "{ |i| FieldParser::parse::<OptionsTemplate>(i, template) }"
    )]
    pub fields: Vec<Vec<IPFixFieldPair>>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

impl OptionsData {
    /// Creates a new OptionsData instance with the given fields.
    /// The padding field is automatically set to an empty vector and will be
    /// calculated during export for manually created packets.
    pub fn new(fields: Vec<Vec<IPFixFieldPair>>) -> Self {
        Self {
            fields,
            padding: vec![],
        }
    }

    /// Parse OptionsData using the enterprise registry to resolve custom enterprise fields
    fn parse_with_registry<'a>(
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

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    #[nom(
        PreExec = "let combined_count = usize::from(field_count);",
        Parse = "count(TemplateField::parse, combined_count)"
    )]
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom, Default)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    #[nom(Count = "field_count")]
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct TemplateField {
    #[nom(
        PostExec = "let (field_type_number, is_enterprise) = if field_type_number > 32767 {
                        (field_type_number.overflowing_sub(32768).0, true)
                     } else { (field_type_number, false) };"
    )]
    pub field_type_number: u16,
    pub field_length: u16,
    #[nom(Cond = "is_enterprise")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_number: Option<u32>,
    #[nom(Value(IPFixField::new(field_type_number, enterprise_number)))]
    pub field_type: IPFixField,
}

// Common trait for both templates.  Mainly for fetching fields.
trait CommonTemplate {
    fn get_fields(&self) -> &Vec<TemplateField>;
    fn get_field_count(&self) -> u16;
    fn get_scope_field_count(&self) -> Option<u16> {
        None
    }

    fn is_valid(&self, parser: &IPFixParser) -> bool {
        // Check field count doesn't exceed maximum
        if usize::from(self.get_field_count()) > parser.max_field_count {
            return false;
        }
        // Check scope field count if applicable
        if let Some(scope_count) = self.get_scope_field_count()
            && scope_count > self.get_field_count()
        {
            return false;
        }
        // Check fields are not empty and have at least one non-zero length field
        !self.get_fields().is_empty() && self.get_fields().iter().any(|f| f.field_length > 0)
    }
}

impl CommonTemplate for Template {
    fn get_fields(&self) -> &Vec<TemplateField> {
        &self.fields
    }

    fn get_field_count(&self) -> u16 {
        self.field_count
    }
}

impl CommonTemplate for OptionsTemplate {
    fn get_fields(&self) -> &Vec<TemplateField> {
        &self.fields
    }

    fn get_field_count(&self) -> u16 {
        self.field_count
    }

    fn get_scope_field_count(&self) -> Option<u16> {
        Some(self.scope_field_count)
    }
}

pub struct FieldParser;

impl<'a> FieldParser {
    /// Takes a byte stream and a cached template.
    /// Fields get matched to static types.
    /// Returns BTree of IPFix Types & Fields or IResult Error.
    fn parse<T: CommonTemplate>(
        mut i: &'a [u8],
        template: &T,
    ) -> IResult<&'a [u8], Vec<Vec<IPFixFieldPair>>> {
        let template_fields = template.get_fields();
        if template_fields.is_empty() {
            return Ok((i, Vec::new()));
        }

        // Estimate capacity based on input size and template field count
        let template_size: usize = template_fields
            .iter()
            .map(|f| usize::from(f.field_length))
            .sum();
        let estimated_records = if template_size > 0 {
            i.len() / template_size
        } else {
            0
        };
        let mut res = Vec::with_capacity(estimated_records);

        // Try to parse as much as we can, but if it fails, just return what we have so far.
        while !i.is_empty() {
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

        // Estimate capacity based on input size and template field count
        let template_size: usize = template_fields
            .iter()
            .map(|f| usize::from(f.field_length))
            .sum();
        let estimated_records = if template_size > 0 {
            i.len() / template_size
        } else {
            0
        };
        let mut res = Vec::with_capacity(estimated_records);

        // Try to parse as much as we can, but if it fails, just return what we have so far.
        while !i.is_empty() {
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

impl IPFix {
    /// Convert the IPFix to a `Vec<u8>` of bytes in big-endian order for exporting
    pub fn to_be_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();

        result.extend_from_slice(&self.header.version.to_be_bytes());
        result.extend_from_slice(&self.header.length.to_be_bytes());
        result.extend_from_slice(&self.header.export_time.to_be_bytes());
        result.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        result.extend_from_slice(&self.header.observation_domain_id.to_be_bytes());

        for flow in &self.flowsets {
            result.extend_from_slice(&flow.header.header_id.to_be_bytes());
            result.extend_from_slice(&flow.header.length.to_be_bytes());

            let mut result_flowset = vec![];

            if let FlowSetBody::Template(template) = &flow.body {
                result_flowset.extend_from_slice(&template.template_id.to_be_bytes());
                result_flowset.extend_from_slice(&template.field_count.to_be_bytes());

                for field in template.fields.iter() {
                    result_flowset.extend_from_slice(&field.field_type_number.to_be_bytes());
                    result_flowset.extend_from_slice(&field.field_length.to_be_bytes());
                    if let Some(enterprise) = field.enterprise_number {
                        result_flowset.extend_from_slice(&enterprise.to_be_bytes());
                    }
                }
            }

            if let FlowSetBody::Templates(templates) = &flow.body {
                for template in templates.iter() {
                    result_flowset.extend_from_slice(&template.template_id.to_be_bytes());
                    result_flowset.extend_from_slice(&template.field_count.to_be_bytes());

                    for field in template.fields.iter() {
                        result_flowset
                            .extend_from_slice(&field.field_type_number.to_be_bytes());
                        result_flowset.extend_from_slice(&field.field_length.to_be_bytes());
                        if let Some(enterprise) = field.enterprise_number {
                            result_flowset.extend_from_slice(&enterprise.to_be_bytes());
                        }
                    }
                }
            }

            if let FlowSetBody::V9Template(template) = &flow.body {
                result.extend_from_slice(&template.template_id.to_be_bytes());
                result.extend_from_slice(&template.field_count.to_be_bytes());
                for field in template.fields.iter() {
                    result.extend_from_slice(&field.field_type_number.to_be_bytes());
                    result.extend_from_slice(&field.field_length.to_be_bytes());
                }
            }

            if let FlowSetBody::OptionsTemplate(options_template) = &flow.body {
                result_flowset.extend_from_slice(&options_template.template_id.to_be_bytes());
                result_flowset.extend_from_slice(&options_template.field_count.to_be_bytes());
                result_flowset
                    .extend_from_slice(&options_template.scope_field_count.to_be_bytes());

                for field in options_template.fields.iter() {
                    result_flowset.extend_from_slice(&field.field_type_number.to_be_bytes());
                    result_flowset.extend_from_slice(&field.field_length.to_be_bytes());
                    if let Some(enterprise) = field.enterprise_number {
                        result_flowset.extend_from_slice(&enterprise.to_be_bytes());
                    }
                }
            }

            if let FlowSetBody::V9OptionsTemplate(template) = &flow.body {
                result.extend_from_slice(&template.template_id.to_be_bytes());
                result.extend_from_slice(&template.options_scope_length.to_be_bytes());
                result.extend_from_slice(&template.options_length.to_be_bytes());
                for field in template.scope_fields.iter() {
                    result.extend_from_slice(&field.field_type_number.to_be_bytes());
                    result.extend_from_slice(&field.field_length.to_be_bytes());
                }
                for field in template.option_fields.iter() {
                    result.extend_from_slice(&field.field_type_number.to_be_bytes());
                    result.extend_from_slice(&field.field_length.to_be_bytes());
                }
            }

            if let FlowSetBody::Data(data) = &flow.body {
                let mut data_content = Vec::new();
                for item in data.fields.iter() {
                    for (_, v) in item.iter() {
                        data_content.extend_from_slice(&v.to_be_bytes()?);
                    }
                }
                result_flowset.extend_from_slice(&data_content);

                // Auto-calculate padding if not provided (for manually created packets)
                let padding = if data.padding.is_empty() {
                    calculate_padding(data_content.len())
                } else {
                    data.padding.clone()
                };
                result_flowset.extend_from_slice(&padding);
            }

            if let FlowSetBody::OptionsData(data) = &flow.body {
                let mut options_data_content = Vec::new();
                for item in data.fields.iter() {
                    for (_, v) in item.iter() {
                        options_data_content.extend_from_slice(&v.to_be_bytes()?);
                    }
                }
                result_flowset.extend_from_slice(&options_data_content);

                // Auto-calculate padding if not provided (for manually created packets)
                let padding = if data.padding.is_empty() {
                    calculate_padding(options_data_content.len())
                } else {
                    data.padding.clone()
                };
                result_flowset.extend_from_slice(&padding);
            }

            if let FlowSetBody::V9Data(data) = &flow.body {
                for item in data.fields.iter() {
                    for (_, v) in item.iter() {
                        result_flowset.extend_from_slice(&v.to_be_bytes()?);
                    }
                }
            }

            if let FlowSetBody::V9OptionsData(options_data) = &flow.body {
                for options_data_field in options_data.fields.iter() {
                    for field in options_data_field.scope_fields.iter() {
                        match field {
                            V9ScopeDataField::System(value) => {
                                result.extend_from_slice(value);
                            }
                            V9ScopeDataField::Interface(value) => {
                                result.extend_from_slice(value);
                            }
                            V9ScopeDataField::LineCard(value) => {
                                result.extend_from_slice(value);
                            }
                            V9ScopeDataField::NetFlowCache(value) => {
                                result.extend_from_slice(value);
                            }
                            V9ScopeDataField::Template(value) => {
                                result.extend_from_slice(value);
                            }
                        }
                    }
                    for options_field in options_data_field.options_fields.iter() {
                        for (_field_type, field_value) in options_field.iter() {
                            result.extend_from_slice(&field_value.to_be_bytes()?);
                        }
                    }
                }
            }

            result.append(&mut result_flowset);
        }

        Ok(result)
    }
}
