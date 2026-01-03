//! # Netflow V9
//!
//! References:
//! - <https://www.ietf.org/rfc/rfc3954.txt>
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use super::data_number::FieldValue;
use super::enterprise_registry::EnterpriseFieldRegistry;
use super::metrics::CacheMetrics;
use super::ttl::{TemplateWithTtl, TtlConfig};
use super::{Config, ConfigError, ParserConfig};
use crate::variable_versions::v9_lookup::{ScopeFieldType, V9Field};
use crate::{NetflowPacket, NetflowParseError, ParsedNetflow, PartialParse};

use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::complete;
use nom::combinator::map_res;
use nom::error::{Error as NomError, ErrorKind};
use nom::multi::many0;
use nom_derive::{Nom, Parse};
use serde::Serialize;

use lru::LruCache;
use std::num::NonZeroUsize;

pub const DATA_TEMPLATE_V9_ID: u16 = 0;
pub const OPTIONS_TEMPLATE_V9_ID: u16 = 1;

/// Default maximum number of templates to cache per parser
pub const DEFAULT_MAX_TEMPLATE_CACHE_SIZE: usize = 1000;

/// Default maximum number of fields allowed per template to prevent DoS attacks
/// A reasonable limit that should accommodate legitimate use cases
/// This can be configured per-parser via the Config struct
pub const MAX_FIELD_COUNT: u16 = 10000;

type TemplateId = u16;
pub type V9FieldPair = (V9Field, FieldValue);
pub type V9FlowRecord = Vec<V9FieldPair>;

/// Calculate padding needed to align to 4-byte boundary.
/// Returns a Vec of zero bytes with the appropriate length.
fn calculate_padding(content_size: usize) -> Vec<u8> {
    const PADDING_SIZES: [usize; 4] = [0, 3, 2, 1];
    let padding_len = PADDING_SIZES[content_size % 4];
    vec![0u8; padding_len]
}

#[derive(Debug)]
pub struct V9Parser {
    pub templates: LruCache<TemplateId, TemplateWithTtl<Template>>,
    pub options_templates: LruCache<TemplateId, TemplateWithTtl<OptionsTemplate>>,
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

impl Default for V9Parser {
    fn default() -> Self {
        // Safe to unwrap because DEFAULT_MAX_TEMPLATE_CACHE_SIZE is non-zero
        let config = Config {
            max_template_cache_size: DEFAULT_MAX_TEMPLATE_CACHE_SIZE,
            max_field_count: MAX_FIELD_COUNT as usize,
            ttl_config: None,
            enterprise_registry: super::enterprise_registry::EnterpriseFieldRegistry::new(),
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

        Ok(Self {
            templates: LruCache::new(cache_size),
            options_templates: LruCache::new(cache_size),
            ttl_config: config.ttl_config,
            max_template_cache_size: config.max_template_cache_size,
            max_field_count: config.max_field_count,
            max_error_sample_size: 256,
            enterprise_registry: config.enterprise_registry,
            metrics: CacheMetrics::new(),
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
        self.options_templates.resize(cache_size);
    }
}

impl V9Parser {
    pub fn parse<'a>(&mut self, packet: &'a [u8]) -> ParsedNetflow<'a> {
        match V9::parse(packet, self) {
            Ok((remaining, v9)) => ParsedNetflow::Success {
                packet: NetflowPacket::V9(v9),
                remaining,
            },
            Err(e) => {
                // Only include first N bytes to prevent memory exhaustion
                let remaining_sample = if packet.len() > self.max_error_sample_size {
                    packet[..self.max_error_sample_size].to_vec()
                } else {
                    packet.to_vec()
                };
                ParsedNetflow::Error {
                    error: NetflowParseError::Partial(PartialParse {
                        version: 9,
                        error: e.to_string(),
                        remaining: remaining_sample,
                    }),
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct V9 {
    /// V9 Header
    pub header: Header,
    /// Flowsets
    #[nom(Parse = "{ |i| FlowSetParser::parse_flowsets(i, parser, header.count) }")]
    pub flowsets: Vec<FlowSet>,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// The version of NetFlow records exported in this packet; for Version 9, this value is 9
    #[nom(Value = "9")]
    pub version: u16,
    /// Number of FlowSet records (both template and data) contained within this packet
    pub count: u16,
    /// Time in milliseconds since this device was first booted
    pub sys_up_time: u32,
    /// Seconds since 0000 Coordinated Universal Time (UTC) 1970
    pub unix_secs: u32,
    /// Incremental sequence counter of all export packets sent by this export device; this value is
    /// cumulative, and it can be used to identify whether any export packets have been missed.
    /// Note: This is a change from the NetFlow Version 5 and Version 8 headers, where this number
    /// represented "total flows."
    pub sequence_number: u32,
    /// The Source ID field is a 32-bit value that is used to guarantee uniqueness for all flows exported
    /// from a particular device. (The Source ID field is the equivalent of the engine type and engine ID
    /// fields found in the NetFlow Version 5 and Version 8 headers). The format of this field is vendor
    /// specific. In the Cisco implementation, the first two bytes are reserved for future expansion, and
    /// will always be zero. Byte 3 provides uniqueness with respect to the routing engine on the exporting
    /// device. Byte 4 provides uniqueness with respect to the particular line card or Versatile Interface
    /// Processor on the exporting device. Collector devices should use the combination of the source IP
    /// address plus the Source ID field to associate an incoming NetFlow export packet with a unique
    /// instance of NetFlow on a particular device.
    pub source_id: u32,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct FlowSet {
    pub header: FlowSetHeader,
    #[nom(
        PreExec = "let length = header.length.saturating_sub(4);",
        Parse = "map_res(take(length),
                  |i| FlowSetBody::parse(i, parser, header.flowset_id)
                      .map(|(_, flow_set)| flow_set))"
    )]
    pub body: FlowSetBody,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct FlowSetHeader {
    /// The FlowSet ID is used to distinguish template records from data records.
    /// A template record always has a FlowSet ID in the range of 0-255. Currently,
    /// the template record that describes flow fields has a FlowSet ID of zero and
    /// the template record that describes option fields (described below) has a
    /// FlowSet ID of 1. A data record always has a nonzero FlowSet ID greater than 255.
    pub flowset_id: u16,
    /// This field gives the length of the data FlowSet. Length is expressed in TLV format,
    /// meaning that the value includes the bytes used for the FlowSet ID and the length bytes
    /// themselves, as well as the combined lengths of any included data records.
    pub length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum FlowSetBody {
    Template(Templates),
    OptionsTemplate(OptionsTemplates),
    Data(Data),
    OptionsData(OptionsData),
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct Templates {
    pub templates: Vec<Template>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct OptionsTemplates {
    pub templates: Vec<OptionsTemplate>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

/// Parses a FlowSetBody from a provided byte slice, updating the parser state as needed.
///
/// This function examines the given identifier (`id`) to determine the type of flowset to parse.
/// It handles multiple cases based on the value of `id`:
///
/// 1. If `id` equals `TEMPLATE_ID`:
///    - It parses a collection of templates using `Templates::parse`.
///    - Each parsed template is added to the parser's `templates` collection.
///    - Returns a `FlowSetBody::Template` variant wrapping the parsed templates.
///
/// 2. If `id` equals `OPTIONS_TEMPLATE_ID`:
///    - It parses a collection of options templates using `OptionsTemplates::parse`.
///    - Each parsed template is added to the parser's `options_templates` collection.
///    - Returns a `FlowSetBody::OptionsTemplate` variant wrapping the parsed options templates.
///
/// 3. If the parser's `options_templates` already contains the `id`:
///    - It parses options data using `OptionsData::parse`.
///    - Returns a `FlowSetBody::OptionsData` variant wrapping the parsed options data.
///
/// 4. If the parser's `templates` already contains the `id`:
///    - It parses standard data using `Data::parse`.
///    - Returns a `FlowSetBody::Data` variant wrapping the parsed data.
///
/// 5. If none of these cases apply:
///    - The function returns a parsing error with a verification error kind.
///
/// # Parameters
///
/// - `i`: A byte slice containing the input data to be parsed.
/// - `parser`: A mutable reference to a `V9Parser` which maintains the state of parsed templates.
/// - `id`: The identifier that determines which parsing strategy is applied.
///
/// # Returns
///
/// An `IResult` containing:
/// - On success: A tuple of the remaining input slice and the parsed `FlowSetBody`.
/// - On failure: A `nom::Err` with an error kind indicating the failure (using `nom::error::ErrorKind::Verify`).
impl FlowSetBody {
    fn parse<'a>(
        i: &'a [u8],
        parser: &mut V9Parser,
        id: u16,
    ) -> IResult<&'a [u8], FlowSetBody> {
        match id {
            DATA_TEMPLATE_V9_ID => {
                let (i, templates) = Templates::parse(i)?;
                // Validate templates before storing
                if templates.templates.is_empty()
                    || templates.templates.iter().any(|t| !t.is_valid(parser))
                {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                // Store templates efficiently - clone only what we need to cache
                for template in &templates.templates {
                    let wrapped = TemplateWithTtl::new(template.clone());
                    // Check for collision (replacing existing template)
                    if parser.templates.contains(&template.template_id) {
                        parser.metrics.record_collision();
                    }
                    // Check if we're evicting an old template
                    else if parser.templates.len() >= parser.max_template_cache_size {
                        parser.metrics.record_eviction();
                    }
                    parser.templates.put(template.template_id, wrapped);
                    parser.metrics.record_insertion();
                }
                Ok((i, FlowSetBody::Template(templates)))
            }
            OPTIONS_TEMPLATE_V9_ID => {
                let (i, options_templates) = OptionsTemplates::parse(i)?;
                // Validate templates before storing
                if options_templates.templates.is_empty()
                    || options_templates
                        .templates
                        .iter()
                        .any(|t| !t.is_valid(parser))
                {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        i,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                // Store templates efficiently - clone only what we need to cache
                for template in &options_templates.templates {
                    let wrapped = TemplateWithTtl::new(template.clone());
                    // Check for collision (replacing existing template)
                    if parser.options_templates.contains(&template.template_id) {
                        parser.metrics.record_collision();
                    }
                    // Check if we're evicting an old template
                    else if parser.options_templates.len() >= parser.max_template_cache_size {
                        parser.metrics.record_eviction();
                    }
                    parser.options_templates.put(template.template_id, wrapped);
                    parser.metrics.record_insertion();
                }
                Ok((i, FlowSetBody::OptionsTemplate(options_templates)))
            }
            _ => {
                // Try to get template from regular templates cache
                if let Some(wrapped_template) = parser.templates.get(&id) {
                    parser.metrics.record_hit();
                    // Check TTL if configured
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            // Template expired, remove it and fall through to error
                            parser.templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else {
                            // Template valid, parse data
                            let (i, data) = Data::parse(i, &wrapped_template.template)?;
                            return Ok((i, FlowSetBody::Data(data)));
                        }
                    } else {
                        // No TTL configured, use template directly
                        let (i, data) = Data::parse(i, &wrapped_template.template)?;
                        return Ok((i, FlowSetBody::Data(data)));
                    }
                }

                // Try to get template from options templates cache
                if let Some(wrapped_template) = parser.options_templates.get(&id) {
                    parser.metrics.record_hit();
                    // Check TTL if configured
                    if let Some(ref config) = parser.ttl_config {
                        if wrapped_template.is_expired(config) {
                            // Template expired, remove it and fall through to error
                            parser.options_templates.pop(&id);
                            parser.metrics.record_expiration();
                        } else {
                            // Template valid, parse options data
                            let (i, options_data) =
                                OptionsData::parse(i, &wrapped_template.template)?;
                            return Ok((i, FlowSetBody::OptionsData(options_data)));
                        }
                    } else {
                        // No TTL configured, use template directly
                        let (i, options_data) =
                            OptionsData::parse(i, &wrapped_template.template)?;
                        return Ok((i, FlowSetBody::OptionsData(options_data)));
                    }
                }

                // Template not found or expired
                parser.metrics.record_miss();
                Err(nom::Err::Error(nom::error::Error::new(
                    i,
                    nom::error::ErrorKind::Verify,
                )))
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Default, Nom)]
pub struct Template {
    /// As a router generates different template FlowSets to match the type of NetFlow
    /// data it will be exporting, each template is given a unique ID. This uniqueness
    /// is local to the router that generated the template ID.
    /// Templates that define data record formats begin numbering at 256 since 0-255
    /// are reserved for FlowSet IDs.
    pub template_id: u16,
    /// This field gives the number of fields in this template record. Because a template
    /// FlowSet may contain multiple template records, this field allows the parser to
    /// determine the end of the current template record and the start of the next.
    pub field_count: u16,
    /// Template Fields.
    #[nom(Count = "field_count")]
    pub fields: Vec<TemplateField>,
}

impl Template {
    /// Validate the template against parser configuration
    pub fn is_valid(&self, parser: &V9Parser) -> bool {
        self.field_count as usize <= parser.max_field_count
    }

    /// Returns the total size of the template, including the header and all fields.
    pub fn get_total_size(&self) -> u16 {
        self.fields
            .iter()
            .fold(0, |acc, i| acc.saturating_add(i.field_length))
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Default, Nom)]
pub struct OptionsTemplate {
    /// As a router generates different template FlowSets to match the type of NetFlow data it is exporting, each template is given a unique ID. This uniqueness is local to the router that generated the template ID. The Template ID is greater than 255. Template IDs inferior to 255 are reserved.
    pub template_id: u16,
    /// This field gives the length in bytes of any scope fields that are contained in this options' template.
    pub options_scope_length: u16,
    /// This field gives the length (in bytes) of any Options field definitions that are contained in this options template
    pub options_length: u16,
    /// Options Scope Fields
    #[nom(Count = "usize::from(options_scope_length.checked_div(4).unwrap_or(0))")]
    pub scope_fields: Vec<OptionsTemplateScopeField>,
    /// Options Fields
    #[nom(Count = "usize::from(options_length.checked_div(4).unwrap_or(0))")]
    pub option_fields: Vec<TemplateField>,
}

impl OptionsTemplate {
    /// Validate the options template against parser configuration
    pub fn is_valid(&self, parser: &V9Parser) -> bool {
        let scope_count = usize::from(self.options_scope_length.checked_div(4).unwrap_or(0));
        let option_count = usize::from(self.options_length.checked_div(4).unwrap_or(0));
        scope_count <= parser.max_field_count && option_count <= parser.max_field_count
    }
}

/// Options Scope Fields
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct OptionsTemplateScopeField {
    pub field_type_number: u16,
    #[nom(Value(ScopeFieldType::from(field_type_number)))]
    pub field_type: ScopeFieldType,
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct TemplateField {
    /// This numeric value represents the type of the field. The possible values of the
    /// field type are vendor specific. Cisco supplied values are consistent across all
    /// platforms that support NetFlow Version 9.
    /// At the time of the initial release of the NetFlow Version 9 code (and after any
    /// subsequent changes that could add new field-type definitions), Cisco provides a file
    /// that defines the known field types and their lengths.
    /// The currently defined field types are detailed in Table 6.
    pub field_type_number: u16,
    /// Human-readable type
    #[nom(Value(V9Field::from(field_type_number)))]
    pub field_type: V9Field,
    /// This number gives the length of the above-defined field, in bytes.
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &OptionsTemplate))]
pub struct OptionsData {
    #[nom(Parse = "{ many0(complete( |i| OptionsDataFields::parse(i, template))) } ")]
    pub fields: Vec<OptionsDataFields>,
}

pub struct ScopeParser;

impl<'a> ScopeParser {
    fn parse(
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

pub struct OptionsFieldParser;

impl<'a> OptionsFieldParser {
    fn parse(
        input: &'a [u8],
        template: &OptionsTemplate,
    ) -> IResult<&'a [u8], Vec<Vec<V9FieldPair>>> {
        let mut result = Vec::with_capacity(template.option_fields.len());
        let mut remaining = input;
        for template_field in template.option_fields.iter() {
            let (i, field_value) = template_field.parse_as_field_value(remaining)?;
            remaining = i;
            result.push(vec![(template_field.field_type, field_value)]);
        }
        Ok((remaining, result))
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &OptionsTemplate))]
pub struct OptionsDataFields {
    // Scope Data
    #[nom(Parse = "{ |i| ScopeParser::parse(i, template) }")]
    pub scope_fields: Vec<ScopeDataField>,
    // Options Data Fields
    #[nom(Parse = "{ |i| OptionsFieldParser::parse(i, template) }")]
    pub options_fields: Vec<Vec<V9FieldPair>>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum ScopeDataField {
    System(Vec<u8>),
    Interface(Vec<u8>),
    LineCard(Vec<u8>),
    NetFlowCache(Vec<u8>),
    Template(Vec<u8>),
}

/// Parses a scope data field from the provided input slice using the given template field information.
///
/// This function reads a number of bytes equal to `template_field.field_length` from the `input` slice and maps
/// the resulting value to the corresponding variant of `ScopeDataField` based on `template_field.field_type`.
///
/// Supported field types include:
/// - `ScopeFieldType::System`
/// - `ScopeFieldType::Interface`
/// - `ScopeFieldType::LineCard`
/// - `ScopeFieldType::NetflowCache`
/// - `ScopeFieldType::Template`
///
/// # Arguments
///
/// * `input` - A byte slice that contains the data to be parsed.
/// * `template_field` - A reference to an `OptionsTemplateScopeField` which holds the metadata describing the expected field,
///   including its length and type.
///
/// # Returns
///
/// Returns an `IResult` tuple containing:
/// - The remaining unparsed slice.
/// - A `ScopeDataField` variant with the parsed data.
///
/// # Errors
///
/// If the field type from `template_field` does not match any of the supported types, the function returns a nom error
/// with `ErrorKind::Verify`.
/// ```
impl ScopeDataField {
    fn parse<'a>(
        input: &'a [u8],
        template_field: &OptionsTemplateScopeField,
    ) -> IResult<&'a [u8], ScopeDataField> {
        let (new_input, field_value) = take(template_field.field_length)(input)?;

        match template_field.field_type {
            ScopeFieldType::System => {
                Ok((new_input, ScopeDataField::System(field_value.to_vec())))
            }
            ScopeFieldType::Interface => {
                Ok((new_input, ScopeDataField::Interface(field_value.to_vec())))
            }
            ScopeFieldType::LineCard => {
                Ok((new_input, ScopeDataField::LineCard(field_value.to_vec())))
            }
            ScopeFieldType::NetflowCache => Ok((
                new_input,
                ScopeDataField::NetFlowCache(field_value.to_vec()),
            )),
            ScopeFieldType::Template => {
                Ok((new_input, ScopeDataField::Template(field_value.to_vec())))
            }
            _ => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &Template))]
pub struct Data {
    // Data Fields
    #[nom(Parse = "{ |i| FieldParser::parse(i, template) }")]
    pub fields: Vec<V9FlowRecord>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

impl Data {
    /// Creates a new Data instance with the given fields.
    /// The padding field is automatically set to an empty vector and will be
    /// calculated during export for manually created packets.
    pub fn new(fields: Vec<V9FlowRecord>) -> Self {
        Self {
            fields,
            padding: vec![],
        }
    }
}

pub struct FlowSetParser;

impl FlowSetParser {
    /// Parses a slice of bytes into a vector of FlowSet records.
    ///
    /// This method iterates over the input byte slice, attempting to parse each flowset using
    /// the `FlowSet::parse` function. It continues this process until the input is exhausted
    /// or the specified number of records (`record_count`) has been parsed.
    ///
    /// The parser argument provides necessary context for interpreting version 9 flowsets.
    ///
    /// # Arguments
    ///
    /// * `i` - A byte slice representing the input data to be parsed.
    /// * `parser` - A mutable reference to the V9Parser, which maintains context during parsing.
    /// * `record_count` - The total number of records expected, as specified in the header (includes data and template records).
    ///
    /// # Returns
    ///
    /// This function returns an `IResult` containing:
    ///
    /// * A slice of bytes that remains unparsed.
    /// * A vector of successfully parsed `FlowSet` objects.
    ///
    /// If a parsing error occurs during the processing of any flowset, the error is propagated.
    fn parse_flowsets<'a>(
        i: &'a [u8],
        parser: &mut V9Parser,
        record_count: u16,
    ) -> IResult<&'a [u8], Vec<FlowSet>> {
        let (remaining, flowsets) = (0..record_count).try_fold(
            (i, Vec::with_capacity(record_count as usize)),
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

pub struct FieldParser;

impl<'a> FieldParser {
    /// Parses the input byte slice into a vector of records based on the provided template.
    ///
    /// The function computes the number of records available in the input by dividing the length of the input
    /// by the template's total size. It then iteratively extracts each record using `parse_data_field`, accumulating
    /// a vector of where each map represents a record mapping field indices to `V9FieldPair`.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice containing the raw data to parse.
    /// * `template` - A template that defines the structure and size of each record.
    ///
    /// # Returns
    ///
    /// A result containing:
    /// - The remaining slice of input data that was not parsed.
    /// - A vector of V9FieldPair, each mapping a field index to its corresponding `V9FieldPair`.
    ///
    /// # Errors
    ///
    /// The function will return an error if any record fails to be parsed according to the template.
    fn parse(
        mut input: &'a [u8],
        template: &Template,
    ) -> IResult<&'a [u8], Vec<Vec<V9FieldPair>>> {
        let template_total_size = usize::from(template.get_total_size());
        if template_total_size == 0 {
            return Err(nom::Err::Error(NomError::new(input, ErrorKind::Verify)));
        }

        // Calculate how many complete records we can parse based on input length
        let record_count = input.len() / template_total_size;
        let mut res = Vec::with_capacity(record_count);

        for _ in 0..record_count {
            match Self::parse_data_fields(input, template) {
                Ok((remaining, record)) => {
                    input = remaining;
                    res.push(record);
                }
                Err(_) => return Ok((input, res)),
            };
        }

        Ok((input, res))
    }

    /// Parses a single record (data field) based on the provided template.
    ///
    /// The function iterates over each field defined in the template, using each field's own parser to
    /// extract its value from the input. The parsed values, along with their corresponding field types.
    ///
    /// # Arguments
    ///
    /// * `input` - A mutable byte slice from which the field values are parsed.
    /// * `template` - The template providing the definition and order of fields to be parsed.
    ///
    /// # Returns
    ///
    /// A result containing:
    /// - The remaining input slice after parsing the record.
    /// - A Vector of `V9FieldPair`, where each pair consists of the field type and the parsed value.
    ///
    /// # Errors
    ///
    /// The function returns an error if parsing any individual field fails according to its type-defined parser.
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
    pub fn parse_as_field_value<'a>(&self, input: &'a [u8]) -> IResult<&'a [u8], FieldValue> {
        FieldValue::from_field_type(input, self.field_type.into(), self.field_length)
    }
}

impl V9 {
    /// Convert the V9 struct to a `Vec<u8>` of bytes in big-endian order for exporting
    pub fn to_be_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();

        result.extend_from_slice(&self.header.version.to_be_bytes());
        result.extend_from_slice(&self.header.count.to_be_bytes());
        result.extend_from_slice(&self.header.sys_up_time.to_be_bytes());
        result.extend_from_slice(&self.header.unix_secs.to_be_bytes());
        result.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        result.extend_from_slice(&self.header.source_id.to_be_bytes());

        for set in self.flowsets.iter() {
            result.extend_from_slice(&set.header.flowset_id.to_be_bytes());
            result.extend_from_slice(&set.header.length.to_be_bytes());

            if let FlowSetBody::Template(templates) = &set.body {
                let mut template_content = Vec::new();
                for template in templates.templates.iter() {
                    template_content.extend_from_slice(&template.template_id.to_be_bytes());
                    template_content.extend_from_slice(&template.field_count.to_be_bytes());
                    for field in template.fields.iter() {
                        template_content
                            .extend_from_slice(&field.field_type_number.to_be_bytes());
                        template_content.extend_from_slice(&field.field_length.to_be_bytes());
                    }
                }
                result.extend_from_slice(&template_content);

                // Auto-calculate padding if not provided (for manually created packets)
                let padding = if templates.padding.is_empty() {
                    calculate_padding(template_content.len())
                } else {
                    templates.padding.clone()
                };
                result.extend_from_slice(&padding);
            }

            if let FlowSetBody::OptionsTemplate(options_templates) = &set.body {
                let mut options_content = Vec::new();
                for template in options_templates.templates.iter() {
                    options_content.extend_from_slice(&template.template_id.to_be_bytes());
                    options_content
                        .extend_from_slice(&template.options_scope_length.to_be_bytes());
                    options_content.extend_from_slice(&template.options_length.to_be_bytes());
                    for field in template.scope_fields.iter() {
                        options_content
                            .extend_from_slice(&field.field_type_number.to_be_bytes());
                        options_content.extend_from_slice(&field.field_length.to_be_bytes());
                    }
                    for field in template.option_fields.iter() {
                        options_content
                            .extend_from_slice(&field.field_type_number.to_be_bytes());
                        options_content.extend_from_slice(&field.field_length.to_be_bytes());
                    }
                }
                result.extend_from_slice(&options_content);

                // Auto-calculate padding if not provided (for manually created packets)
                let padding = if options_templates.padding.is_empty() {
                    calculate_padding(options_content.len())
                } else {
                    options_templates.padding.clone()
                };
                result.extend_from_slice(&padding);
            }

            if let FlowSetBody::Data(data) = &set.body {
                let mut data_content = Vec::new();
                for data_field in data.fields.iter() {
                    for (_, field_value) in data_field.iter() {
                        data_content.extend_from_slice(&field_value.to_be_bytes()?);
                    }
                }
                result.extend_from_slice(&data_content);

                // Auto-calculate padding if not provided (for manually created packets)
                let padding = if data.padding.is_empty() {
                    calculate_padding(data_content.len())
                } else {
                    data.padding.clone()
                };
                result.extend_from_slice(&padding);
            }

            if let FlowSetBody::OptionsData(options_data) = &set.body {
                for options_data_field in options_data.fields.iter() {
                    for field in options_data_field.scope_fields.iter() {
                        match field {
                            ScopeDataField::System(value) => {
                                result.extend_from_slice(value);
                            }
                            ScopeDataField::Interface(value) => {
                                result.extend_from_slice(value);
                            }
                            ScopeDataField::LineCard(value) => {
                                result.extend_from_slice(value);
                            }
                            ScopeDataField::NetFlowCache(value) => {
                                result.extend_from_slice(value);
                            }
                            ScopeDataField::Template(value) => {
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
        }

        Ok(result)
    }
}
