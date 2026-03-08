//! # IPFIX (IP Flow Information Export)
//!
//! Types and parsing logic for IPFIX (RFC 7011), the IETF standard evolution of NetFlow V9.
//!
//! IPFIX extends V9 with variable-length fields, enterprise-specific information elements,
//! and a length-based message header (instead of V9's count-based header).
//!
//! Key types:
//! - [`IPFix`] — a parsed IPFIX message containing a [`Header`] and a list of [`FlowSet`]s
//! - [`IPFixParser`] — stateful parser with LRU template caches (supports both IPFIX and V9-style templates)
//! - [`Template`] / [`OptionsTemplate`] — IPFIX template definitions with enterprise field support
//! - [`Data`] / [`OptionsData`] — parsed data records decoded using a cached template
//! - [`FlowSetBody`] — enum of all possible flowset payloads
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

mod parser;
mod serializer;

use super::PendingFlowCache;
use super::data_number::FieldValue;
use super::enterprise_registry::EnterpriseFieldRegistry;
use super::metrics::CacheMetrics;
use super::ttl::{TemplateWithTtl, TtlConfig};
use crate::variable_versions::ipfix_lookup::IPFixField;

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
    OptionsTemplate as V9OptionsTemplate, Template as V9Template,
};

use lru::LruCache;
use std::sync::Arc;

use super::{DEFAULT_MAX_TEMPLATE_CACHE_SIZE, MAX_FIELD_COUNT, TemplateId};

const DATA_TEMPLATE_IPFIX_ID: u16 = 2;
const OPTIONS_TEMPLATE_IPFIX_ID: u16 = 3;
pub type IPFixFieldPair = (IPFixField, FieldValue);
pub type IpFixFlowRecord = Vec<IPFixFieldPair>;

use super::calculate_padding;

// IPFixParser struct and impl blocks are in parser.rs
// Serialization (to_be_bytes) is in serializer.rs

/// Stateful IPFIX parser with LRU template caches and optional pending flow support.
/// Supports both native IPFIX templates and V9-style templates embedded in IPFIX messages.
#[derive(Debug)]
pub struct IPFixParser {
    pub(crate) templates: LruCache<TemplateId, TemplateWithTtl<Arc<Template>>>,
    pub(crate) v9_templates: LruCache<TemplateId, TemplateWithTtl<Arc<V9Template>>>,
    pub(crate) ipfix_options_templates: LruCache<TemplateId, TemplateWithTtl<Arc<OptionsTemplate>>>,
    pub(crate) v9_options_templates: LruCache<TemplateId, TemplateWithTtl<Arc<V9OptionsTemplate>>>,
    pub(crate) ttl_config: Option<TtlConfig>,
    pub(crate) max_template_cache_size: usize,
    pub(crate) max_field_count: usize,
    pub(crate) max_template_total_size: usize,
    pub(crate) max_error_sample_size: usize,
    pub(crate) enterprise_registry: EnterpriseFieldRegistry,
    pub(crate) metrics: CacheMetrics,
    pub(crate) pending_flows: Option<PendingFlowCache>,
}

// IPFixParser Default, ParserConfig, parse(), and pending flow impl blocks are in parser.rs.
// Serialization (to_be_bytes) impl block is in serializer.rs.
//
// The add_* template methods below remain here because they are called directly
// from FlowSet parsing code in this file.

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

/// A parsed IPFIX message containing a header and a list of flowsets.
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

pub use super::NoTemplateInfo;

/// The payload of an IPFIX flowset: template definitions, data records, options,
/// V9-style templates/data, or a placeholder when the required template is missing.
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
                    let raw_data = if parser.pending_flows.as_ref().is_some_and(|c| {
                        i.len() <= c.max_entry_size_bytes() && c.would_accept(id)
                    }) {
                        i.to_vec()
                    } else {
                        i[..i.len().min(parser.max_error_sample_size)].to_vec()
                    };
                    let info = NoTemplateInfo::new(id, raw_data);
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

/// IPFIX message header (RFC 7011 Section 3.1).
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

/// A single set within an IPFIX message, containing a header and a body.
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

/// Header of an IPFIX set, identifying its type (template, options, or data) and length.
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

/// Parsed IPFIX data records decoded using an IPFIX template.
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

/// Parsed IPFIX options data records decoded using an IPFIX options template.
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

/// An IPFIX options template definition (RFC 7011 Section 3.4.2.2).
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

impl OptionsTemplate {
    /// Validate the options template against parser configuration
    pub fn is_valid(&self, parser: &IPFixParser) -> bool {
        <Self as CommonTemplate>::is_valid(self, parser)
    }
}

/// An IPFIX template definition (RFC 7011 Section 3.4.1) that describes data record layout.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom, Default)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    #[nom(Count = "field_count")]
    pub fields: Vec<TemplateField>,
}

impl Template {
    /// Validate the template against parser configuration
    pub fn is_valid(&self, parser: &IPFixParser) -> bool {
        <Self as CommonTemplate>::is_valid(self, parser)
    }
}

/// A single field definition within an IPFIX template, with optional enterprise number support.
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

/// Shared interface for IPFIX `Template` and `OptionsTemplate`, providing
/// field access and validation against parser configuration limits.
pub(crate) trait CommonTemplate {
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
        if self.get_fields().is_empty() || !self.get_fields().iter().any(|f| f.field_length > 0)
        {
            return false;
        }

        // Check total size limit
        let total_size: usize = self
            .get_fields()
            .iter()
            .fold(0, |acc, f| acc.saturating_add(usize::from(f.field_length)));
        if total_size > parser.max_template_total_size {
            return false;
        }

        // Check for duplicate field IDs
        let mut seen = std::collections::HashSet::with_capacity(self.get_fields().len());
        for field in self.get_fields() {
            // For IPFIX, we need to check the combination of field_type_number and enterprise_number
            let key = (field.field_type_number, field.enterprise_number);
            if !seen.insert(key) {
                return false; // Found duplicate
            }
        }

        true
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
