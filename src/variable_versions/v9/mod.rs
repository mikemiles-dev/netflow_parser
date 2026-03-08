//! # NetFlow V9
//!
//! Types and parsing logic for Cisco NetFlow Version 9 (RFC 3954).
//!
//! Key types:
//! - [`V9`] — a parsed V9 packet containing a [`Header`] and a list of [`FlowSet`]s
//! - [`V9Parser`] — stateful parser with an LRU template cache
//! - [`Template`] / [`OptionsTemplate`] — template definitions that describe data record layout
//! - [`Data`] / [`OptionsData`] — parsed data records decoded using a cached template
//! - [`FlowSetBody`] — enum of all possible flowset payloads (templates, data, options, or no-template)
//!
//! References:
//! - <https://www.ietf.org/rfc/rfc3954.txt>
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

mod parser;
mod serializer;

pub use parser::V9Parser;

use super::field_value::FieldValue;
use crate::variable_versions::v9_lookup::{ScopeFieldType, V9Field};

use nom::bytes::complete::take;
use nom::combinator::map_res;
use nom_derive::{Nom, Parse};
use serde::Serialize;

pub const DATA_TEMPLATE_V9_ID: u16 = 0;
pub const OPTIONS_TEMPLATE_V9_ID: u16 = 1;

use super::calculate_padding;
use super::{DEFAULT_MAX_TEMPLATE_CACHE_SIZE, MAX_FIELD_COUNT, TemplateId};
pub type V9FieldPair = (V9Field, FieldValue);
pub type V9FlowRecord = Vec<V9FieldPair>;

pub use super::NoTemplateInfo;

/// A parsed NetFlow V9 packet containing a header and a list of flowsets.
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct V9 {
    /// V9 Header
    pub header: Header,
    /// Flowsets
    #[nom(Parse = "{ |i| FlowSetParser::parse_flowsets(i, parser, header.count) }")]
    pub flowsets: Vec<FlowSet>,
}

/// NetFlow V9 packet header (RFC 3954 Section 5.1).
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
    pub sequence_number: u32,
    /// The Source ID field is a 32-bit value that is used to guarantee uniqueness for all flows exported
    /// from a particular device.
    pub source_id: u32,
}

/// A single flowset within a V9 packet, containing a header and a body.
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

/// Header of a V9 flowset, identifying its type and length.
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct FlowSetHeader {
    /// The FlowSet ID is used to distinguish template records from data records.
    pub flowset_id: u16,
    /// This field gives the length of the data FlowSet.
    pub length: u16,
}

/// The payload of a V9 flowset: template definitions, data records, options, or a placeholder
/// when the required template has not yet been received.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum FlowSetBody {
    Template(Templates),
    OptionsTemplate(OptionsTemplates),
    Data(Data),
    OptionsData(OptionsData),
    NoTemplate(NoTemplateInfo),
}

/// A collection of V9 template definitions parsed from a template flowset.
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct Templates {
    pub templates: Vec<Template>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

/// A collection of V9 options template definitions parsed from an options template flowset.
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct OptionsTemplates {
    pub templates: Vec<OptionsTemplate>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

/// A V9 template definition that describes the format of data records.
#[derive(Debug, PartialEq, Clone, Serialize, Default, Nom)]
pub struct Template {
    /// Template ID (256+ for data templates, 0-255 reserved for FlowSet IDs).
    pub template_id: u16,
    /// Number of fields in this template record.
    pub field_count: u16,
    /// Template Fields.
    #[nom(Count = "field_count")]
    pub fields: Vec<TemplateField>,
}

/// A V9 options template definition that describes the format of options data records.
#[derive(Debug, PartialEq, Clone, Serialize, Default, Nom)]
pub struct OptionsTemplate {
    /// Template ID (greater than 255).
    pub template_id: u16,
    /// Length in bytes of scope fields in this options template.
    pub options_scope_length: u16,
    /// Length in bytes of option field definitions in this options template.
    pub options_length: u16,
    /// Options Scope Fields
    #[nom(Count = "usize::from(options_scope_length.checked_div(4).unwrap_or(0))")]
    pub scope_fields: Vec<OptionsTemplateScopeField>,
    /// Options Fields
    #[nom(Count = "usize::from(options_length.checked_div(4).unwrap_or(0))")]
    pub option_fields: Vec<TemplateField>,
}

/// Options Scope Fields
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct OptionsTemplateScopeField {
    pub field_type_number: u16,
    #[nom(Value(ScopeFieldType::from(field_type_number)))]
    pub field_type: ScopeFieldType,
    pub field_length: u16,
}

/// A single field definition within a V9 template, specifying the field type and byte length.
#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct TemplateField {
    /// Numeric field type (vendor specific, see Table 6 in RFC 3954).
    pub field_type_number: u16,
    /// Human-readable type
    #[nom(Value(V9Field::from(field_type_number)))]
    pub field_type: V9Field,
    /// Length of the field in bytes.
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &OptionsTemplate))]
pub struct OptionsData {
    #[nom(Parse = "{ many0(complete( |i| OptionsDataFields::parse(i, template))) } ")]
    pub fields: Vec<OptionsDataFields>,
}

pub struct ScopeParser;

pub struct OptionsFieldParser;

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(template: &OptionsTemplate))]
pub struct OptionsDataFields {
    // Scope Data
    #[nom(Parse = "{ |i| ScopeParser::parse(i, template) }")]
    pub scope_fields: Vec<ScopeDataField>,
    // Options Data Fields
    #[nom(Parse = "{ |i| OptionsFieldParser::parse(i, template) }")]
    pub options_fields: Vec<V9FieldPair>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum ScopeDataField {
    System(Vec<u8>),
    Interface(Vec<u8>),
    LineCard(Vec<u8>),
    NetFlowCache(Vec<u8>),
    Template(Vec<u8>),
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
    pub fn new(fields: Vec<V9FlowRecord>) -> Self {
        Self {
            fields,
            padding: vec![],
        }
    }
}

pub struct FlowSetParser;

pub struct FieldParser;

// Nom-derive needs many0 and complete in scope for OptionsData parsing
use nom::combinator::complete;
use nom::multi::many0;
