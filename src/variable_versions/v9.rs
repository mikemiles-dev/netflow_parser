//! # Netflow V9
//!
//! References:
//! - <https://www.ietf.org/rfc/rfc3954.txt>
//! - <https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html>

use super::common::*;
use crate::variable_versions::v9_lookup::*;

use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom::IResult;
use nom::{Err as NomErr, InputTake};
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::collections::BTreeMap;
use std::collections::HashMap;

const TEMPLATE_ID: u16 = 0;
const OPTIONS_TEMPLATE_ID: u16 = 1;
const FLOW_SET_MIN_RANGE: u16 = 255;

type TemplateId = u16;

#[derive(Default, Debug)]
pub struct V9Parser {
    pub templates: HashMap<TemplateId, Template>,
    pub options_templates: HashMap<TemplateId, OptionsTemplate>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser))]
pub struct V9 {
    /// V9 Header
    pub header: Header,
    /// Flowsets
    #[nom(Parse = "{ |i| parse_flowsets(i, parser) }")]
    pub flowsets: Vec<FlowSet>,
}

fn parse_flowsets<'a>(i: &'a [u8], parser: &mut V9Parser) -> IResult<&'a [u8], Vec<FlowSet>> {
    let mut flowsets = vec![];
    let mut remaining = i;

    // Header.count represents total number of records in data + records in templates
    while !remaining.is_empty() {
        let (i, mut flowset) = FlowSet::parse(remaining, parser)?;

        if flowset.is_empty() {
            flowset.body.unparsed_data = Some(remaining.to_vec());
            remaining = &[];
        } else if flowset.is_unparsed() {
            flowset.body.unparsed_data =
                Some(remaining[..flowset.header.length as usize].to_vec());
            remaining = &remaining[flowset.header.length as usize..];
        } else {
            remaining = i;
        }

        flowsets.push(flowset)
    }

    Ok((remaining, flowsets))
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
    #[nom(Parse = "{ |i| parse_set_body(i, parser, header.flow_set_id, header.length) }")]
    pub body: FlowSetBody,
}

// Custom parse set body function to take only length provided by set header.
fn parse_set_body<'a>(
    i: &'a [u8],
    parser: &mut V9Parser,
    id: u16,
    length: u16,
) -> IResult<&'a [u8], FlowSetBody> {
    // length - 4 to account for the set header
    let length = length.checked_sub(4).unwrap_or(length);
    let (remaining, taken) = take(length)(i)?;
    let (_, set_body) = FlowSetBody::parse(taken, parser, id)?;
    Ok((remaining, set_body))
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct FlowSetHeader {
    /// The FlowSet ID is used to distinguish template records from data records.
    /// A template record always has a FlowSet ID in the range of 0-255. Currently,
    /// the template record that describes flow fields has a FlowSet ID of zero and
    /// the template record that describes option fields (described below) has a
    /// FlowSet ID of 1. A data record always has a nonzero FlowSet ID greater than 255.
    pub flow_set_id: u16,
    /// This field gives the length of the data FlowSet. Length is expressed in TLV format,
    /// meaning that the value includes the bytes used for the FlowSet ID and the length bytes
    /// themselves, as well as the combined lengths of any included data records.
    pub length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct FlowSetBody {
    /// Templates
    #[nom(
        Cond = "flow_set_id == TEMPLATE_ID",
        // Save our templates
        PostExec = "if let Some(templates) = templates.clone() { 
            for template in templates {
                parser.templates.insert(template.template_id, template); 
            }
        }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<Template>>,
    // Options template
    #[nom(
        Cond = "flow_set_id == OPTIONS_TEMPLATE_ID",
        Parse = "parse_options_template_vec",
        // Save our options templates
        PostExec = "if let Some(options_templates) = options_templates.clone() { 
            for template in options_templates {
                parser.options_templates.insert(template.template_id, template); 
            } 
        }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_templates: Option<Vec<OptionsTemplate>>,
    // Options Data
    #[nom(
        Cond = "flow_set_id > FLOW_SET_MIN_RANGE && parser.options_templates.get(&flow_set_id).is_some()",
        Parse = "{ |i| OptionsData::parse(i, parser, flow_set_id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_data: Option<OptionsData>,
    // Data
    #[nom(
        Cond = "flow_set_id > FLOW_SET_MIN_RANGE && parser.templates.get(&flow_set_id).is_some()",
        Parse = "{ |i| Data::parse(i, parser, flow_set_id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    // Unparsed data
    #[nom(Ignore)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparsed_data: Option<Vec<u8>>,
}

impl FlowSet {
    fn is_unparsed(&self) -> bool {
        self.body.templates.is_none()
            && self.body.options_templates.is_none()
            && self.body.data.is_none()
            && self.body.options_data.is_none()
    }

    fn is_empty(&self) -> bool {
        self.header.length == 0
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
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

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    /// As a router generates different template FlowSets to match the type of NetFlow data it is exporting, each template is given a unique ID. This uniqueness is local to the router that generated the template ID. The Template ID is greater than 255. Template IDs inferior to 255 are reserved.
    pub template_id: u16,
    /// This field gives the length in bytes of any scope fields that are contained in this options template.
    pub options_scope_length: u16,
    /// This field gives the length (in bytes) of any Options field definitions that are contained in this options template
    pub options_length: u16,
    /// Options Scope Fields
    #[nom(Count = "(options_scope_length / 4) as usize")]
    pub scope_fields: Vec<OptionsTemplateScopeField>,
    /// Options Fields
    #[nom(Count = "(options_length / 4) as usize")]
    pub option_fields: Vec<TemplateField>,
}

fn parse_options_template_vec(i: &[u8]) -> IResult<&[u8], Vec<OptionsTemplate>> {
    let mut fields = vec![];
    let mut remaining = i;
    while let Ok((rem, data)) = OptionsTemplate::parse(remaining) {
        fields.push(data);
        remaining = rem;
    }
    Ok((remaining, fields))
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
    /// Human readable type
    #[nom(Value(V9Field::from(field_type_number)))]
    pub field_type: V9Field,
    /// This number gives the length of the above-defined field, in bytes.
    pub field_length: u16,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct OptionsData {
    // Scope Data
    #[nom(
        Parse = "{ |i| parse_scope_data_fields(i, flow_set_id, &parser.options_templates) }"
    )]
    pub scope_fields: Vec<ScopeDataField>,
    // Options Data Fields
    #[nom(
        Parse = "{ |i| parse_options_data_fields(i, flow_set_id, parser.options_templates.clone()) }"
    )]
    pub options_fields: Vec<OptionDataField>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: &OptionsTemplateScopeField))]
pub struct ScopeDataField {
    /// System
    #[nom(
        Cond = "field.field_type == ScopeFieldType::System",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<u8>>,
    /// Interface
    #[nom(
        Cond = "field.field_type == ScopeFieldType::Interface",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<Vec<u8>>,
    /// LineCard
    #[nom(
        Cond = "field.field_type == ScopeFieldType::LineCard",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_card: Option<Vec<u8>>,
    /// NetFlowCache
    #[nom(
        Cond = "field.field_type == ScopeFieldType::NetflowCache",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_flow_cache: Option<Vec<u8>>,
    /// Template
    #[nom(
        Cond = "field.field_type == ScopeFieldType::Template",
        Map = "|i: &[u8]| i.to_vec()",
        Take = "field.field_length"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut V9Parser, flow_set_id: u16))]
pub struct Data {
    // Data Fields
    #[nom(Parse = "{ |i| parse_fields(i, parser.templates.get(&flow_set_id)) }")]
    pub data_fields: Vec<BTreeMap<V9Field, FieldValue>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(field: &TemplateField))]
pub struct OptionDataField {
    #[nom(Value(field.field_type))]
    pub field_type: V9Field,
    #[nom(Map = "|i: &[u8]| i.to_vec()", Take = "field.field_length")]
    pub field_value: Vec<u8>,
}

fn parse_fields<'a>(
    i: &'a [u8],
    template: Option<&Template>,
) -> IResult<&'a [u8], Vec<BTreeMap<V9Field, FieldValue>>> {
    let template = match template {
        Some(t) => t,
        None => {
            // dbg!("Could not fetch any v9 templates!");
            return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
        }
    };

    let mut fields = vec![];
    // If no fields there are no fields to parse
    if template.fields.is_empty() {
        // dbg!("Template without fields!");
        return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
    };
    let mut remaining = i;

    while !remaining.is_empty() {
        let mut data_field = BTreeMap::new();
        for template_field in template.fields.iter() {
            let field_type: FieldDataType = template_field.field_type.into();
            let (i, field_value) = DataNumber::from_field_type(
                remaining,
                field_type,
                template_field.field_length,
            )?;
            remaining = i;
            data_field.insert(template_field.field_type, field_value);
        }
        // Check if the remaining flow is padding and remove it
        if remaining.iter().all(|&item| item == 0) {
            let padding = remaining.len();
            (remaining, _) = remaining.take_split(padding);
        }
        fields.push(data_field);
    }
    Ok((remaining, fields))
}

fn parse_options_data_fields(
    i: &[u8],
    flow_set_id: u16,
    templates: HashMap<u16, OptionsTemplate>,
) -> IResult<&[u8], Vec<OptionDataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        // dbg!("Could not fetch any v9 options templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.option_fields.iter() {
        let (i, v9_data_field) = OptionDataField::parse(remaining, field)?;
        remaining = i;
        fields.push(v9_data_field)
    }
    Ok((remaining, fields))
}

fn parse_scope_data_fields<'a>(
    i: &'a [u8],
    flow_set_id: u16,
    templates: &HashMap<u16, OptionsTemplate>,
) -> IResult<&'a [u8], Vec<ScopeDataField>> {
    let template = templates.get(&flow_set_id).ok_or_else(|| {
        // dbg!("Could not fetch any v9 options templates!");
        NomErr::Error(NomError::new(i, ErrorKind::Fail))
    })?;
    let mut fields = vec![];
    let mut remaining = i;
    for field in template.scope_fields.iter() {
        let (i, v9_data_field) = ScopeDataField::parse(remaining, field)?;
        remaining = i;
        fields.push(v9_data_field)
    }
    Ok((remaining, fields))
}
