//! # IPFix
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::common::*;
use crate::variable_versions::ipfix_lookup::*;
use crate::{NetflowByteParserVariable, NetflowPacketResult, ParsedNetflow};

use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom::multi::count;
use nom::number::complete::be_u32;
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::collections::BTreeMap;
use std::time::Duration;

const TEMPLATE_ID: u16 = 2;
const OPTIONS_TEMPLATE_ID: u16 = 3;
const SET_MIN_RANGE: u16 = 255;

type TemplateId = u16;

#[derive(Default, Debug)]
pub struct IPFixParser {
    pub templates: BTreeMap<TemplateId, Template>,
    pub options_templates: BTreeMap<TemplateId, OptionsTemplate>,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct IPFix {
    /// IPFix Header
    pub header: Header,
    /// Sets
    pub sets: Vec<Set>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub struct Header {
    /// Version of Flow Record format that is exported in this message. The value of this field is 0x000a for the current version, incrementing by one the version that is used in the NetFlow services export version 9
    pub version: u16,
    /// Total length of the IPFIX Message, which is measured in octets, including Message Header and Sets.
    pub length: u16,
    /// Time, in seconds, since 0000 Coordinated Universal Time Jan 1, 1970, at which the IPFIX Message Header leaves the Exporter.
    #[nom(Map = "|i| Duration::from_secs(i as u64)", Parse = "be_u32")]
    pub export_time: Duration,
    /// Incremental sequence counter-modulo 2^32 of all IPFIX Data Records sent on this PR-SCTP stream from the current Observation Domain by the Exporting Process. Check the specific meaning of this field in the subsections of Section 10 when UDP or TCP is selected as the transport protocol. This value must be used by the Collecting Process to identify whether any IPFIX Data Records are missed. Template and Options Template Records do not increase the Sequence Number.
    pub sequence_number: u32,
    /// A 32-bit identifier of the Observation Domain that is locally unique to the Exporting Process. The Exporting Process uses the Observation Domain ID to uniquely identify to the Collector.  Process the Observation Domain that metered the Flows. It is recommended that this identifier is unique per IPFIX Device. Collecting Processes must use the Transport Session.  Observation Domain ID field to separate different export streams that originate from the same Exporting Process. The Observation Domain ID must be 0 when no specific Observation Domain ID is relevant for the entire IPFIX Message. For example, when the Exporting Process Statistics are exported, or in a hierarchy of Collectors when aggregated Data Records are exported.
    pub observation_domain_id: u32,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser))]
pub struct Set {
    /// Set ID value identifies the Set. A value of 2 is reserved for the Template Set. A value of 3 is reserved for the Option Template Set. All other values 4-255 are reserved for future use. Values more than 255 are used for Data Sets. The Set ID values of 0 and 1 are not used for historical reasons
    pub id: u16,
    /// Total length of the Set, in octets, including the Set Header, all records, and the optional padding. Because an individual Set MAY contain multiple records, the Length value must be used to determine the position of the next Set.
    pub length: u16,
    #[nom(
        Cond = "id == TEMPLATE_ID",
        // Save our templates
        PostExec = "if let Some(template) = template.clone() { parser.templates.insert(template.template_id, template); }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Template>,
    #[nom(
        Cond = "id == OPTIONS_TEMPLATE_ID",
        Parse = "{ |i| parse_options_template(i, length) }",
        // Save our templates
        PostExec = "if let Some(options_template) = options_template.clone() { parser.options_templates.insert(options_template.template_id, options_template); }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_template: Option<OptionsTemplate>,
    // Data
    #[nom(
        Cond = "id > SET_MIN_RANGE && parser.templates.get(&id).is_some()",
        Parse = "{ |i| Data::parse(i, parser, id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    // OptionsData
    #[nom(
        Cond = "id > SET_MIN_RANGE && parser.options_templates.get(&id).is_some()",
        Parse = "{ |i| OptionsData::parse(i, parser, id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_data: Option<OptionsData>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct Data {
    #[nom(Parse = "{ |i| parse_fields::<Template>(i, parser.templates.get(&set_id)) }")]
    pub data_fields: Vec<BTreeMap<IPFixField, FieldValue>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct OptionsData {
    #[nom(
        Parse = "{ |i| parse_fields::<OptionsTemplate>(i, parser.options_templates.get(&set_id)) }"
    )]
    pub data_fields: Vec<BTreeMap<IPFixField, FieldValue>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    #[nom(
        PreExec = "let combined_count = scope_field_count as usize + 
                       field_count.checked_sub(scope_field_count).unwrap_or(field_count) as usize;",
        Parse = "count(|i| TemplateField::parse(i, true), combined_count)"
    )]
    pub fields: Vec<TemplateField>,
    #[nom(Cond = "!i.is_empty()")]
    #[serde(skip_serializing)]
    padding: Option<u16>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    #[nom(Parse = "count(|i| TemplateField::parse(i, false), field_count as usize)")]
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(options_template: bool))]
pub struct TemplateField {
    pub field_type_number: u16,
    #[nom(Value(IPFixField::from(field_type_number)))]
    pub field_type: IPFixField,
    pub field_length: u16,
    #[nom(
        Cond = "options_template && field_type_number > 32767",
        PostExec = "let field_type_number = if options_template {
                      field_type_number.overflowing_sub(32768).0
                    } else { field_type_number };",
        PostExec = "let field_type = if options_template {
                      set_entperprise_field(field_type, enterprise_number)
                    } else { field_type };"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_number: Option<u32>,
}

fn set_entperprise_field(field_type: IPFixField, enterprise_number: Option<u32>) -> IPFixField {
    if enterprise_number.is_some() {
        IPFixField::Enterprise
    } else {
        field_type
    }
}

/// Parses options template
fn parse_options_template(i: &[u8], length: u16) -> IResult<&[u8], OptionsTemplate> {
    let (remaining, taken) = take(length.checked_sub(4).unwrap_or(length))(i)?;
    let (_, option_template) = OptionsTemplate::parse(taken)?;
    Ok((remaining, option_template))
}

// Common trait for both templates.  Mainly for fetching fields.
trait CommonTemplate {
    fn get_fields(&self) -> &Vec<TemplateField>;
}

impl CommonTemplate for Template {
    fn get_fields(&self) -> &Vec<TemplateField> {
        &self.fields
    }
}

impl CommonTemplate for OptionsTemplate {
    fn get_fields(&self) -> &Vec<TemplateField> {
        &self.fields
    }
}

/// Takes a byte stream and a cached template.
/// Fields get matched to static types.
/// Returns BTree of IPFix Types & Fields or IResult Error.
fn parse_fields<'a, T: CommonTemplate>(
    i: &'a [u8],
    template: Option<&T>,
) -> IResult<&'a [u8], Vec<BTreeMap<IPFixField, FieldValue>>> {
    // If no fields there are no fields to parse, return an error.
    let template_fields = template
        .ok_or(NomErr::Error(NomError::new(i, ErrorKind::Fail)))?
        .get_fields();

    if template_fields.is_empty() {
        // dbg!("Template without fields!");
        return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
    };

    let mut fields = vec![];
    let mut remaining = i;

    // While we have bytes remaining
    while !remaining.is_empty() {
        let mut data_field = BTreeMap::new();
        for template_field in template_fields.iter() {
            let field_type: FieldDataType = template_field.field_type.into();
            // Enterprise Number
            let (i, field_value) = if template_field.enterprise_number.is_some() {
                let (i, data_number) = DataNumber::parse(remaining, 4, false)?;
                let field = FieldValue::DataNumber(data_number);
                (i, field)
            // Type matching
            } else {
                DataNumber::from_field_type(remaining, field_type, template_field.field_length)?
            };
            remaining = i;
            data_field.insert(template_field.field_type, field_value);
        }
        fields.push(data_field);
    }
    Ok((remaining, fields))
}

impl NetflowByteParserVariable for IPFixParser {
    /// Takes a byte stream, returns either a Parsed Netflow or a Boxed Error.
    #[inline]
    fn parse_bytes<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> Result<ParsedNetflow, Box<dyn std::error::Error>> {
        let mut sets = vec![];

        let (mut remaining, v10_header) =
            Header::parse(packet).map_err(|_| "Could not parse v10_packet".to_string())?;

        let mut total_left = v10_header.length as usize;

        // dbg!("remaining: {}", remaining);

        while total_left != 0 {
            let (left_remaining, v10_set) = Set::parse(remaining, self)
                .map_err(|e| format!("Could not parse v10_set: {e}"))?;
            // dbg!("left remaining: {}", left_remaining);
            remaining = left_remaining;
            let parsed = total_left
                .checked_sub(remaining.len())
                .unwrap_or(total_left);
            total_left -= parsed;
            sets.push(v10_set);
        }

        let v10_parsed = IPFix {
            header: v10_header,
            sets,
        };

        Ok(ParsedNetflow {
            remaining: remaining.to_vec(),
            netflow_packet: NetflowPacketResult::IPFix(v10_parsed),
        })
    }
}
