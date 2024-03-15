//! # IPFix
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::common::*;
use crate::protocol::ProtocolTypes;
use crate::variable_versions::ipfix_lookup::*;
use crate::{NetflowByteParserVariable, NetflowPacketResult, ParsedNetflow};

use nom::bytes::complete::take;
use nom::error::{Error as NomError, ErrorKind};
use nom::number::complete::{be_u128, be_u32};
use nom::Err as NomErr;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;
use Nom;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    #[nom(
        Parse = "{ |i| parse_fields::<Template>(i, parser.templates.get(&set_id).cloned()) }"
    )]
    pub data_fields: Vec<BTreeMap<IPFixField, FieldValue>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct OptionsData {
    #[nom(
        Parse = "{ |i| parse_fields::<OptionsTemplate>(i, parser.options_templates.get(&set_id).cloned()) }"
    )]
    pub data_fields: Vec<BTreeMap<IPFixField, FieldValue>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    #[nom(Count = "scope_field_count")]
    pub scope_field_specifiers: Vec<OptionsTemplateField>,
    #[nom(
        Count = "(field_count.checked_sub(scope_field_count).unwrap_or(field_count)) as usize"
    )]
    pub field_specifiers: Vec<OptionsTemplateField>,
    #[nom(Cond = "!i.is_empty()")]
    #[serde(skip_serializing)]
    padding: Option<u16>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    #[nom(Count = "field_count")]
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplateField {
    pub field_type_number: u16,
    #[nom(Value(IPFixField::from(field_type_number)))]
    pub field_type: IPFixField,
    field_length: u16,
    #[nom(
        Cond = "field_type_number > 32767",
        PostExec = "let field_type_number = field_type_number.overflowing_sub(32768).0;",
        PostExec = "let field_type = set_entperprise_field(field_type, enterprise_number);"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    enterprise_number: Option<u32>,
}

fn set_entperprise_field(field_type: IPFixField, enterprise_number: Option<u32>) -> IPFixField {
    match enterprise_number {
        Some(_) => IPFixField::Enterprise,
        None => field_type,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, PartialOrd, Ord, Nom)]
pub struct TemplateField {
    pub field_type_number: u16,
    #[nom(Value(IPFixField::from(field_type_number)))]
    pub field_type: IPFixField,
    pub field_length: u16,
}

/// Parses options template
fn parse_options_template(i: &[u8], length: u16) -> IResult<&[u8], OptionsTemplate> {
    let (remaining, taken) = take(length.checked_sub(4).unwrap_or(length))(i)?;
    let (_, option_template) = OptionsTemplate::parse(taken)?;
    Ok((remaining, option_template))
}

// Hacky way when using Template as generic T to cast to a common field type.
// We use OptionsTemplateField as it is the same as type Template Field but
// with enterprise_field.  In TemplateField tpe enterprise_field is just None.
trait CommonTemplateFields {
    fn get_fields(&self) -> Vec<OptionsTemplateField>;
}

impl CommonTemplateFields for Template {
    fn get_fields(&self) -> Vec<OptionsTemplateField> {
        self.fields
            .iter()
            .map(|f| OptionsTemplateField {
                field_length: f.field_length,
                field_type: f.field_type,
                field_type_number: f.field_type_number,
                enterprise_number: None,
            })
            .collect()
    }
}

impl CommonTemplateFields for OptionsTemplate {
    fn get_fields(&self) -> Vec<OptionsTemplateField> {
        let mut temp = vec![];
        temp.append(&mut self.scope_field_specifiers.clone());
        temp.append(&mut self.field_specifiers.clone());
        temp
    }
}

/// Takes a byte stream and a cached template.
/// Fields get matched to static types.
/// Returns BTree of IPFix Types & Fields or IResult Error.
fn parse_fields<T: CommonTemplateFields>(
    i: &[u8],
    template: Option<T>,
) -> IResult<&[u8], Vec<BTreeMap<IPFixField, FieldValue>>> {
    let template = match template {
        Some(t) => t,
        None => {
            // dbg!("Could not fetch any v10 templates!");
            return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
        }
    };
    // If no fields there are no fields to parse
    if template.get_fields().is_empty() {
        // dbg!("Template without fields!");
        return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
    };
    let mut fields = vec![];
    let mut remaining = i;
    while !remaining.is_empty() {
        let mut data_field = BTreeMap::new();
        for template_field in template.get_fields().iter() {
            let field_type: FieldDataType = template_field.field_type.into();
            // Enterprise Number
            if template_field.enterprise_number.is_some() {
                let (i, data_number) = parse_data_number(remaining, 4, false)?;
                remaining = i;
                data_field.insert(
                    template_field.field_type,
                    FieldValue::DataNumber(data_number),
                );
                continue;
            }
            // Type matching
            let field_value = match field_type {
                FieldDataType::UnsignedDataNumber => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, false)?;
                    remaining = i;
                    FieldValue::DataNumber(data_number)
                }
                FieldDataType::SignedDataNumber => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, true)?;
                    remaining = i;
                    FieldValue::DataNumber(data_number)
                }
                FieldDataType::String => {
                    let (i, taken) = take(template_field.field_length)(remaining)?;
                    remaining = i;
                    FieldValue::String(String::from_utf8_lossy(taken).to_string())
                }
                FieldDataType::Ip4Addr => {
                    let (i, taken) = be_u32(remaining)?;
                    remaining = i;
                    let ip_addr = Ipv4Addr::from(taken);
                    FieldValue::Ip4Addr(ip_addr)
                }
                FieldDataType::Ip6Addr => {
                    let (i, taken) = be_u128(remaining)?;
                    remaining = i;
                    let ip_addr = Ipv6Addr::from(taken);
                    FieldValue::Ip6Addr(ip_addr)
                }
                FieldDataType::DurationSeconds => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, false)?;
                    remaining = i;
                    FieldValue::Duration(Duration::from_secs(data_number.get_value() as u64))
                }
                FieldDataType::DurationMillis => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, false)?;
                    remaining = i;
                    FieldValue::Duration(Duration::from_millis(data_number.get_value() as u64))
                }
                FieldDataType::DurationMicros => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, false)?;
                    remaining = i;
                    FieldValue::Duration(Duration::from_micros(data_number.get_value() as u64))
                }
                FieldDataType::DurationNanos => {
                    let (i, data_number) =
                        parse_data_number(remaining, template_field.field_length, false)?;
                    remaining = i;
                    FieldValue::Duration(Duration::from_nanos(data_number.get_value() as u64))
                }
                FieldDataType::ProtocolType => {
                    let (i, protocol) = ProtocolTypes::parse(remaining)?;
                    remaining = i;
                    FieldValue::ProtocolType(protocol)
                }
                FieldDataType::Float64 => {
                    let (i, f) = f64::parse(remaining)?;
                    remaining = i;
                    FieldValue::Float64(f)
                }
                FieldDataType::Vec => {
                    let (i, taken) = take(template_field.field_length)(remaining)?;
                    remaining = i;
                    FieldValue::Vec(taken.to_vec())
                }
                FieldDataType::Unknown => {
                    let (i, taken) = take(template_field.field_length)(remaining)?;
                    remaining = i;
                    FieldValue::Vec(taken.to_vec())
                }
            };
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
            sets.push(v10_set.clone());
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
