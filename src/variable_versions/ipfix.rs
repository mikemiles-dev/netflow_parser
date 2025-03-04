//! # IPFix
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::data_number::*;
use crate::variable_versions::ipfix_lookup::*;
use crate::{NetflowPacket, NetflowParseError, ParsedNetflow, PartialParse};

use Nom;
use nom::Err as NomErr;
use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::map_res;
use nom::error::{Error as NomError, ErrorKind};
use nom::multi::count;
use nom::number::complete::{be_u8, be_u16};
use nom_derive::*;
use serde::Serialize;

use std::collections::BTreeMap;

const OPTIONS_TEMPLATE_ID: u16 = 3;
const SET_MIN_RANGE: u16 = 255;

type TemplateId = u16;
type IPFixFieldPair = (IPFixField, FieldValue);

pub(crate) fn parse_netflow_ipfix(
    packet: &[u8],
    parser: &mut IPFixParser,
) -> Result<ParsedNetflow, NetflowParseError> {
    IPFix::parse(packet, parser)
        .map(|(remaining, ipfix)| ParsedNetflow::new(remaining, NetflowPacket::IPFix(ipfix)))
        .map_err(|e| {
            NetflowParseError::Partial(PartialParse {
                version: 10,
                error: e.to_string(),
                remaining: packet.to_vec(),
            })
        })
}

#[derive(Default, Debug)]
pub struct IPFixParser {
    pub templates: BTreeMap<TemplateId, Template>,
    pub options_templates: BTreeMap<TemplateId, OptionsTemplate>,
}

// Custom parse set function to take only length provided by header.
fn parse_sets<'a>(
    i: &'a [u8],
    parser: &mut IPFixParser,
    length: u16,
) -> IResult<&'a [u8], Vec<FlowSet>> {
    let length = length.checked_sub(16).unwrap_or(length);
    let (i, taken) = take(length)(i)?;
    let mut sets = vec![];
    let mut remaining = taken;

    while !remaining.is_empty() {
        let (i, set) = FlowSet::parse(remaining, parser)?;
        sets.push(set);
        remaining = i;
    }

    Ok((i, sets))
}

#[derive(Nom, Debug, PartialEq, Clone, Serialize)]
#[nom(ExtraArgs(parser: &mut IPFixParser))]
pub struct IPFix {
    /// IPFix Header
    pub header: Header,
    /// Sets
    #[nom(Parse = "{ |i| parse_sets(i, parser, header.length) }")]
    pub flowsets: Vec<FlowSet>,
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
#[nom(ExtraArgs(parser: &mut IPFixParser, id: u16))]
pub struct FlowSetBody {
    #[nom(
        Cond = "id < SET_MIN_RANGE && id != OPTIONS_TEMPLATE_ID",
        Verify = "usize::from(template.field_count) == template.fields.len()",
        Verify = "template.get_fields().iter().any(|f| f.field_length > 0)",
        // Save our templates
        PostExec = "if let Some(template) = template.clone() { parser.templates.insert(template.template_id, template); }"
        ,
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Template>,
    #[nom(
        Cond = "id == OPTIONS_TEMPLATE_ID",
        Parse = "{ |i| OptionsTemplate::parse(i) }",
        Verify = "usize::from(options_template.field_count) == options_template.fields.len()",
        Verify = "options_template.get_fields().any(|f| f.field_length > 0)",
        // Save our templates
        PostExec = "if let Some(options_template) = options_template.clone() {
                      parser.options_templates.insert(options_template.template_id, options_template);
                    }",
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_template: Option<OptionsTemplate>,
    // Data
    #[nom(
        Cond = "id > SET_MIN_RANGE && parser.templates.contains_key(&id)",
        Parse = "{ |i| Data::parse(i, parser, id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    // OptionsData
    #[nom(
        Cond = "id > SET_MIN_RANGE && parser.options_templates.contains_key(&id)",
        Parse = "{ |i| OptionsData::parse(i, parser, id) }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_data: Option<OptionsData>,
    #[serde(skip_serializing)]
    pub padding: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct Data {
    #[nom(
        PreExec = "let template = parser.templates.get(&set_id).cloned().unwrap_or_default();",
        Parse = "{ |i| parse_fields::<Template>(i, template) }",
        Verify = "template.get_fields().any(|f| f.field_length > 0)"
    )]
    pub data_fields: Vec<BTreeMap<usize, (IPFixField, FieldValue)>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct OptionsData {
    #[nom(
        PreExec = "let template = parser.options_templates.get(&set_id).cloned().unwrap_or_default();",
        Parse = "{ |i| parse_fields::<OptionsTemplate>(i, template) }",
        Verify = "template.get_fields().any(|f| f.field_length > 0)"
    )]
    pub data_fields: Vec<BTreeMap<usize, (IPFixField, FieldValue)>>,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct OptionsTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    #[nom(
        PreExec = "let combined_count = usize::from(scope_field_count.saturating_add(
                       field_count.checked_sub(scope_field_count).unwrap_or(field_count)));",
        Parse = "count(TemplateField::parse, combined_count)"
    )]
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom, Default)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<TemplateField>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct TemplateField {
    pub field_type_number: u16,
    #[nom(Value(IPFixField::from(field_type_number)))]
    pub field_type: IPFixField,
    pub field_length: u16,
    #[nom(
        Cond = "field_type_number > 32767",
        PostExec = "let field_type_number = if enterprise_number.is_some() {
                      field_type_number.overflowing_sub(32768).0
                    } else { field_type_number };",
        PostExec = "let field_type = if enterprise_number.is_some() {
                        IPFixField::Enterprise
                    } else { field_type };"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_number: Option<u32>,
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
fn parse_fields<T: CommonTemplate + std::fmt::Debug>(
    i: &[u8],
    template: T,
) -> IResult<&[u8], Vec<BTreeMap<usize, IPFixFieldPair>>> {
    if template.get_fields().is_empty() {
        return Err(NomErr::Error(NomError::new(i, ErrorKind::Fail)));
    }

    let mut total_taken = 0;

    // If no fields there are no fields to parse, return an error.
    let mut fields = vec![];
    let mut remaining = i;
    for (c, field) in template.get_fields().iter().enumerate() {
        // Iter through template fields and push them to a vec.  If we encouter any zero length fields we return an error.
        let mut data_field = BTreeMap::new();
        let (i, field_value) = parse_field(remaining, field)?;
        let taken = remaining.len().saturating_sub(i.len());
        total_taken += taken;
        remaining = i;
        data_field.insert(c, (field.field_type, field_value));
        fields.push(data_field);
    }

    let remaining = if !remaining.is_empty() && remaining.len() >= total_taken {
        let (remaining, more) = parse_fields(remaining, template)?;
        fields.extend(more);
        remaining
    } else {
        remaining
    };

    Ok((remaining, fields))
}

// If 65335, read 1 byte.
// If that byte is < 255 that is the length.
// If that byte is == 255 then read 2 bytes.  That is the length.
// Otherwise, return the field length.
fn calculate_field_length<'a>(
    i: &'a [u8],
    template_field: &TemplateField,
) -> IResult<&'a [u8], u16> {
    match template_field.field_length {
        65535 => {
            let (i, length) = be_u8(i)?;
            if length == 255 {
                be_u16(i)
            } else {
                Ok((i, u16::from(length)))
            }
        }
        length => Ok((i, length)),
    }
}

fn parse_field<'a>(
    i: &'a [u8],
    template_field: &TemplateField,
) -> IResult<&'a [u8], FieldValue> {
    let (i, length) = calculate_field_length(i, template_field)?;
    if template_field.enterprise_number.is_some() {
        let (i, data) = take(length)(i)?;
        Ok((i, FieldValue::Vec(data.to_vec())))
    } else {
        FieldValue::from_field_type(i, template_field.field_type.into(), length)
    }
}

impl IPFix {
    /// Convert the IPFix to a `Vec<u8>` of bytes in big-endian order for exporting
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.header.version.to_be_bytes());
        result.extend_from_slice(&self.header.length.to_be_bytes());
        result.extend_from_slice(&self.header.export_time.to_be_bytes());
        result.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        result.extend_from_slice(&self.header.observation_domain_id.to_be_bytes());

        for flow in &self.flowsets {
            result.extend_from_slice(&flow.header.header_id.to_be_bytes());
            result.extend_from_slice(&flow.header.length.to_be_bytes());

            let mut result_flowset = vec![];

            if let Some(template) = &flow.body.template {
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

            if let Some(options_template) = &flow.body.options_template {
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

            if let Some(data) = &flow.body.data {
                for item in data.data_fields.iter() {
                    for (_, (_, v)) in item.iter() {
                        result_flowset.extend_from_slice(&v.to_be_bytes());
                    }
                }

                result_flowset.extend_from_slice(&flow.body.padding);
            }

            if let Some(data) = &flow.body.options_data {
                for item in data.data_fields.iter() {
                    for (_, (_, v)) in item.iter() {
                        result_flowset.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }

            result.append(&mut result_flowset);
        }

        result
    }
}
