//! # IPFix
//!
//! References:
//! - <https://datatracker.ietf.org/doc/html/rfc7011>
//! - <https://en.wikipedia.org/wiki/IP_Flow_Information_Export>
//! - <https://www.ibm.com/docs/en/npi/1.3.1?topic=overview-ipfix-message-format>
//! - <https://www.iana.org/assignments/ipfix/ipfix.xhtml>

use super::common::*;
use crate::variable_versions::ipfix_lookup::*;
use crate::{NetflowPacket, NetflowParseError, ParsedNetflow};

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
type IPFixFieldPair = (IPFixField, FieldValue);

pub fn parse_as_netflow(
    packet: &[u8],
    parser: &mut IPFixParser,
) -> Result<ParsedNetflow, NetflowParseError> {
    IPFix::parse(packet, parser)
        .map(|(remaining, ipfix)| ParsedNetflow::new(remaining, NetflowPacket::IPFix(ipfix)))
        .map_err(|e| NetflowParseError::IPFix(e.to_string()))
}

#[derive(Default, Debug)]
pub struct IPFixParser {
    pub templates: BTreeMap<TemplateId, Template>,
    pub options_templates: BTreeMap<TemplateId, OptionsTemplate>,
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
    #[nom(Map = "|i| Duration::from_secs(i as u64)", Parse = "be_u32")]
    pub export_time: Duration,
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
    #[nom(Parse = "{ |i| parse_set_body(i, parser, header.length, header.header_id) }")]
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
#[nom(ExtraArgs(parser: &mut IPFixParser, id: u16, length: u16))]
pub struct FlowSetBody {
    #[nom(
        Cond = "id == TEMPLATE_ID",
        // Save our templates
        PostExec = "if let Some(template) = template.clone() { parser.templates.insert(template.template_id, template); }"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<Template>,
    #[nom(
        Cond = "id == OPTIONS_TEMPLATE_ID",
        PreExec = "let set_length = length.checked_sub(4).unwrap_or(length);",
        Parse = "{ |i| OptionsTemplate::parse(i, set_length) }",
        // Save our templates
        PostExec = "if let Some(options_template) = options_template.clone() {
                      parser.options_templates.insert(options_template.template_id, options_template);
                    }"
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
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct Data {
    #[nom(Parse = "{ |i| parse_fields::<Template>(i, parser.templates.get(&set_id)) }")]
    pub data_fields: Vec<BTreeMap<usize, (IPFixField, FieldValue)>>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(parser: &mut IPFixParser, set_id: u16))]
pub struct OptionsData {
    #[nom(
        Parse = "{ |i| parse_fields::<OptionsTemplate>(i, parser.options_templates.get(&set_id)) }"
    )]
    pub data_fields: Vec<BTreeMap<usize, (IPFixField, FieldValue)>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
#[nom(ExtraArgs(set_length: u16))]
pub struct OptionsTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub scope_field_count: u16,
    #[nom(
        PreExec = "let combined_count = scope_field_count as usize + 
                       field_count.checked_sub(scope_field_count).unwrap_or(field_count) as usize;",
        Parse = "count(|i| TemplateField::parse(i, true), combined_count)",
        PostExec = "let options_remaining = set_length.checked_sub(field_count * 4).unwrap_or(set_length) > 0;"
    )]
    pub fields: Vec<TemplateField>,
    #[nom(Cond = "options_remaining && !i.is_empty()")]
    #[serde(skip_serializing)]
    padding: Option<u16>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Nom)]
pub struct Template {
    pub template_id: u16,
    pub field_count: u16,
    #[nom(Parse = "{ |i| parse_template_fields(i, field_count) } ")]
    pub fields: Vec<TemplateField>,
}

fn parse_template_fields(i: &[u8], count: u16) -> IResult<&[u8], Vec<TemplateField>> {
    let mut result = vec![];

    let mut remaining = i;

    for _ in 0..count {
        let (i, field) = TemplateField::parse(remaining, false)?;
        result.push(field);
        remaining = i;
    }

    Ok((remaining, result))
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
        PostExec = "let field_type = if options_template && enterprise_number.is_some() {
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

// Custom parse set function to take only length provided by header.
fn parse_sets<'a>(
    i: &'a [u8],
    parser: &mut IPFixParser,
    length: u16,
) -> IResult<&'a [u8], Vec<FlowSet>> {
    let length = length.checked_sub(16).unwrap_or(length);
    let (_, taken) = take(length)(i)?;

    let mut sets = vec![];

    let mut remaining = taken;

    while !remaining.is_empty() {
        let (i, set) = FlowSet::parse(remaining, parser)?;
        sets.push(set);
        remaining = i;
    }

    Ok((remaining, sets))
}

// Custom parse set body function to take only length provided by set header.
fn parse_set_body<'a>(
    i: &'a [u8],
    parser: &mut IPFixParser,
    length: u16,
    id: u16,
) -> IResult<&'a [u8], FlowSetBody> {
    // length - 4 to account for the set header
    let length = length.checked_sub(4).unwrap_or(length);
    let (remaining, taken) = take(length)(i)?;
    let (_, set_body) = FlowSetBody::parse(taken, parser, id, length)?;
    Ok((remaining, set_body))
}

/// Takes a byte stream and a cached template.
/// Fields get matched to static types.
/// Returns BTree of IPFix Types & Fields or IResult Error.
fn parse_fields<'a, T: CommonTemplate>(
    i: &'a [u8],
    template: Option<&T>,
) -> IResult<&'a [u8], Vec<BTreeMap<usize, IPFixFieldPair>>> {
    fn parse_field<'a>(
        i: &'a [u8],
        template_field: &TemplateField,
    ) -> IResult<&'a [u8], FieldValue> {
        // Enterprise Number
        if template_field.enterprise_number.is_some() {
            let (remaining, data_number) = DataNumber::parse(i, 4, false)?;
            Ok((remaining, FieldValue::DataNumber(data_number)))
        // Type matching
        } else {
            Ok(DataNumber::from_field_type(
                i,
                template_field.field_type.into(),
                template_field.field_length,
            ))?
        }
    }

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

    let total_size = template_fields
        .iter()
        .map(|m| m.field_length as usize)
        .sum::<usize>();

    if total_size == 0 {
        return Ok((&[], fields));
    }
    let count: usize = i.len() / total_size;

    let mut error = false;

    // Iter through template fields and push them to a vec.  If we encouter any zero length fields we return an error.
    for _ in 0..count {
        let mut data_field = BTreeMap::new();
        for (c, template_field) in template_fields.iter().enumerate() {
            // If field length is 0 we error
            let (i, field_value) = parse_field(remaining, template_field)?;
            // If we don't move forward for some reason we error
            if i.len() == remaining.len() {
                error = true;
                break;
            }
            remaining = i;
            data_field.insert(c, (template_field.field_type, field_value));
        }
        fields.push(data_field);
    }

    if error {
        Err(NomErr::Error(NomError::new(remaining, ErrorKind::Fail)))
    } else {
        Ok((&[], fields))
    }
}

impl IPFix {
    /// Convert the IPFix to a Vec<u8> of bytes in big-endian order for exporting
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.header.version.to_be_bytes());
        result.extend_from_slice(&self.header.length.to_be_bytes());
        result.extend_from_slice(&(self.header.export_time.as_secs() as u32).to_be_bytes());
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
                if let Some(padding) = &options_template.padding {
                    result_flowset.extend_from_slice(&padding.to_be_bytes());
                }
            }

            if let Some(data) = &flow.body.data {
                for item in data.data_fields.iter() {
                    for (_, (_, v)) in item.iter() {
                        result_flowset.extend_from_slice(&v.to_be_bytes());
                    }
                }
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
