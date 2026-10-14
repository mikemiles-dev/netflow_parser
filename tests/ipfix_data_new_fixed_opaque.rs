use netflow_parser::variable_versions::field_value::FieldValue;
use netflow_parser::variable_versions::ipfix::Data;
use netflow_parser::variable_versions::ipfix::lookup::IPFixField;

#[test]
fn data_new_accepts_fixed_opaque_values_larger_than_254_octets() {
    let value = vec![0x5a; 300];

    let data = Data::new(vec![vec![(
        IPFixField::new(266, None),
        FieldValue::Vec(value.clone()),
    )]]);

    assert_eq!(data.fields[0][0].1, FieldValue::Vec(value));
    assert!(!data.has_varlen_metadata());
}
