//! Enterprise field registry for user-defined IPFIX enterprise fields.
//!
//! This module provides a mechanism for library users to register custom enterprise field
//! definitions without modifying the library source code. The parser automatically recognizes
//! built-in enterprise fields, but you can extend support for custom vendors.
//!
//! # Common Enterprise Numbers
//!
//! The following vendors have built-in support via dedicated enum types:
//!
//! | Vendor | Enterprise ID | Type |
//! |--------|---------------|------|
//! | IANA (Standard Fields) | 0 | [`IANAIPFixField`](super::ipfix_lookup::IANAIPFixField) |
//! | Cisco Systems | 9 | [`CiscoIPFixField`](super::ipfix_lookup::CiscoIPFixField) |
//! | Citrix NetScaler | 5951 | [`NetscalerIPFixField`](super::ipfix_lookup::NetscalerIPFixField) |
//! | YAF (Yet Another Flowmeter) | 6871 | [`YafIPFixField`](super::ipfix_lookup::YafIPFixField) |
//! | VMware | 6876 | [`VMWareIPFixField`](super::ipfix_lookup::VMWareIPFixField) |
//! | Fortinet | 12356 | Built-in support |
//!
//! For enterprise fields from other vendors or custom implementations, use this registry.
//!
//! # Usage Example
//!
//! ```
//! use netflow_parser::variable_versions::enterprise_registry::{EnterpriseFieldRegistry, EnterpriseFieldDef};
//! use netflow_parser::variable_versions::data_number::FieldDataType;
//! use netflow_parser::variable_versions::Config;
//!
//! // Create a registry
//! let mut registry = EnterpriseFieldRegistry::new();
//!
//! // Register custom fields
//! registry.register(EnterpriseFieldDef::new(
//!     12345,  // Your enterprise ID
//!     1,      // Field number
//!     "myCustomField",
//!     FieldDataType::UnsignedDataNumber,
//! ));
//!
//! // Use with parser configuration
//! let config = Config::with_enterprise_registry(10000, None, registry);
//! ```

use super::data_number::FieldDataType;
use std::collections::HashMap;

/// Definition of a custom enterprise field that can be registered by library users
///
/// # Examples
///
/// ```rust
/// use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;
/// use netflow_parser::variable_versions::data_number::FieldDataType;
///
/// let field_def = EnterpriseFieldDef {
///     enterprise_number: 12345,
///     field_number: 1,
///     name: "customMetric".to_string(),
///     data_type: FieldDataType::UnsignedDataNumber,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseFieldDef {
    /// The enterprise number assigned by IANA
    pub enterprise_number: u32,
    /// The field number within this enterprise
    pub field_number: u16,
    /// Human-readable field name (used for debugging and display)
    pub name: String,
    /// The data type used for parsing this field
    pub data_type: FieldDataType,
}

impl EnterpriseFieldDef {
    /// Create a new enterprise field definition
    ///
    /// # Arguments
    ///
    /// * `enterprise_number` - The enterprise number assigned by IANA
    /// * `field_number` - The field number within this enterprise
    /// * `name` - Human-readable field name
    /// * `data_type` - The data type used for parsing this field
    ///
    /// # Examples
    ///
    /// ```rust
    /// use netflow_parser::variable_versions::enterprise_registry::EnterpriseFieldDef;
    /// use netflow_parser::variable_versions::data_number::FieldDataType;
    ///
    /// let field_def = EnterpriseFieldDef::new(
    ///     12345,
    ///     1,
    ///     "customMetric",
    ///     FieldDataType::UnsignedDataNumber,
    /// );
    /// ```
    pub fn new(
        enterprise_number: u32,
        field_number: u16,
        name: impl Into<String>,
        data_type: FieldDataType,
    ) -> Self {
        Self {
            enterprise_number,
            field_number,
            name: name.into(),
            data_type,
        }
    }
}

/// Registry for storing user-defined enterprise field definitions
///
/// This registry is used internally by parsers to look up custom field metadata
/// during parsing.
#[derive(Debug, Clone, Default)]
pub struct EnterpriseFieldRegistry {
    // Key: (enterprise_number, field_number)
    fields: HashMap<(u32, u16), EnterpriseFieldDef>,
}

impl EnterpriseFieldRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Register a single enterprise field definition
    ///
    /// If a field with the same enterprise number and field number already exists,
    /// it will be replaced.
    pub fn register(&mut self, def: EnterpriseFieldDef) {
        self.fields
            .insert((def.enterprise_number, def.field_number), def);
    }

    /// Register multiple enterprise field definitions at once
    pub fn register_many(&mut self, defs: impl IntoIterator<Item = EnterpriseFieldDef>) {
        for def in defs {
            self.register(def);
        }
    }

    /// Look up a field definition by enterprise number and field number
    pub fn get(
        &self,
        enterprise_number: u32,
        field_number: u16,
    ) -> Option<&EnterpriseFieldDef> {
        self.fields.get(&(enterprise_number, field_number))
    }

    /// Check if a field is registered
    pub fn contains(&self, enterprise_number: u32, field_number: u16) -> bool {
        self.fields.contains_key(&(enterprise_number, field_number))
    }

    /// Get the number of registered fields
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Clear all registered fields
    pub fn clear(&mut self) {
        self.fields.clear();
    }
}
