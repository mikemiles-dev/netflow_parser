//! Custom decoded field types for NetFlow V9 and IPFIX fields.
//!
//! Some flow fields encode structured data within a single integer value.
//! This module provides typed enums that decode these fields into meaningful variants,
//! similar to how [`ProtocolTypes`](crate::protocol::ProtocolTypes) decodes protocol numbers.
//!
//! # Types
//!
//! - [`ForwardingStatus`] — Decodes field ID 89 (RFC 7270) into status category and reason code.

mod forwarding_status;

pub use forwarding_status::ForwardingStatus;
