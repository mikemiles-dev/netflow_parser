use nom_derive::*;
use serde::Serialize;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ForwaringStatus {
    Unknown = 0,
}
