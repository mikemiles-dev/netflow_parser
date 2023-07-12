use nom_derive::*;
use serde::Serialize;

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    NetflowCache = 4,
    Template = 5,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ForwaringStatus {
    Unknown = 0,
}
