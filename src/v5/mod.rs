use nom_derive::*;
use Nom;

#[derive(Debug, Nom, Clone)]
pub struct V5 {
    #[nom(Parse = "{ V5Header::parse }")]
    pub header: V5Header,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Nom)]
pub struct V5Header {
    pub version: u8,
    pub count: u8,
    pub sys_up_time: u16,
    pub unix_secs: u16,
    pub unix_nsecs: u16,
    pub flow_sequence: u16,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u8,
}

pub struct V5Body {}
