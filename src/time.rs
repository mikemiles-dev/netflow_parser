use std::time::{Duration, SystemTime};

pub fn convert_system_time(i: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(i.into())
}
