use std::time::{Duration, SystemTime};

/// Builda a System time from unix_secd and unix_nsecs usually provided by a Netflow Header
pub(crate) fn build_unix_time(secs: u32, n_secs: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH
        + Duration::from_secs(secs.into())
        + Duration::from_nanos(n_secs.into())
}
