//! Fragment Flags field decoding (IPFIX field ID 197).
//!
//! Encodes IPv4/IPv6 fragment flags as a 3-bit bitmask:
//! - Bit 0: Reserved
//! - Bit 1: Don't Fragment (DF)
//! - Bit 2: More Fragments (MF)

use nom::IResult;
use nom_derive::Parse;
use serde::Serialize;

/// Decoded fragment flags from an IPFIX field (ID 197).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub struct FragmentFlags {
    pub reserved: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

impl FragmentFlags {
    /// Parse a `FragmentFlags` from a byte slice by reading a single `u8`.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (remaining, value) = u8::parse(input)?;
        Ok((remaining, Self::from(value)))
    }
}

impl From<u8> for FragmentFlags {
    fn from(value: u8) -> Self {
        Self {
            reserved: value & 0x01 != 0,
            dont_fragment: value & 0x02 != 0,
            more_fragments: value & 0x04 != 0,
        }
    }
}

impl From<FragmentFlags> for u8 {
    fn from(flags: FragmentFlags) -> Self {
        (flags.reserved as u8)
            | ((flags.dont_fragment as u8) << 1)
            | ((flags.more_fragments as u8) << 2)
    }
}

impl PartialOrd for FragmentFlags {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FragmentFlags {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u8::from(*self).cmp(&u8::from(*other))
    }
}

#[cfg(test)]
mod fragment_flags_tests {
    use super::FragmentFlags;
    use insta::assert_yaml_snapshot;

    #[test]
    fn test_round_trip() {
        for byte in 0..=255u8 {
            let flags = FragmentFlags::from(byte);
            let back = u8::from(flags);
            assert_eq!(byte & 0x07, back, "round-trip failed for {byte:#04x}");
        }
    }

    #[test]
    fn test_known_values() {
        assert_eq!(
            FragmentFlags::from(0x00),
            FragmentFlags {
                reserved: false,
                dont_fragment: false,
                more_fragments: false
            }
        );
        assert_eq!(
            FragmentFlags::from(0x02),
            FragmentFlags {
                reserved: false,
                dont_fragment: true,
                more_fragments: false
            }
        );
        assert_eq!(
            FragmentFlags::from(0x04),
            FragmentFlags {
                reserved: false,
                dont_fragment: false,
                more_fragments: true
            }
        );
        assert_eq!(
            FragmentFlags::from(0x07),
            FragmentFlags {
                reserved: true,
                dont_fragment: true,
                more_fragments: true
            }
        );
    }

    #[test]
    fn test_all_fragment_flags() {
        let flags: Vec<_> = (0..=7u8).map(FragmentFlags::from).collect();
        assert_yaml_snapshot!(flags);
    }
}
