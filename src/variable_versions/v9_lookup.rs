use nom_derive::*;
use serde::Serialize;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub enum ForwardStatus {
    Unknown = 0,
    Fowarded = 1,
    Dropped = 2,
    Consumed = 3,
}

impl From<u8> for ForwardStatus {
    fn from(item: u8) -> Self {
        match item {
            1 => Self::Fowarded,
            2 => Self::Dropped,
            3 => Self::Consumed,
            _ => Self::Unknown,
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub enum ForwardReason {
    Unknown = 0,
    ForwardedUnknown = 64,
    ForwardedFragmented = 65,
    ForwardednotFragmented = 66,
    DroppedUnknown = 128,
    DropACLDeny = 129,
    DropACLdrop = 130,
    DropUnroutable = 131,
    DropAdjacency = 132,
    DropFragmentationAndDFset = 133,
    DropBadheaderChecksum = 134,
    DropBadTotalLength = 135,
    DropBadHeaderLength = 136,
    DropBadTTL = 137,
    DropPolicer = 138,
    DropWRED = 139,
    DropRPF = 140,
    DropForUs = 141,
    DropBadOutputInterface = 142,
    DropHardware = 143,
    ConsumedUnknown = 192,
    TerminatePuntAdjacency = 193,
    TerminateIncompleteAdjacency = 194,
    TerminateForUs = 195,
}

impl From<u8> for ForwardReason {
    fn from(item: u8) -> Self {
        match item {
            64 => Self::ForwardedUnknown,
            65 => Self::ForwardedFragmented,
            66 => Self::ForwardednotFragmented,
            128 => Self::DroppedUnknown,
            129 => Self::DropACLDeny,
            130 => Self::DropACLdrop,
            131 => Self::DropUnroutable,
            132 => Self::DropAdjacency,
            133 => Self::DropFragmentationAndDFset,
            134 => Self::DropBadheaderChecksum,
            135 => Self::DropBadTotalLength,
            136 => Self::DropBadHeaderLength,
            137 => Self::DropBadTTL,
            138 => Self::DropPolicer,
            139 => Self::DropWRED,
            140 => Self::DropRPF,
            141 => Self::DropForUs,
            142 => Self::DropBadOutputInterface,
            143 => Self::DropHardware,
            192 => Self::ConsumedUnknown,
            193 => Self::TerminatePuntAdjacency,
            194 => Self::TerminateIncompleteAdjacency,
            195 => Self::TerminateForUs,
            _ => Self::Unknown,
        }
    }
}

/// Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub struct ForwardStatusType {
    pub status: ForwardStatus,
    pub reason: ForwardReason,
}

impl ForwardStatusType {
    pub fn new(i: u8) -> Self {
        let status = ForwardStatus::from(i >> 6);
        let reason = ForwardReason::from(i << 2);
        ForwardStatusType { status, reason }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub enum FlowDirectionType {
    Ingress = 0,
    Egress = 1,
    Unknown(u8),
}

impl From<u8> for FlowDirectionType {
    fn from(item: u8) -> Self {
        match item {
            0 => Self::Ingress,
            1 => Self::Egress,
            _ => Self::Unknown(item),
        }
    }
}

#[repr(u16)]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    NetflowCache = 4,
    Template = 5,
    #[default]
    Unknown,
}

impl From<u16> for ScopeFieldType {
    fn from(item: u16) -> Self {
        match item {
            1 => ScopeFieldType::System,
            2 => ScopeFieldType::Interface,
            3 => ScopeFieldType::LineCard,
            4 => ScopeFieldType::NetflowCache,
            5 => ScopeFieldType::Template,
            _ => ScopeFieldType::Unknown,
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ForwaringStatus {
    Unknown = 0,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum DataFieldType {
    INBYTES = 1,
    INPKTS = 2,
    FLOWS = 3,
    PROTOCOL = 4,
    SRCTOS = 5,
    TCPFLAGS = 6,
    L4SRCPORT = 7,
    IPV4SRCADDR = 8,
    SRCMASK = 9,
    INPUTSNMP = 10,
    L4DSTPORT = 11,
    IPV4DSTADDR = 12,
    DSTMASK = 13,
    OUTPUTSNMP = 14,
    IPV4NEXTHOP = 15,
    SRCAS = 16,
    DSTAS = 17,
    BGPIPV4NEXTHOP = 18,
    MULDSTPKTS = 19,
    MULDSTBYTES = 20,
    LASTSWITCHED = 21,
    FIRSTSWITCHED = 22,
    OUTBYTES = 23,
    OUTPKTS = 24,
    MINPKTLNGTH = 25,
    MAXPKTLNGTH = 26,
    IPV6SRCADDR = 27,
    IPV6DSTADDR = 28,
    IPV6SRCMASK = 29,
    IPV6DSTMASK = 30,
    IPV6FLOWLABEL = 31,
    ICMPTYPE = 32,
    MULIGMPTYPE = 33,
    SAMPLINGINTERVAL = 34,
    SAMPLINGALGORITHM = 35,
    FLOWACTIVETIMEOUT = 36,
    FLOWINACTIVETIMEOUT = 37,
    ENGINETYPE = 38,
    ENGINEID = 39,
    TOTALBYTESEXP = 40,
    TOTALPKTSEXP = 41,
    TOTALFLOWSEXP = 42,
    IPV4SRCPREFIX = 44,
    IPV4DSTPREFIX = 45,
    MPLSTOPLABELTYPE = 46,
    MPLSTOPLABELIPADDR = 47,
    FLOWSAMPLERID = 48,
    FLOWSAMPLERMODE = 49,
    FLOWSAMPLERRANDOMINTERVAL = 50,
    MINTTL = 52,
    MAXTTL = 53,
    IPV4IDENT = 54,
    DSTTOS = 55,
    INSRCMAC = 56,
    OUTDSTMAC = 57,
    SRCVLAN = 58,
    DSTVLAN = 59,
    IPPROTOCOLVERSION = 60,
    DIRECTION = 61,
    IPV6NEXTHOP = 62,
    BPGIPV6NEXTHOP = 63,
    IPV6OPTIONHEADERS = 64,
    MPLSLABEL1 = 70,
    MPLSLABEL2 = 71,
    MPLSLABEL3 = 72,
    MPLSLABEL4 = 73,
    MPLSLABEL5 = 74,
    MPLSLABEL6 = 75,
    MPLSLABEL7 = 76,
    MPLSLABEL8 = 77,
    MPLSLABEL9 = 78,
    MPLSLABEL10 = 79,
    INDSTMAC = 80,
    OUTSRCMAC = 81,
    IFNAME = 82,
    IFDESC = 83,
    SAMPLERNAME = 84,
    INPERMANENTBYTES = 85,
    INPERMANENTPKTS = 86,
    FRAGMENTOFFSET = 87,
    FORWARDINGSTATUS = 88,
    MPLSPALRD = 90,
    MPLSPREFIXLEN = 91,
    SRCTRAFFICINDEX = 92,
    DSTTRAFFICINDEX = 93,
    APPLICATIONDESCRIPTION = 94,
    APPLICATIONTAG = 95,
    APPLICATIONNAME = 96,
    PostipDiffServCodePoint = 98,
    ReplicationFactor = 99,
    DEPRECATED = 100,
    Layer2packetSectionOffset = 102,
    Layer2packetSectionSize = 103,
    Layer2packetSectionData = 104,
    Unknown,
}

impl From<u16> for DataFieldType {
    fn from(item: u16) -> Self {
        match item {
            1 => DataFieldType::INBYTES,
            2 => DataFieldType::INPKTS,
            3 => DataFieldType::FLOWS,
            4 => DataFieldType::PROTOCOL,
            5 => DataFieldType::SRCTOS,
            6 => DataFieldType::TCPFLAGS,
            7 => DataFieldType::L4SRCPORT,
            8 => DataFieldType::IPV4SRCADDR,
            9 => DataFieldType::SRCMASK,
            10 => DataFieldType::INPUTSNMP,
            11 => DataFieldType::L4DSTPORT,
            12 => DataFieldType::IPV4DSTADDR,
            13 => DataFieldType::DSTMASK,
            14 => DataFieldType::OUTPUTSNMP,
            15 => DataFieldType::IPV4NEXTHOP,
            16 => DataFieldType::SRCAS,
            17 => DataFieldType::DSTAS,
            18 => DataFieldType::BGPIPV4NEXTHOP,
            19 => DataFieldType::MULDSTPKTS,
            20 => DataFieldType::MULDSTBYTES,
            21 => DataFieldType::LASTSWITCHED,
            22 => DataFieldType::FIRSTSWITCHED,
            23 => DataFieldType::OUTBYTES,
            24 => DataFieldType::OUTPKTS,
            25 => DataFieldType::MINPKTLNGTH,
            26 => DataFieldType::MAXPKTLNGTH,
            27 => DataFieldType::IPV6SRCADDR,
            28 => DataFieldType::IPV6DSTADDR,
            29 => DataFieldType::IPV6SRCMASK,
            30 => DataFieldType::IPV6DSTMASK,
            31 => DataFieldType::IPV6FLOWLABEL,
            32 => DataFieldType::ICMPTYPE,
            33 => DataFieldType::MULIGMPTYPE,
            34 => DataFieldType::SAMPLINGINTERVAL,
            35 => DataFieldType::SAMPLINGALGORITHM,
            36 => DataFieldType::FLOWACTIVETIMEOUT,
            37 => DataFieldType::FLOWINACTIVETIMEOUT,
            38 => DataFieldType::ENGINETYPE,
            39 => DataFieldType::ENGINEID,
            40 => DataFieldType::TOTALBYTESEXP,
            41 => DataFieldType::TOTALPKTSEXP,
            42 => DataFieldType::TOTALFLOWSEXP,
            44 => DataFieldType::IPV4SRCPREFIX,
            45 => DataFieldType::IPV4DSTPREFIX,
            46 => DataFieldType::MPLSTOPLABELTYPE,
            47 => DataFieldType::MPLSTOPLABELIPADDR,
            48 => DataFieldType::FLOWSAMPLERID,
            49 => DataFieldType::FLOWSAMPLERMODE,
            50 => DataFieldType::FLOWSAMPLERRANDOMINTERVAL,
            52 => DataFieldType::MINTTL,
            53 => DataFieldType::MAXTTL,
            54 => DataFieldType::IPV4IDENT,
            55 => DataFieldType::DSTTOS,
            56 => DataFieldType::INSRCMAC,
            57 => DataFieldType::OUTDSTMAC,
            58 => DataFieldType::SRCVLAN,
            59 => DataFieldType::DSTVLAN,
            60 => DataFieldType::IPPROTOCOLVERSION,
            61 => DataFieldType::DIRECTION,
            62 => DataFieldType::IPV6NEXTHOP,
            63 => DataFieldType::BPGIPV6NEXTHOP,
            64 => DataFieldType::IPV6OPTIONHEADERS,
            70 => DataFieldType::MPLSLABEL1,
            71 => DataFieldType::MPLSLABEL2,
            72 => DataFieldType::MPLSLABEL3,
            73 => DataFieldType::MPLSLABEL4,
            74 => DataFieldType::MPLSLABEL5,
            75 => DataFieldType::MPLSLABEL6,
            76 => DataFieldType::MPLSLABEL7,
            77 => DataFieldType::MPLSLABEL8,
            78 => DataFieldType::MPLSLABEL9,
            79 => DataFieldType::MPLSLABEL10,
            80 => DataFieldType::INDSTMAC,
            81 => DataFieldType::OUTSRCMAC,
            82 => DataFieldType::IFNAME,
            83 => DataFieldType::IFDESC,
            84 => DataFieldType::SAMPLERNAME,
            85 => DataFieldType::INPERMANENTBYTES,
            86 => DataFieldType::INPERMANENTPKTS,
            88 => DataFieldType::FRAGMENTOFFSET,
            89 => DataFieldType::FORWARDINGSTATUS,
            90 => DataFieldType::MPLSPALRD,
            91 => DataFieldType::MPLSPREFIXLEN,
            92 => DataFieldType::SRCTRAFFICINDEX,
            93 => DataFieldType::DSTTRAFFICINDEX,
            94 => DataFieldType::APPLICATIONDESCRIPTION,
            95 => DataFieldType::APPLICATIONTAG,
            96 => DataFieldType::APPLICATIONNAME,
            98 => DataFieldType::PostipDiffServCodePoint,
            99 => DataFieldType::ReplicationFactor,
            102 => DataFieldType::Layer2packetSectionOffset,
            103 => DataFieldType::Layer2packetSectionSize,
            104 => DataFieldType::Layer2packetSectionData,
            _ => DataFieldType::Unknown,
        }
    }
}
