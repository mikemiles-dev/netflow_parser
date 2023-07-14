use nom_derive::*;
use serde::Serialize;

#[repr(u16)]
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ScopeFieldType {
    System = 1,
    Interface = 2,
    LineCard = 3,
    NetflowCache = 4,
    Template = 5,
    #[default]
    Unknown = 0,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
pub enum ForwaringStatus {
    Unknown = 0,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Nom)]
#[nom(Selector = "u16")]
pub enum DataFieldType {
    #[nom(Selector = "1")]
    INBYTES,
    #[nom(Selector = "2")]
    INPKTS,
    #[nom(Selector = "3")]
    FLOWS,
    #[nom(Selector = "4")]
    PROTOCOL,
    #[nom(Selector = "5")]
    SRCTOS,
    #[nom(Selector = "6")]
    TCPFLAGS,
    #[nom(Selector = "7")]
    L4SRCPORT,
    #[nom(Selector = "8")]
    IPV4SRCADDR,
    #[nom(Selector = "9")]
    SRCMASK,
    #[nom(Selector = "10")]
    INPUTSNMP,
    #[nom(Selector = "11")]
    L4DSTPORT,
    #[nom(Selector = "12")]
    IPV4DSTADDR,
    #[nom(Selector = "13")]
    DSTMASK,
    #[nom(Selector = "14")]
    OUTPUTSNMP,
    #[nom(Selector = "15")]
    IPV4NEXTHOP,
    #[nom(Selector = "16")]
    SRCAS,
    #[nom(Selector = "17")]
    DSTAS,
    #[nom(Selector = "18")]
    BGPIPV4NEXTHOP,
    #[nom(Selector = "19")]
    MULDSTPKTS,
    #[nom(Selector = "20")]
    MULDSTBYTES,
    #[nom(Selector = "21")]
    LASTSWITCHED,
    #[nom(Selector = "22")]
    FIRSTSWITCHED,
    #[nom(Selector = "23")]
    OUTBYTES,
    #[nom(Selector = "24")]
    OUTPKTS,
    #[nom(Selector = "25")]
    MINPKTLNGTH,
    #[nom(Selector = "26")]
    MAXPKTLNGTH,
    #[nom(Selector = "27")]
    IPV6SRCADDR,
    #[nom(Selector = "28")]
    IPV6DSTADDR,
    #[nom(Selector = "29")]
    IPV6SRCMASK,
    #[nom(Selector = "30")]
    IPV6DSTMASK,
    #[nom(Selector = "31")]
    IPV6FLOWLABEL,
    #[nom(Selector = "32")]
    ICMPTYPE,
    #[nom(Selector = "33")]
    MULIGMPTYPE,
    #[nom(Selector = "34")]
    SAMPLINGINTERVAL,
    #[nom(Selector = "35")]
    SAMPLINGALGORITHM,
    #[nom(Selector = "36")]
    FLOWACTIVETIMEOUT,
    #[nom(Selector = "37")]
    FLOWINACTIVETIMEOUT,
    #[nom(Selector = "38")]
    ENGINETYPE,
    #[nom(Selector = "39")]
    ENGINEID,
    #[nom(Selector = "40")]
    TOTALBYTESEXP,
    #[nom(Selector = "41")]
    TOTALPKTSEXP,
    #[nom(Selector = "42")]
    TOTALFLOWSEXP,
    #[nom(Selector = "44")]
    IPV4SRCPREFIX,
    #[nom(Selector = "45")]
    IPV4DSTPREFIX,
    #[nom(Selector = "46")]
    MPLSTOPLABELTYPE,
    #[nom(Selector = "47")]
    MPLSTOPLABELIPADDR,
    #[nom(Selector = "48")]
    FLOWSAMPLERID,
    #[nom(Selector = "49")]
    FLOWSAMPLERMODE,
    #[nom(Selector = "50")]
    FLOWSAMPLERRANDOMINTERVAL,
    #[nom(Selector = "52")]
    MINTTL,
    #[nom(Selector = "53")]
    MAXTTL,
    #[nom(Selector = "54")]
    IPV4IDENT,
    #[nom(Selector = "55")]
    DSTTOS,
    #[nom(Selector = "56")]
    INSRCMAC,
    #[nom(Selector = "57")]
    OUTDSTMAC,
    #[nom(Selector = "58")]
    SRCVLAN,
    #[nom(Selector = "59")]
    DSTVLAN,
    #[nom(Selector = "60")]
    IPPROTOCOLVERSION,
    #[nom(Selector = "61")]
    DIRECTION,
    #[nom(Selector = "62")]
    IPV6NEXTHOP,
    #[nom(Selector = "63")]
    BPGIPV6NEXTHOP,
    #[nom(Selector = "64")]
    IPV6OPTIONHEADERS,
    #[nom(Selector = "70")]
    MPLSLABEL1,
    #[nom(Selector = "71")]
    MPLSLABEL2,
    #[nom(Selector = "72")]
    MPLSLABEL3,
    #[nom(Selector = "73")]
    MPLSLABEL4,
    #[nom(Selector = "74")]
    MPLSLABEL5,
    #[nom(Selector = "75")]
    MPLSLABEL6,
    #[nom(Selector = "76")]
    MPLSLABEL7,
    #[nom(Selector = "77")]
    MPLSLABEL8,
    #[nom(Selector = "78")]
    MPLSLABEL9,
    #[nom(Selector = "79")]
    MPLSLABEL10,
    #[nom(Selector = "80")]
    INDSTMAC,
    #[nom(Selector = "81")]
    OUTSRCMAC,
    #[nom(Selector = "82")]
    IFNAME,
    #[nom(Selector = "83")]
    IFDESC,
    #[nom(Selector = "84")]
    SAMPLERNAME,
    #[nom(Selector = "85")]
    INPERMANENTBYTES,
    #[nom(Selector = "86")]
    INPERMANENTPKTS,
    #[nom(Selector = "88")]
    FRAGMENTOFFSET,
    #[nom(Selector = "89")]
    FORWARDINGSTATUS,
    #[nom(Selector = "90")]
    MPLSPALRD,
    #[nom(Selector = "91")]
    MPLSPREFIXLEN,
    #[nom(Selector = "92")]
    SRCTRAFFICINDEX,
    #[nom(Selector = "93")]
    DSTTRAFFICINDEX,
    #[nom(Selector = "94")]
    APPLICATIONDESCRIPTION,
    #[nom(Selector = "95")]
    APPLICATIONTAG,
    #[nom(Selector = "96")]
    APPLICATIONNAME,
    #[nom(Selector = "98")]
    PostipDiffServCodePoint,
    #[nom(Selector = "99")]
    ReplicationFactor,
    #[nom(Selector = "100")]
    DEPRECATED,
    #[nom(Selector = "102")]
    Layer2packetSectionOffset,
    #[nom(Selector = "103")]
    Layer2packetSectionSize,
    #[nom(Selector = "104")]
    Layer2packetSectionData,
    #[nom(Selector = "_")]
    Unknown,
}
