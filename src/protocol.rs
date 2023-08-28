use nom_derive::*;
use serde::Serialize;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Serialize, Nom)]
pub enum ProtocolTypes {
    HOPOPT = 0,
    ICMP = 1,
    IGMP = 2,
    GGP = 3,
    IPv4 = 4,
    ST = 5,
    TCP = 6,
    CBT = 7,
    EGP = 8,
    IGP = 9,
    BbcRccMon = 10,
    NVPII = 11,
    PUP = 12,
    ARGUS = 13,
    EMCON = 14,
    XNET = 15,
    CHAOS = 16,
    UDP = 17,
    MUX = 18,
    DcnMEAS = 19,
    HMP = 20,
    PRM = 21,
    XnxIDP = 22,
    TRUNK1 = 23,
    TRUNK2 = 24,
    LEAF1 = 25,
    LEAF2 = 26,
    RDP = 27,
    IRTP = 28,
    ISOTP4 = 29,
    NETBLT = 30,
    MfeNSP = 31,
    MeritINP = 32,
    DCCP = 33,
    ThreePC = 34,
    IDPR = 35,
    XTP = 36,
    DDP = 37,
    IdprCMTP = 38,
    TPpp = 39,
    IL = 40,
    IPv6 = 41,
    SDRP = 42,
    IPv6Route = 43,
    IPv6Frag = 44,
    IDRP = 45,
    RSVP = 46,
    GRE = 47,
    DSR = 48,
    BNA = 49,
    ESP = 50,
    AH = 51,
    INLSP = 52,
    SWIPE = 53,
    NARP = 54,
    MOBILE = 55,
    TLSP = 56,
    SKIP = 57,
    IPv6ICMP = 58,
    IPv6NoNxt = 59,
    IPv6Opts = 60,
    AnyDistributedProtocol = 61,
    CFTP = 62,
    AnyLocalNetwork = 63,
    SatEXPAK = 64,
    KRYPTOLAN = 65,
    RVD = 66,
    IPPC = 67,
    AnyDistributedFileSystem = 68,
    SatMON = 69,
    VISA = 70,
    IPCV = 71,
    CPNX = 72,
    CPHB = 73,
    WSN = 74,
    PVP = 75,
    BrSatMON = 76,
    SunND = 77,
    WbMON = 78,
    WbEXPAK = 79,
    IsoIP = 80,
    VMTP = 81,
    SecureVMTP = 82,
    VINES = 83,
    IPTM = 84,
    NsfnetIGP = 85,
    DGP = 86,
    TCF = 87,
    EIGRP = 88,
    OSPFIGP = 89,
    SpriteRPC = 90,
    LARP = 91,
    MTP = 92,
    AX25 = 93,
    IPIP = 94,
    MICP = 95,
    SccSP = 96,
    ETHERIP = 97,
    ENCAP = 98,
    AnyPrivateEncryptionScheme = 99,
    GMTP = 100,
    IFMP = 101,
    PNNI = 102,
    PIM = 103,
    ARIS = 104,
    SCPS = 105,
    QNX = 106,
    AN = 107,
    IPComp = 108,
    SNP = 109,
    CompaqPeer = 110,
    IPXinIP = 111,
    VRRP = 112,
    PGM = 113,
    Any0HopProtocol = 114,
    L2TP = 115,
    DDX = 116,
    IATP = 117,
    STP = 118,
    SRP = 119,
    UTI = 120,
    SMP = 121,
    SM = 122,
    PTP = 123,
    ISISoverIPv4 = 124,
    FIRE = 125,
    CRTP = 126,
    CRUDP = 127,
    SSCOPMCE = 128,
    IPLT = 129,
    SPS = 130,
    PIPE = 131,
    SCTP = 132,
    FC = 133,
    RsvpE2EIGNORE = 134,
    MobilityHeader = 135,
    UDPLite = 136,
    MPLSinIP = 137,
    Manet = 138,
    HIP = 139,
    Shim6 = 140,
    WESP = 141,
    ROHC = 142,
    Ethernet = 143,
    AGGFRAG = 144,
    Unknown,
    Reserved = 255,
}

impl From<u8> for ProtocolTypes {
    fn from(item: u8) -> Self {
        match item {
            1 => ProtocolTypes::HOPOPT,
            2 => ProtocolTypes::ICMP,
            3 => ProtocolTypes::IGMP,
            4 => ProtocolTypes::IPv4,
            5 => ProtocolTypes::ST,
            6 => ProtocolTypes::TCP,
            7 => ProtocolTypes::CBT,
            8 => ProtocolTypes::EGP,
            9 => ProtocolTypes::IGP,
            10 => ProtocolTypes::BbcRccMon,
            11 => ProtocolTypes::NVPII,
            12 => ProtocolTypes::PUP,
            13 => ProtocolTypes::ARGUS,
            14 => ProtocolTypes::EMCON,
            15 => ProtocolTypes::XNET,
            16 => ProtocolTypes::CHAOS,
            17 => ProtocolTypes::UDP,
            18 => ProtocolTypes::MUX,
            19 => ProtocolTypes::DcnMEAS,
            20 => ProtocolTypes::HMP,
            21 => ProtocolTypes::PRM,
            22 => ProtocolTypes::XnxIDP,
            23 => ProtocolTypes::TRUNK1,
            24 => ProtocolTypes::TRUNK2,
            25 => ProtocolTypes::LEAF1,
            26 => ProtocolTypes::LEAF2,
            27 => ProtocolTypes::RDP,
            28 => ProtocolTypes::IRTP,
            29 => ProtocolTypes::ISOTP4,
            30 => ProtocolTypes::NETBLT,
            31 => ProtocolTypes::MfeNSP,
            32 => ProtocolTypes::MeritINP,
            33 => ProtocolTypes::DCCP,
            34 => ProtocolTypes::ThreePC,
            35 => ProtocolTypes::IDPR,
            36 => ProtocolTypes::XTP,
            37 => ProtocolTypes::DDP,
            38 => ProtocolTypes::IdprCMTP,
            39 => ProtocolTypes::TPpp,
            40 => ProtocolTypes::IL,
            41 => ProtocolTypes::IPv6,
            42 => ProtocolTypes::SDRP,
            43 => ProtocolTypes::IPv6Route,
            44 => ProtocolTypes::IPv6Frag,
            45 => ProtocolTypes::IDRP,
            46 => ProtocolTypes::RSVP,
            47 => ProtocolTypes::GRE,
            48 => ProtocolTypes::DSR,
            49 => ProtocolTypes::BNA,
            50 => ProtocolTypes::ESP,
            51 => ProtocolTypes::AH,
            52 => ProtocolTypes::INLSP,
            53 => ProtocolTypes::SWIPE,
            54 => ProtocolTypes::NARP,
            55 => ProtocolTypes::MOBILE,
            56 => ProtocolTypes::TLSP,
            57 => ProtocolTypes::SKIP,
            58 => ProtocolTypes::IPv6ICMP,
            59 => ProtocolTypes::IPv6NoNxt,
            60 => ProtocolTypes::IPv6Opts,
            61 => ProtocolTypes::AnyDistributedProtocol,
            62 => ProtocolTypes::CFTP,
            63 => ProtocolTypes::AnyLocalNetwork,
            64 => ProtocolTypes::SatEXPAK,
            65 => ProtocolTypes::KRYPTOLAN,
            66 => ProtocolTypes::RVD,
            67 => ProtocolTypes::IPPC,
            68 => ProtocolTypes::AnyDistributedFileSystem,
            69 => ProtocolTypes::SatMON,
            70 => ProtocolTypes::VISA,
            71 => ProtocolTypes::IPCV,
            72 => ProtocolTypes::CPNX,
            73 => ProtocolTypes::CPHB,
            74 => ProtocolTypes::WSN,
            75 => ProtocolTypes::PVP,
            76 => ProtocolTypes::BrSatMON,
            77 => ProtocolTypes::SunND,
            78 => ProtocolTypes::WbMON,
            79 => ProtocolTypes::WbEXPAK,
            80 => ProtocolTypes::IsoIP,
            81 => ProtocolTypes::VMTP,
            82 => ProtocolTypes::SecureVMTP,
            83 => ProtocolTypes::VINES,
            84 => ProtocolTypes::IPTM,
            85 => ProtocolTypes::NsfnetIGP,
            86 => ProtocolTypes::DGP,
            87 => ProtocolTypes::TCF,
            88 => ProtocolTypes::EIGRP,
            89 => ProtocolTypes::OSPFIGP,
            90 => ProtocolTypes::SpriteRPC,
            91 => ProtocolTypes::LARP,
            92 => ProtocolTypes::MTP,
            93 => ProtocolTypes::AX25,
            94 => ProtocolTypes::IPIP,
            95 => ProtocolTypes::MICP,
            96 => ProtocolTypes::SccSP,
            97 => ProtocolTypes::ETHERIP,
            98 => ProtocolTypes::ENCAP,
            99 => ProtocolTypes::AnyPrivateEncryptionScheme,
            100 => ProtocolTypes::GMTP,
            101 => ProtocolTypes::IFMP,
            102 => ProtocolTypes::PNNI,
            103 => ProtocolTypes::PIM,
            104 => ProtocolTypes::ARIS,
            105 => ProtocolTypes::SCPS,
            106 => ProtocolTypes::QNX,
            107 => ProtocolTypes::AN,
            108 => ProtocolTypes::IPComp,
            109 => ProtocolTypes::SNP,
            110 => ProtocolTypes::CompaqPeer,
            111 => ProtocolTypes::IPXinIP,
            112 => ProtocolTypes::VRRP,
            113 => ProtocolTypes::PGM,
            114 => ProtocolTypes::Any0HopProtocol,
            115 => ProtocolTypes::L2TP,
            116 => ProtocolTypes::DDX,
            117 => ProtocolTypes::IATP,
            118 => ProtocolTypes::STP,
            119 => ProtocolTypes::SRP,
            120 => ProtocolTypes::UTI,
            121 => ProtocolTypes::SMP,
            122 => ProtocolTypes::SM,
            123 => ProtocolTypes::PTP,
            124 => ProtocolTypes::ISISoverIPv4,
            125 => ProtocolTypes::FIRE,
            126 => ProtocolTypes::CRTP,
            127 => ProtocolTypes::CRUDP,
            128 => ProtocolTypes::SSCOPMCE,
            129 => ProtocolTypes::IPLT,
            130 => ProtocolTypes::SPS,
            131 => ProtocolTypes::PIPE,
            132 => ProtocolTypes::SCTP,
            133 => ProtocolTypes::FC,
            134 => ProtocolTypes::RsvpE2EIGNORE,
            135 => ProtocolTypes::MobilityHeader,
            136 => ProtocolTypes::UDPLite,
            137 => ProtocolTypes::MPLSinIP,
            138 => ProtocolTypes::Manet,
            139 => ProtocolTypes::HIP,
            140 => ProtocolTypes::Shim6,
            141 => ProtocolTypes::WESP,
            142 => ProtocolTypes::ROHC,
            143 => ProtocolTypes::Ethernet,
            144 => ProtocolTypes::AGGFRAG,
            255 => ProtocolTypes::Reserved,
            _ => ProtocolTypes::Unknown,
        }
    }
}