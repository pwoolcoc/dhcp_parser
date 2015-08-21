mod parse;

use std::net::{IpAddr};
pub use self::parse::parse;

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum DhcpOption {
    Pad,
    End,
    SubnetMask(IpAddr),
    TimeOffset(i32),
    Router(Vec<IpAddr>),
    TimeServer(Vec<IpAddr>),
    NameServer(Vec<IpAddr>),
    DomainNameServer(Vec<IpAddr>),
    LogServer(Vec<IpAddr>),
    CookieServer(Vec<IpAddr>),
    LprServer(Vec<IpAddr>),
    ImpressServer(Vec<IpAddr>),
    ResourceLocationServer(Vec<IpAddr>),
    HostName(String),
    BootFileSize(u16),
    MeritDumpFile(String),
    DomainName(String),
    SwapServer(IpAddr),
    RootPath(String),
    ExtensionsPath(String),
    IPForwarding(bool),

    NonLocalSourceRouting(bool),
    PolicyFilter(Vec<(IpAddr, IpAddr)>),
    MaxDatagramReassemblySize(u16),
    DefaultIpTtl(u8),
    PathMtuAgingTimeout(u32),
    PathMtuPlateauTable(Vec<u16>),

    InterfaceMtu(u16),
    AllSubnetsAreLocal(bool),
    BroadcastAddress(IpAddr),
    PerformMaskDiscovery(bool),
    MaskSupplier(bool),
    PerformRouterDiscovery(bool),
    RouterSolicitationAddress(IpAddr),
    StaticRoute(Vec<(IpAddr, IpAddr)>),

    TrailerEncapsulation(bool),
    ArpCacheTimeout(u32),
    EthernetEncapsulation(bool),

    TcpDefaultTtl(u8),
    TcpKeepaliveInterval(u32),
    TcpKeepaliveGarbage(bool),

    NisDomain(String),
    NetworkInformationServers(Vec<IpAddr>),
    NtpServers(Vec<IpAddr>),
    VendorExtensions(Vec<u8>),
    NetBiosNameServers(Vec<IpAddr>),
    NetBiosDatagramDistributionServer(Vec<IpAddr>),
    NetBiosNodeType(NodeType),
    NetBiosScope(String),
    XFontServer(Vec<IpAddr>),
    XDisplayManager(Vec<IpAddr>),

    // DHCP-specific options
    RequestedIpAddress(IpAddr),
    IpAddressLeaseTime(u32),
    OptionOverload(OptionOverloadType),
    MessageType(DhcpMessageTypes),
    ServerIdentifier(IpAddr),
    ParamRequestList(Vec<u8>),
    Message(String),
    MaxMessageSize(u16),
    RenewalTimeValue(u32),
    RebindingTimeValue(u32),
    ClassIdentifier,
    ClientIdentifier,
}

enum_from_primitive! {
#[derive(Debug, PartialEq)]
enum NodeType {
    B = 1,
    P = 2,
    M = 4,
    H = 8,
}
}

enum_from_primitive! {
#[derive(Debug, PartialEq)]
enum OptionOverloadType {
    File = 1,
    Sname = 2,
    FileAndSname = 3,
}
}

enum_from_primitive! {
#[derive(Debug, PartialEq)]
enum DhcpMessageTypes {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
}
}

//impl DhcpOption {
//    pub fn from_bytes<T: AsRef<[u8]>>(&self, bytes: T) -> {
//    }
//}
