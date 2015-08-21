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
    LPRServer(Vec<IpAddr>),
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
    PolicyFilter(Vec<(IpAddr, u32)>),
    MaxDatagramReassemblySize(u16),
    DefaultIPTTL(u8),
    PathMTUAgingTimeout(u32),
    PathMTUPlateauTable,

    InterfaceMTU,
    AllSubnetsAreLocal,
    BroadcastAddress,
    PerformMaskDiscovery,
    MaskSupplier,
    PerformRouterDiscovery,
    RouterSolicitationAddress,
    StaticRoute,

    TrailerEncapsulation,
    ARPCacheTimeout,
    EthernetEncapsulation,

    TCPDefaultTTL,
    TCPKeepaliveInterval,
    TCPKeepaliveGarbage,

    NISDomain,
    NetworkInformationServers,
    NTPServers,
    VendorExtensions,
    NetBIOSNameServers,
    NetBIOSDatagramDistributionServer,
    NetBIOSNodeType,
    NetBIOSScope,
    XFontServer,
    XDisplayManager,

    // DHCP-specific options
    RequestedIPAddress,
    IPAddressLeaseTime,
    OptionOverload,
    MessageType,
    ServerIdentifier,
    ParamRequestList,
    Message,
    MaxMessageSize,
    RenewalTimeValue,
    RebindingTimeValue,
    ClassIdentifier,
    ClientIdentifier,
}

//impl DhcpOption {
//    pub fn from_bytes<T: AsRef<[u8]>>(&self, bytes: T) -> {
//    }
//}
