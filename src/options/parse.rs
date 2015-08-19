use options::{DhcpOption};
use options::DhcpOption::*;
use {Result, Error};
use nom::{be_u8, be_u16, be_u32, be_i32, length_value, IResult};
use std::borrow::{ToOwned};
use std::str;
use std::convert::{From};
use std::net::{IpAddr, Ipv4Addr};

pub fn parse(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    Ok(vec![])
}

fn many_ip_addrs(addrs: Vec<u32>) -> Vec<IpAddr> {
    addrs.into_iter().map(|a| IpAddr::V4(Ipv4Addr::from(a))).collect()
}

/// A macro for the options that take the form
///
///     [tag, length, ip_addr...]
///
/// Since the only thing that really differs, is
/// the tag and the Enum variant that is returned
macro_rules! many_ips(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                addrs: length_value!(be_u8, be_u32),
                || { $variant(many_ip_addrs(addrs)) }
            )
        );
    )
);

/// A macro for options that are of the form:
///
///     [tag, length, somestring]
///
/// , since I haven't figured out a way to
/// easily construct a parser to take the length
/// out of a byte of the input, and parse that
/// many bytes into a string
macro_rules! length_specific_string(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                s: length_value!(be_u8, be_u8),
                || { $variant(str::from_utf8(&s).unwrap().to_owned()) }
            )
        );
    )
);

macro_rules! single_ip(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                _length: be_u8 ~
                addr: be_u32,
                || { $variant(IpAddr::V4(Ipv4Addr::from(addr))) }
            )
        );
    )
);

macro_rules! bool(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!($name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                _length: be_u8 ~
                val: be_u8,
                || { $variant(val == 1u8) }
            )
        );
    )
);

named!(subnet_mask<&[u8], DhcpOption>,
    chain!(
        tag!([1u8]) ~
        // length field, always 4
        be_u8 ~
        addr: be_u32,
        || { SubnetMask(IpAddr::V4(Ipv4Addr::from(addr))) }
    )
);

named!(time_offset<&[u8], DhcpOption>,
    chain!(
        tag!([2u8]) ~
        // length field, always 4
        be_u8 ~
        time: be_i32,
        || { TimeOffset(time) }
    )
);

many_ips!(router, 3u8, Router);
many_ips!(time_server, 4u8, TimeServer);
many_ips!(name_server, 5u8, NameServer);
many_ips!(domain_name_server, 6u8, DomainNameServer);
many_ips!(log_server, 7u8, LogServer);
many_ips!(cookie_server, 8u8, CookieServer);
many_ips!(lpr_server, 9u8, LPRServer);
many_ips!(impress_server, 10u8, ImpressServer);
many_ips!(resource_loc_server, 11u8, ResourceLocationServer);

length_specific_string!(hostname, 12u8, HostName);

named!(boot_file_size<&[u8], DhcpOption>,
    chain!(
        tag!([13u8]) ~
        _length: be_u8 ~
        s: be_u16,
        || { BootFileSize(s) }
    )
);

length_specific_string!(merit_dump_file, 14u8, MeritDumpFile);
length_specific_string!(domain_name, 15u8, DomainName);
single_ip!(swap_server, 16u8, SwapServer);
length_specific_string!(root_path, 17u8, RootPath);
length_specific_string!(extensions_path, 18u8, ExtensionsPath);
bool!(ip_forwarding, 19u8, IPForwarding);
bool!(non_source_local_routing, 20u8, NonSourceLocalRouting);

//named!(policy_filter<&[u8], DhcpOption>,
//    chain!(
//        tag!([21u8]) ~

named!(dhcp_option(&'a [u8]) -> DhcpOption, alt!(
        chain!(tag!([0u8]),
            || { Pad }
        )                           |
        subnet_mask                 |
        time_offset                 |
        router                      |
        time_server                 |
        name_server                 | // 5
        domain_name_server          |
        log_server                  |
        cookie_server               |
        lpr_server                  |
        impress_server              | // 10
        resource_loc_server         |
        hostname                    |
        boot_file_size              |
        merit_dump_file             |
        domain_name                 | // 15
        swap_server                 |
        root_path                   |
        extensions_path             |
        ip_forwarding               |
        non_source_local_routing    | // 20
        chain!(
            tag!([255u8]),
            || { End }
        ) 
    )
);
