use options::{DhcpOption};
use options::DhcpOption::*;
use {Result, Error};
use nom::{be_u8, be_u16, be_u32, be_i32, length_value, IResult, sized_buffer};
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

fn ip_addr_mask_pairs(bytes: &[u8]) -> Vec<(IpAddr, IpAddr)> {
    vec![]
    /* let it = bytes.iter(); */
    /* let mut pairs: Vec<(u32, u32)> = vec![]; */
    /* loop { */
    /*     let next_4 = it.take(4).collect::<Vec<_>>(); */

    /* } */
    /* pairs.into_iter().map(|pair| { */
    /* }) */
}

fn num_u16s(bytes: &[u8]) -> IResult<&[u8], u8> {
    match be_u8(bytes) {
        IResult::Done(i, o) => IResult::Done(i, o / 2),
        a => a,
    }
}

fn num_u32s(bytes: &[u8]) -> IResult<&[u8], u8> {
    match be_u8(bytes) {
        IResult::Done(i, o) => IResult::Done(i, o / 4),
        a => a,
    }
}

/// A macro for the options that take the form
///
///     [tag, length, ip_addr...]
///
/// Since the only thing that really differs, is
/// the tag and the Enum variant that is returned
macro_rules! many_ips(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!(pub $name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                addrs: length_value!(num_u32s, be_u32),
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
        named!(pub $name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                s: map_res!(sized_buffer, str::from_utf8),
                || { $variant(s.to_owned()) }
            )
        );
    )
);

macro_rules! single_ip(
    ($name:ident, $tag:expr, $variant:expr) => (
        named!(pub $name<&[u8], DhcpOption>,
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
        named!(pub $name<&[u8], DhcpOption>,
            chain!(
                tag!([$tag]) ~
                _length: be_u8 ~
                val: be_u8,
                || { $variant(val == 1u8) }
            )
        );
    )
);

single_ip!(subnet_mask, 1u8, SubnetMask);

named!(pub time_offset<&[u8], DhcpOption>,
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

named!(pub boot_file_size<&[u8], DhcpOption>,
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
bool!(non_source_local_routing, 20u8, NonLocalSourceRouting);

// TODO
named!(pub policy_filter<&[u8], DhcpOption>,
    chain!(
        tag!([21u8]) ~
        s: map!(sized_buffer, ip_addr_mask_pairs),
        || { PolicyFilter(s) }
    )
);

named!(pub max_datagram_reassembly_size<&[u8], DhcpOption>,
    chain!(
        tag!([22u8]) ~
        _len: be_u8 ~
        aa: be_u16,
        || { MaxDatagramReassemblySize(aa) }
    )
);

named!(default_ip_ttl<&[u8], DhcpOption>,
    chain!(
        tag!([23u8]) ~
        _length: be_u8 ~
        ttl: be_u8,
        || { DefaultIPTTL(ttl) }
    )
);

named!(path_mtu_aging_timeout<&[u8], DhcpOption>,
    chain!(
        tag!([24u8]) ~
        _length: be_u8 ~
        timeout: be_u32,
        || { PathMTUAgingTimeout(timeout) }
    )
);

named!(path_mtu_plateau_table<&[u8], DhcpOption>,
    chain!(
        tag!([25u8]) ~
        sizes: length_value!(num_u16s, be_u16),
        || { PathMTUPlateauTable(sizes) }
    )
);

// Start collections of parsers, to get around the fact that alt! exceeds the
// recursion once you get to ~21 parsers

named!(vendor_extensions_1497<&[u8], DhcpOption>, alt!(
          chain!(tag!([0u8]),
              || { Pad }
          )
        | chain!(
                tag!([255u8]),
                || { End }
            )
        | subnet_mask
        | time_offset
        | router
        | time_server
        | name_server         // 5
        | domain_name_server
        | log_server
        | cookie_server
        | lpr_server
        | impress_server      // 10
        | resource_loc_server
        | hostname
        | boot_file_size
        | merit_dump_file
        | domain_name         // 15
        | swap_server
        | root_path
        | extensions_path
    )
);

named!(ip_layer_parameters_per_host<&[u8], DhcpOption>, alt!(
          ip_forwarding
        | non_source_local_routing      // 20
        | policy_filter //TODO
        | max_datagram_reassembly_size
        | default_ip_ttl
        | path_mtu_aging_timeout
        | path_mtu_plateau_table        // 25
    )
);

/* named!(ip_layer_parameters_per_interface<&[u8], DhcpOption>, alt!( */
/*           interface_mtu */
/*         | all_subnets_are_local */
/*         | broadcast_address */
/*         | perform_mask_discovery */
/*         | mask_supplier                 // 30 */
/*         | perform_router_discovery */
/*         | router_solicitation_address */
/*         | static_route */
/*     ) */
/* ); */

/* named!(link_layer_parameters_per_interface<&[u8], DhcpOption>, alt!( */
/*           trailer_encapsulation */
/*         | arp_cache_timeout         // 35 */
/*         | ethernet_encapsulation */
/*     ) */
/* ); */

/* named!(tcp_parameters<&[u8], DhcpOption>, alt!( */
/*           tcp_default_ttl */
/*         | tcp_keepalive_interval */
/*         | tcp_keepalive_garbage */
/*     ) */
/* ); */
/* named!(application_and_service_parameters<&[u8], DhcpOption>, alt!( */
/*           nis_domain                            // 40 */
/*         | network_information_servers */
/*         | ntp_servers */
/*         | vendor_extensions */
/*         | net_bios_name_servers */
/*         | net_bios_datagram_distribution_server // 45 */
/*         | net_bios_node_type */
/*         | net_bios_scope */
/*         | xfont_server */
/*         | xdisplay_manager */
/*     ) */
/* ); */
/* named!(dhcp_extensions<&[u8], DhcpOption>, alt!( */
/*           requested_ip_address  // 50 */
/*         | ip_address_lease_time */
/*         | option_overload */
/*         | message_type */
/*         | server_identifier */
/*         | param_request_list    // 55 */
/*         | message */
/*         | max_message_size */
/*         | renewal_time_value */
/*         | rebinding_time_value */
/*         | class_identifier      // 60 */
/*         | client_identifier */
/*     ) */
/* ); */

// Main parser
named!(dhcp_option(&'a [u8]) -> DhcpOption, alt!(
          vendor_extensions_1497
        | ip_layer_parameters_per_host
//      | ip_layer_parameters_per_interface
//      | link_layer_parameters_per_interface
//      | tcp_parameters
//      | application_and_service_parameters
//      | dhcp_extensions
    )
);

#[cfg(test)] mod tests {
    use options::DhcpOption::{Router};
    use super::{router};
    use nom::{IResult};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_many_ip_addresses() {
        let ips = vec![3u8,
                       8,
                       127, 0, 0, 1,
                       192, 168, 1, 1,
        ];

        match router(&ips) {
            IResult::Done(i, o) => {
                if i.len() > 0 {
                    panic!("Remaining input was {:?}", i);
                }
                assert_eq!(o, Router(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                          IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]));
            },
            e => panic!("Result was {:?}", e),
        }
    }
}
