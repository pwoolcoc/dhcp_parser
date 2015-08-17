use options::{DhcpOption};
use options::DhcpOption::*;
use {Result, Error};
use nom::{be_u8, be_u32, be_i32, length_value, IResult};
use std::convert::{From};
use std::net::{IpAddr, Ipv4Addr};

pub fn parse(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    Ok(vec![])
}

named!(dhcp_option(&'a [u8]) -> DhcpOption, alt!(
        chain!(
            tag!([0u8]),
            || { Pad }
        ) |
        // SubnetMask
        chain!(
            tag!([1u8]) ~
            // length field, always 4
            be_u8 ~
            addr: be_u32,
            || { SubnetMask(IpAddr::V4(Ipv4Addr::from(addr))) }
        ) |
        // TimeOffset
        chain!(
            tag!([2u8]) ~
            // length field, always 4
            be_u8 ~
            time: be_i32,
            || { TimeOffset(time) }
        ) |
        // Router
        chain!(
            tag!([3u8]) ~
            addrs: length_value!(be_u8, be_u32),
            || { Router(addrs.into_iter().map(|a| IpAddr::V4(Ipv4Addr::from(a))).collect()) }
        ) |
        chain!(
            tag!([255u8]),
            || { End }
        ) 
    )
);
