use options::{DhcpOption};
use options::DhcpOption::*;
use {Result, Error};
use nom::{be_u8};

use num::FromPrimitive;

pub fn parse(bytes: &[u8]) -> Result<Vec<DhcpOption>> {
    Ok(vec![])
}

named!(dhcp_option(&'a [u8]) -> (DhcpOption, Vec<u8>), alt!(
        chain!(
            tag!([0u8]),
            || { (Pad, vec![]) }
        ) |
        chain!(
            tag!([255u8]),
            || { (End, vec![]) }
        ) |
        chain!(
            op: be_u8 ~
            data: length_value!(be_u8, be_u8),
            || { (FromPrimitive::from_u8(op).unwrap(), data) }
        )
    )
);
