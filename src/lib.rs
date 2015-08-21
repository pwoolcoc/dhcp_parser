#![feature(trace_macros)]
#![feature(ip_addr)]
#![feature(plugin)]

#[plugin] #[no_link] extern crate rest_easy;

/// DHCP Parsing
///
/// Takes bytes and turns them into Rust datatypes

#[macro_use] extern crate nom;
#[macro_use] extern crate enum_primitive;
extern crate num;

mod htype;
mod op;
mod options;
mod util;

use std::fmt;
use std::error;
use std::convert::{From};
use std::net::{IpAddr, Ipv4Addr};
use nom::{IResult, be_u8, be_u16, be_u32};

use self::op::Op;
use self::htype::Htype;
use self::util::{take_rest};
use self::options::{DhcpOption};

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone)]
pub enum Error {
    ParseError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::ParseError(ref s) => {
                write!(f, "{:?}", s)
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::ParseError(ref s) => {
                s
            }
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
/// Data type that the bytes get translated into.
///
/// In some cases I translated them into more specific data types
/// where possible. I would like to make `sname` and `file` into
/// `&'a str`, but it is possible that they will hold more `options`
/// instead of actually being strings, so I have to keep them as
/// bytes in RawMessage. Something using this should probably change
/// them to `Option<String>`s in a higher-level datatype.
pub struct RawMessage<'a> {
    op: Op,
    htype: Htype,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: IpAddr,
    yiaddr: IpAddr,
    siaddr: IpAddr,
    giaddr: IpAddr,
    chaddr: &'a [u8],  // 16 bytes
    sname: &'a [u8],  // 64 bytes
    file: &'a [u8],  // 128 bytes
    options: Vec<DhcpOption>,
}

#[allow(dead_code)]
fn parse_message<'a>(bytes: &'a [u8]) -> Result<RawMessage<'a>> {
    match _parse_message(bytes) {
        IResult::Done(inp, msg) => {
            if inp.len() > 0 {
                return Err(Error::ParseError("LEFTOVER INPUT".into()));
            }
            Ok(msg)
        },
        IResult::Error(err) => {
            Err(Error::ParseError(format!("SOME OTHER ERROR: {:?}", err)))
        },
        IResult::Incomplete(_) => {
            Err(Error::ParseError("INCOMPLETE".into()))
        }
    }
}

named!(_parse_message(&'a [u8]) -> RawMessage<'a>,
    chain!(
        pop: map_res!(be_u8, Op::from_byte) ~
        phtype: map_res!(be_u8, Htype::from_byte) ~
        phlen: be_u8 ~
        phops: be_u8 ~
        pxid: be_u32 ~
        psecs: be_u16 ~
        pflags: be_u16 ~
        pciaddr: map!(be_u32, |a| IpAddr::V4(Ipv4Addr::from(a))) ~
        pyiaddr: map!(be_u32, |a| IpAddr::V4(Ipv4Addr::from(a))) ~
        psiaddr: map!(be_u32, |a| IpAddr::V4(Ipv4Addr::from(a))) ~
        pgiaddr: map!(be_u32, |a| IpAddr::V4(Ipv4Addr::from(a))) ~
        pchaddr: take!(16) ~
        psname: take!(64) ~
        pfile: take!(128) ~
        _cookie: tag!(&MAGIC_COOKIE) ~
        poptions: map_res!(take_rest, options::parse),
    ||{
        RawMessage {
            op: pop,
            htype: phtype,
            hlen: phlen,
            hops: phops,
            xid: pxid,
            secs: psecs,
            flags: pflags,
            ciaddr: pciaddr,
            yiaddr: pyiaddr,
            siaddr: psiaddr,
            giaddr: pgiaddr,
            chaddr: pchaddr,
            sname: psname,
            file: pfile,
            options: poptions,
        }
    }
    )
);

#[cfg(test)]
mod tests {

    use std::str;
    use super::{parse_message, RawMessage};
    use super::op::{Op};
    use super::htype::{Htype};

#[test]
fn test_parse_message() {
    let test_message: Vec<u8> = vec![
        1u8,                                    // op
        2,                                      // htype
        3,                                      // hlen
        4,                                      // ops
        5, 6, 7, 8,                             // xid
        9, 10,                                  // secs
        11, 12,                                 // flags
        13, 14, 15, 16,                         // ciaddr
        17, 18, 19, 20,                         // yiaddr
        21, 22, 23, 24,                         // siaddr
        25, 26, 27, 28,                         // giaddr
        29, 30, 31, 32,
        33, 34, 35, 36,
        37, 38, 39, 40,
        41, 42, 43, 44,                         // chaddr
        45, 46, 47, 48, 49, 50, 51, 52,
        53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68,
        69, 70, 71, 72, 73, 74, 75, 76,

        77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 91, 92,
        93, 94, 95, 96, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 0,   // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",

        109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124,
        125, 109, 110, 111, 112, 113, 114, 115,
        116, 117, 118, 119, 120, 121, 122, 123,

        124, 125, 109, 110, 111, 112, 113, 114,
        115, 116, 117, 118, 119, 120, 121, 122,
        123, 124, 125, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 120, 121,

        122, 123, 124, 125, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 123, 124, 125, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119,

        120, 121, 122, 123, 124, 125, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118,
        119, 120, 121, 122, 123, 124, 125, 109,
        0, 0, 0, 0, 0, 0, 0, 0,                 // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",

        99, 130, 83, 99,                        // magic cookie
    ];
    assert_eq!(parse_message(&test_message).unwrap(), RawMessage {
        op: Op::BootRequest,
        htype: Htype::Experimental_Ethernet_3mb,
        hlen: 3,
        hops: 4,
        xid: 84281096,
        secs: 2314,
        flags: 2828,
        ciaddr: str::FromStr::from_str("13.14.15.16").unwrap(),
        yiaddr: str::FromStr::from_str("17.18.19.20").unwrap(),
        siaddr: str::FromStr::from_str("21.22.23.24").unwrap(),
        giaddr: str::FromStr::from_str("25.26.27.28").unwrap(),
        chaddr: &vec![29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44][..],
        sname: &vec![
            45, 46, 47, 48, 49, 50, 51, 52,
            53, 54, 55, 56, 57, 58, 59, 60,
            61, 62, 63, 64, 65, 66, 67, 68,
            69, 70, 71, 72, 73, 74, 75, 76,

            77, 78, 79, 80, 81, 82, 83, 84,
            85, 86, 87, 88, 89, 90, 91, 92,
            93, 94, 95, 96, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 0,
        ][..],
        file: &vec![
            109, 110, 111, 112, 113, 114, 115, 116,
            117, 118, 119, 120, 121, 122, 123, 124,
            125, 109, 110, 111, 112, 113, 114, 115,
            116, 117, 118, 119, 120, 121, 122, 123,

            124, 125, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 120, 121, 122,
            123, 124, 125, 109, 110, 111, 112, 113,
            114, 115, 116, 117, 118, 119, 120, 121,

            122, 123, 124, 125, 109, 110, 111, 112,
            113, 114, 115, 116, 117, 118, 119, 120,
            121, 122, 123, 124, 125, 109, 110, 111,
            112, 113, 114, 115, 116, 117, 118, 119,

            120, 121, 122, 123, 124, 125, 109, 110,
            111, 112, 113, 114, 115, 116, 117, 118,
            119, 120, 121, 122, 123, 124, 125, 109,
            0, 0, 0, 0, 0, 0, 0, 0,
        ][..],
        options: vec![],
    });

}

}
