use super::{Error, Result};

#[derive(Debug, PartialEq)]
pub enum Op {
    BootRequest = 1,
    BootReply,
}

impl Op {
    pub fn from_byte(byte: u8) -> Result<Op> {
        match byte {
            1u8 => { Ok(Op::BootRequest) },
            2u8 => { Ok(Op::BootReply) },
            _ => { Err(Error::ParseError("Got bad value for `op`".into())) }
        }
    }
}

