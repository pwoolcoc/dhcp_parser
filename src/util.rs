use std::str;
use nom::{IResult};
use super::{Result, Error};

pub fn take_rest(input: &[u8]) -> IResult<&[u8], &[u8]> {
    IResult::Done(b"", input)
}

#[allow(dead_code)]
pub fn null_terminated_slice_to_string(bytes: &[u8]) -> Result<&str> {
    let pos = match bytes.iter().position(|b| *b == 0u8) {
        Some(p) => p,
        None => return Err(Error::ParseError("NO NULL TERMINATION FOUND".into())),
    };
    match str::from_utf8(&bytes[0..pos]) {
        Ok(s) => Ok(s),
        Err(_) => Err(Error::ParseError("Could not get utf8 from bytes".into())),
    }
}


#[cfg(test)] mod tests {

use super::{take_rest};
use nom::{IResult};
use std::str;

#[test]
fn test_take_rest() {
    named!(parts<&[u8],(&str,&str)>,
        chain!(
            key: map_res!(tag!("abcd"), str::from_utf8) ~
            tag!(":") ~
            value: map_res!(take_rest, str::from_utf8),
            || {(key, value)}
        )
    );

    assert_eq!(parts(b"abcd:thisistherestofthestring"), IResult::Done(&b""[..], ("abcd", "thisistherestofthestring")));
}


}
