use super::{Result, Error};

#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Htype {
    Ethernet_10mb = 1,
    Experimental_Ethernet_3mb,
    Amateur_Radio_AX_25,
    Proteon_ProNET_Token_Ring,
    Chaos,
    IEEE_802_Networks,
    Arcnet,
    Hyperchannel,
    Lanstar,
    Autonet_Short_Address,
    LocalTalk,
    LocalNet,
    Ultra_link,
    SMDS,
    Frame_Relay,
    Asynchronous_Transmission_Mode,
}

impl Htype {
    pub fn from_byte(byte: u8) -> Result<Htype> {
        match byte {
            1u8 => Ok(Htype::Ethernet_10mb),
            2u8 => Ok(Htype::Experimental_Ethernet_3mb),
            3u8 => Ok(Htype::Amateur_Radio_AX_25),
            4u8 => Ok(Htype::Proteon_ProNET_Token_Ring),
            5u8 => Ok(Htype::Chaos),
            6u8 => Ok(Htype::IEEE_802_Networks),
            7u8 => Ok(Htype::Arcnet),
            8u8 => Ok(Htype::Hyperchannel),
            9u8 => Ok(Htype::Lanstar),
            10u8 => Ok(Htype::Autonet_Short_Address),
            11u8 => Ok(Htype::LocalTalk),
            12u8 => Ok(Htype::LocalNet),
            13u8 => Ok(Htype::Ultra_link),
            14u8 => Ok(Htype::SMDS),
            15u8 => Ok(Htype::Frame_Relay),
            16u8 => Ok(Htype::Asynchronous_Transmission_Mode),
            _ => Err(Error::ParseError(format!("Unknown Htype {:?}", byte)))
        }
    }
}


