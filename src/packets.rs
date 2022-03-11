use crate::binrw;
use binrw::{BinRead, BinWrite};
use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[binrw]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32)]
pub struct PacketCCHeader {
    pub u16_zero: u16,
    pub payload_len: u16, // total packet len - 24
    pub u64_8_f: u64,     // 0?
    pub u32_10_13: u32,   // 0 or 1
    pub u8_14: u8,        // 0
    pub len2: u16,        // received len in response, payload_len in command
    pub b17: u8,          // 0x23 in command, 0x27 in response
}

impl PacketCCHeader {
    pub fn new_cmd(len: u16) -> Self {
        Self {
            u16_zero: 0,
            payload_len: len,
            u64_8_f: 0,
            u32_10_13: 0,
            u8_14: 0,
            len2: len,
            b17: 0x23,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big)]
pub struct PacketCC<Payload = PayloadUnknown>
where
    Payload: 'static + BinRead<Args = (PacketCCHeader,)> + BinWrite<Args = ()>,
{
    pub hdr: PacketCCHeader,
    #[br(args(hdr))]
    pub payload: Payload,
}

impl<P: Payload> PacketCC<P> {
    pub fn new(payload: P) -> Self {
        let len = payload.len() as u16;
        Self {
            hdr: PacketCCHeader::new_cmd(len),
            payload,
        }
    }
}

pub trait Payload: BinRead<Args = (PacketCCHeader,)> + BinWrite<Args = ()> {
    fn len(&self) -> u16;
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, import (hdr: PacketCCHeader))]
pub struct PayloadUnknown {
    #[br(count = hdr.payload_len)]
    pub data: Vec<u8>,
}

impl Payload for PayloadUnknown {
    fn len(&self) -> u16 {
        self.data.len() as u16
    }
}

impl<T: AsRef<[u8]>> From<T> for PayloadUnknown {
    fn from(d: T) -> Self {
        Self {
            data: d.as_ref().to_vec(),
        }
    }
}

#[derive(Clone, PartialEq)]
#[binrw]
#[br(big, import(hdr: PacketCCHeader))]
pub struct PayloadSdbDownload {
    pub continues: u32, // 0 if this is the last packet, 1 otherwise
    pub sdb_len: u16,
    #[br(count = sdb_len)]
    pub sdb_part: Vec<u8>,
    #[br(count = (hdr.payload_len - 4 - 2 - sdb_len) as usize)]
    pub tail: Vec<u8>,
}

impl Payload for PayloadSdbDownload {
    fn len(&self) -> u16 {
        4 + self.tail.len() as u16
    }
}

impl Debug for PayloadSdbDownload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadSdbDownload {{\n continues: {},\n{}\ntail: {:x?}}}",
            self.continues,
            hexdump(&self.sdb_part[0..100]),
            &self.tail,
        )
    }
}
