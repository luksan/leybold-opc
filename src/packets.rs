use crate::binrw;
use binrw::{BinRead, BinWrite};
use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[binrw]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32)]
pub struct PacketCCHeader {
    pub payload_len: u32, // total packet len - 24
    pub u64_8_f: u64,     // 0?
    pub u32_10_13: u32,   // 0 or 1
    pub u16_14_15: u16,   // 0
    pub b16: u8,          // 23 or 27
    pub b17: u8,          //
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

pub trait Payload: BinRead<Args = (PacketCCHeader,)> + BinWrite<Args = ()> {
    fn len(&self) -> u32;
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, import (hdr: PacketCCHeader))]
pub struct PayloadUnknown {
    #[br(count = hdr.payload_len)]
    pub data: Vec<u8>,
}

impl Payload for PayloadUnknown {
    fn len(&self) -> u32 {
        self.data.len() as u32
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
    #[br(count = (hdr.payload_len - 4) as usize)]
    pub tail: Vec<u8>,
}

impl Payload for PayloadSdbDownload {
    fn len(&self) -> u32 {
        4 + self.tail.len() as u32
    }
}

impl Debug for PayloadSdbDownload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadSdbDownload {{\n continues: {},\n{}\n}}",
            self.continues,
            hexdump(&self.tail[0..100])
        )
    }
}
