use anyhow::{Context, Result};
use binrw::{
    binread, binrw, BinRead, BinReaderExt, BinResult, BinWrite, ReadOptions, WriteOptions,
};
use rhexdump::hexdump;

use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek, Write};
use std::time::Duration;

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[binrw]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32)]
pub struct PacketCCHeader {
    pub u16_zero: u16,
    pub payload_len: u16,            // total packet len - 24
    pub u64_8_f: u64,                // 0?
    pub one_if_data_poll_maybe: u32, // 0 or 1
    pub u8_14: u8,                   // 0
    pub len2: u16,                   // received len in response, payload_len in command
    pub b17: u8,                     // 0x23 in command, 0x27 in response
}

impl PacketCCHeader {
    pub fn new_cmd(len: u16) -> Self {
        Self {
            u16_zero: 0,
            payload_len: len,
            u64_8_f: 0,
            one_if_data_poll_maybe: 0,
            u8_14: 0,
            len2: len,
            b17: 0x23,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PacketCC<Payload = PayloadUnknown>
where
    Payload: 'static,
{
    pub hdr: PacketCCHeader,
    pub payload: Payload,
}
pub trait ResponsePayload: BinRead<Args = (PacketCCHeader,)> {}

impl<P: ResponsePayload> BinRead for PacketCC<P> {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        _args: Self::Args,
    ) -> BinResult<Self> {
        let hdr = PacketCCHeader::read_options(reader, options, ())?;
        let payload = P::read_options(reader, options, (hdr,))?;
        Ok(Self { hdr, payload })
    }
}

impl<P: SendPayload> BinWrite for PacketCC<P> {
    type Args = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        options: &WriteOptions,
        _args: Self::Args,
    ) -> BinResult<()> {
        self.hdr.write_options(writer, options, ())?;
        self.payload.write_options(writer, options, ())
    }
}

impl<P: SendPayload> PacketCC<P> {
    pub fn new(payload: P) -> Self {
        let len = payload.len() as u16;
        Self {
            hdr: PacketCCHeader::new_cmd(len),
            payload,
        }
    }
}

pub trait SendPayload: BinWrite<Args = ()> {
    fn len(&self) -> u16;
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, import (hdr: PacketCCHeader))]
pub struct PayloadUnknown {
    #[br(count = hdr.payload_len)]
    pub data: Vec<u8>,
}

impl SendPayload for PayloadUnknown {
    fn len(&self) -> u16 {
        self.data.len() as u16
    }
}

impl ResponsePayload for PayloadUnknown {}

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

impl SendPayload for PayloadSdbDownload {
    fn len(&self) -> u16 {
        4 + self.tail.len() as u16
    }
}
impl ResponsePayload for PayloadSdbDownload {}

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

#[derive(Clone, PartialEq)]
#[binrw]
#[br(big, import(_hdr: PacketCCHeader))]
#[bw(big, magic = 0x2e00u16)]
pub struct PayloadParamsQuery {
    param_count: u32,
    #[br(count = param_count)]
    params: Vec<QueryParam>,
    end: u32,
}

impl SendPayload for PayloadParamsQuery {
    fn len(&self) -> u16 {
        self.params.len() as u16 * (2 + 4 + 4) + 4 + 4
    }
}

#[derive(Clone, PartialEq)]
#[binrw]
#[bw(big)]
pub struct QueryParam {
    i1: u16, // 0x03
    param_id: u32,
    i2: u32,
}

pub trait Param: BinRead<Args = ()> {
    const LEN: usize;
}

impl Param for f32 {
    const LEN: usize = 4;
}

#[derive(Clone)]
#[binread]
pub struct Bstr<const LEN: usize>(#[br(count = LEN)] Vec<u8>);

impl<const LEN: usize> Bstr<LEN> {
    pub fn try_as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.0.as_slice().split(|&c| c == 0).next().unwrap())
            .context("Bstr is not valid utf-8")
    }
}

impl<const LEN: usize> Debug for Bstr<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Ok(s) = self.try_as_str() {
            write!(f, "{}", s)
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}
impl<const N: usize> Param for Bstr<N> {
    const LEN: usize = N;
}

#[derive(Clone, Debug)]
pub struct Params<P>(P);

macro_rules! param_impls {
    ($end:ident) => {};
    ( $head:ident, $( $name:ident ),+ ) => {
        impl<$($name: Param),+> BinRead for Params<($($name,)+)> {
            type Args = ();
            fn read_options<R: Read + Seek>(reader: &mut R, options: &ReadOptions, _args: Self::Args)
              -> BinResult<Self> {
                Ok(Self(($(ParamResponse::<$name>::read_options(reader, options, ())?.0,)+)))
            }
        }
        param_impls!($($name),+);
    };
}

param_impls!(end, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, S, T);

#[derive(Clone, Debug)]
pub struct PayloadParamsResponse<PTuple: BinRead<Args = ()> + 'static> {
    pub x0: [u8; 2], // 0 0
    /// Timestamp, instrument uptime in milliseconds
    pub timestamp: Duration,
    params: Params<PTuple>,
    tail: Vec<u8>,
}

impl<PTuple: BinRead<Args = ()>> BinRead for PayloadParamsResponse<PTuple>
where
    Params<PTuple>: BinRead<Args = ()>,
{
    type Args = (PacketCCHeader,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        _args: Self::Args,
    ) -> BinResult<Self> {
        let x0 = reader.read_type(options.endian())?;
        let timestamp =
            u32::read_options(reader, options, ()).map(|d| Duration::from_millis(d as u64))?;
        let params = reader.read_type(options.endian())?;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;
        Ok(Self {
            x0,
            timestamp,
            params,
            tail,
        })
    }
}

impl<PTuple> ResponsePayload for PayloadParamsResponse<PTuple>
where
    PTuple: BinRead<Args = ()>,
    Params<PTuple>: BinRead<Args = ()>,
{
}

#[derive(Clone, PartialEq)]
#[binread]
#[br(big, magic = 0x01u8)]
struct ParamResponse<T: Param + 'static>(#[br(pad_size_to = T::LEN)] T);
