use anyhow::{anyhow, Result};
use binrw::{binread, binrw, binwrite, BinRead, BinResult, BinWrite, ReadOptions, WriteOptions};
use rhexdump::hexdump;

use crate::opc_values::EncodeOpcValue;
use crate::Parameter;

use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

#[binrw]
#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32, import (payload_len_wr: u16))]
pub struct PacketCCHeader {
    pub u16_zero: u16,
    #[bw(map =|_| payload_len_wr)]
    /// Transmission length minus header
    pub payload_len: u16,
    pub u64_8_f: u64,                // 0?
    pub one_if_data_poll_maybe: u32, // 0 or 1
    pub u8_14: u8,                   // 0
    #[bw(map =|_| payload_len_wr)]
    /// received len in response, payload_len in command
    pub len2: u16,
    /// 0x23 in command, 0x27 in response
    pub b17: u8,
}

impl PacketCCHeader {
    pub fn new_cmd() -> Self {
        Self {
            b17: 0x23,
            ..Self::default()
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
    pub tail: Vec<u8>,
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
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;
        Ok(Self { hdr, payload, tail })
    }
}

impl BinRead for PacketCC<PayloadDynResponse> {
    type Args = Vec<usize>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let hdr = PacketCCHeader::read_options(reader, options, ())?;
        let payload = PayloadDynResponse::read_options(reader, options, (args,))?;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;
        Ok(Self { hdr, payload, tail })
    }
}

// BinWrite can't be derived, since not all payloads implement BinWrite.
impl<P: BinWrite<Args = ()>> BinWrite for PacketCC<P> {
    type Args = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        options: &WriteOptions,
        _args: Self::Args,
    ) -> BinResult<()> {
        let hdr_start = writer.stream_position()?;
        self.hdr.write_options(writer, options, (0,))?;
        let payload_start = writer.stream_position()?;
        self.payload.write_options(writer, options, ())?;
        let len: u16 = (writer.stream_position()? - payload_start)
            .try_into()
            .expect("Payload length too big.");
        writer.seek(SeekFrom::Start(hdr_start))?;
        self.hdr.write_options(writer, options, (len,))
    }
}

impl<P: BinWrite> PacketCC<P> {
    pub fn new(payload: P) -> Self {
        Self {
            hdr: PacketCCHeader::new_cmd(),
            payload,
            tail: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, import (hdr: PacketCCHeader))]
pub struct PayloadUnknown {
    #[br(count = hdr.payload_len)]
    pub data: Vec<u8>,
}

impl ResponsePayload for PayloadUnknown {}

impl<T: AsRef<[u8]>> From<T> for PayloadUnknown {
    fn from(d: T) -> Self {
        Self {
            data: d.as_ref().to_vec(),
        }
    }
}

#[binwrite]
#[derive(Clone, Debug)]
#[bw(big, magic = 0x34u8)]
pub struct PayloadSdbVersionQuery {
    x: &'static [u8],
}

impl PayloadSdbVersionQuery {
    pub fn new() -> Self {
        Self {
            x: b"\0\0\x0eDOWNLOAD.SDB\0\0",
        }
    }
}

#[binread]
#[derive(Clone, Debug)]
#[br(big, import(_hdr:PacketCCHeader))]
pub struct PayloadSdbVersionResponse {
    error_code: u16,
    sbd_size: u32,
    // The remaining bytes are unknown
}

impl ResponsePayload for PayloadSdbVersionResponse {}

#[binread]
#[derive(Clone)]
#[br(big, import(_hdr: PacketCCHeader))]
pub struct PayloadSdbDownload {
    #[br(try_map(|x:u32|match x {0 => Ok(false), 1 => Ok(true), _ => Err(anyhow!("Unexpected in continues field."))}))]
    pub continues: bool, // 0 if this is the last packet, 1 otherwise
    #[br(temp)]
    pub sdb_len: u16,
    #[br(count = sdb_len)]
    pub sdb_part: Vec<u8>,
}

impl ResponsePayload for PayloadSdbDownload {}

impl Debug for PayloadSdbDownload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadSdbDownload {{\n continues: {},\n{}}}",
            self.continues,
            hexdump(&self.sdb_part[0..100]),
        )
    }
}

#[binwrite]
#[derive(Clone, Debug)]
#[br(big, import(_hdr: PacketCCHeader))]
#[bw(big, magic = 0x2e00u16)]
pub struct PayloadParamsRead {
    #[bw(calc = params.len() as u32)]
    #[br(temp)]
    param_count: u32,
    #[br(count = param_count)]
    params: Vec<ParamRead>,
    #[bw(magic = 0x00_02_53_34_u32)]
    end: (),
}

impl PayloadParamsRead {
    pub fn new(params: &[ParamRead]) -> Self {
        let params = params.to_vec();
        Self { params, end: () }
    }
}

/// Instructs the instrument to change the value of the given parameters.
#[binwrite]
#[derive(Clone, Debug)]
#[bw(big, magic = 0x3c00u16)]
pub struct PayloadParamWrite {
    #[bw(calc = params.len() as u32)]
    param_count: u32,
    params: Vec<ParamWrite>,
    #[bw(magic = 0x00_02_53_34_u32)]
    end: (),
}

impl PayloadParamWrite {
    pub fn new(params: &[ParamWrite]) -> Self {
        Self {
            params: params.to_vec(),
            end: (),
        }
    }
}

#[binwrite]
#[derive(Clone, Debug)]
#[bw(big, magic = 3u16)]
pub struct ParamWrite {
    param_id: u32,
    #[bw(calc = data.len() as u32)]
    data_len: u32,
    data: Vec<u8>,
}

impl ParamWrite {
    pub fn new<T: EncodeOpcValue>(param: Parameter, data: T) -> Result<Self> {
        Ok(Self {
            param_id: param.id(),
            data: data.opc_encode(&param.type_info())?,
        })
    }
}

#[binrw]
#[derive(Copy, Clone, Debug)]
#[bw(big, magic = 0x03u16)]
pub struct ParamRead {
    param_id: u32,
    response_len: u32,
}

impl ParamRead {
    pub fn new(param_id: u32, response_len: u32) -> Self {
        Self {
            param_id,
            response_len,
        }
    }
}

#[binread]
#[derive(Clone, Debug)]
#[br(big, import(payload_lengths: Vec<usize>))]
pub struct PayloadDynResponse {
    pub error_code: u16,
    #[br(map(|d:u32| Duration::from_millis(d as u64)))]
    pub timestamp: Duration,
    #[br(parse_with = |reader,_,()| parse_dyn_payload(reader, &payload_lengths))]
    pub data: Vec<Vec<u8>>,
}
fn parse_dyn_payload<R: Read + Seek>(reader: &mut R, lengths: &[usize]) -> BinResult<Vec<Vec<u8>>> {
    lengths
        .iter()
        .map(|len| DynParam::read_args(reader, (*len,)).map(|p| p.0))
        .collect()
}

#[derive(BinRead, Clone, Debug)]
#[br(big, import(len: usize), magic = 1u8)]
struct DynParam(#[br(count = len)] Vec<u8>);
