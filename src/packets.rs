#![allow(dead_code)]

use anyhow::{anyhow, Result};
use binrw::{binread, binrw, binwrite, BinRead, BinResult, BinWrite, ReadOptions, WriteOptions};
use rhexdump::hexdump;

use crate::opc_values::{EncodeOpcValue, Value};
use crate::sdb;

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::rc::Rc;
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

pub trait QueryPacket: BinWrite<Args = ()> {
    type Response: BinRead;
}

#[derive(Clone)]
pub struct ReadArgs<T: Clone> {
    hdr: PacketCCHeader,
    args: T,
}

impl<P: BinRead<Args = ReadArgs<Args>>, Args: Clone> BinRead for PacketCC<P> {
    type Args = Args;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let hdr = PacketCCHeader::read_options(reader, options, ())?;
        let payload = P::read_options(reader, options, ReadArgs { hdr, args })?;
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
#[br(big, import_raw(arg: ReadArgs<()>))]
pub struct PayloadUnknown {
    #[br(count = arg.hdr.payload_len)]
    pub data: Vec<u8>,
}

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
#[br(big, import_raw(_hdr:ReadArgs<()>))]
pub struct PayloadSdbVersionResponse {
    error_code: u16,
    sbd_size: u32,
    // The remaining bytes are unknown
}

#[binread]
#[derive(Clone)]
#[br(big, import_raw(_hdr: ReadArgs<()>))]
pub struct PayloadSdbDownload {
    #[br(try_map(|x:u32|match x {0 => Ok(false), 1 => Ok(true), _ => Err(anyhow!("Unexpected in continues field."))}))]
    pub continues: bool, // 0 if this is the last packet, 1 otherwise
    #[br(temp)]
    pub sdb_len: u16,
    #[br(count = sdb_len)]
    pub sdb_part: Vec<u8>,
}

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

/// Encodes a parameter read command.
#[binwrite]
#[derive(Clone, Debug)]
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

impl QueryPacket for PayloadParamsRead {
    type Response = PayloadDynResponse;
}

impl PayloadParamsRead {
    pub fn new(params: &[sdb::Parameter]) -> Self {
        let params = params
            .iter()
            .map(|param| ParamRead::new(param.id(), param.type_info().response_len() as u32))
            .collect();
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

impl QueryPacket for PayloadParamWrite {
    type Response = PayloadUnknown;
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
    pub fn new<T: EncodeOpcValue>(param: &sdb::Parameter, data: T) -> Result<Self> {
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
#[br(big, import_raw(read_args: ReadArgs<ParamQuerySet>))]
pub struct PayloadDynResponse {
    pub error_code: u16,
    #[br(map(|d:u32| Duration::from_millis(d as u64)))]
    pub timestamp: Duration,
    #[br(parse_with = |reader,_,()| parse_dyn_payload(reader, &read_args.args.0))]
    pub data: Vec<Value>,
    #[br(calc = read_args.args)]
    pub query_set: ParamQuerySet,
}
fn parse_dyn_payload<R: Read + Seek>(
    reader: &mut R,
    params: &[sdb::Parameter],
) -> BinResult<Vec<Value>> {
    params
        .iter()
        .map(|param| {
            let one = u8::read(reader)?;
            assert_eq!(one, 1, "Bad magic at start of parameter response payload.");
            Value::read_args(reader, param.type_info())
        })
        .collect()
}

impl PayloadDynResponse {
    pub fn into_hashmap(self) -> HashMap<sdb::Parameter, Value> {
        self.query_set
            .0
            .iter()
            .cloned()
            .zip(self.data.into_iter())
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&sdb::Parameter, &Value)> {
        self.query_set.0.iter().zip(self.data.iter())
    }
}

#[derive(Debug, Clone)]
pub struct ParamQuerySetBuilder(Vec<sdb::Parameter>, sdb::SdbRef);

#[derive(Debug, Clone)]
pub struct ParamQuerySet(pub Rc<[sdb::Parameter]>);

impl ParamQuerySetBuilder {
    pub fn new(sdb: &sdb::Sdb) -> Self {
        Self(vec![], sdb.get_ref())
    }
    pub fn add(&mut self, name: &str) -> Result<()> {
        self.0.push(self.1.param_by_name(name)?);
        Ok(())
    }
    pub fn add_param(&mut self, param: sdb::Parameter) {
        self.0.push(param);
    }
    pub fn complete(self) -> ParamQuerySet {
        ParamQuerySet(self.0.into())
    }
}

impl ParamQuerySet {
    pub fn create_query_packet(&self) -> PacketCC<PayloadParamsRead> {
        let mut p = PacketCC::new(PayloadParamsRead::new(&self.0));
        p.hdr.one_if_data_poll_maybe = 1;
        p
    }
}
