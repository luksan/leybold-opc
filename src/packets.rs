#![allow(dead_code, clippy::new_without_default)]

use anyhow::{anyhow, Result};
use binrw::{binread, binrw, binwrite, BinRead, BinResult, BinWrite, Endian};
use rhexdump::hexdump;

use crate::opc_values::{EncodeOpcValue, Value};
use crate::sdb;

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

#[binrw]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketCC<'p, Payload: 'p> {
    pub hdr: PacketCCHeader,
    pub payload: Payload,
    pub tail: Vec<u8>,
    lifetime: PhantomData<&'p Payload>,
}

pub trait QueryPacket<'p>
where
    PacketCC<'p, Self::Response<'p>>: BinRead + 'p,
{
    /// The type used for decoding the query response
    type Response<'r>: BinRead;
    fn get_response_read_arg(&self) -> <PacketCC<'p, Self::Response<'p>> as BinRead>::Args<'p>;
}

#[derive(Clone)]
pub struct ReadArgs<T: Clone> {
    hdr: PacketCCHeader,
    args: T,
}

impl<P, Args> BinRead for PacketCC<'_, P>
where
    for<'a> P: BinRead<Args<'a> = ReadArgs<Args>>,
    Args: Clone,
{
    type Args<'a> = Args;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let hdr = PacketCCHeader::read_options(reader, options, ())?;
        let payload = P::read_options(reader, options, ReadArgs { hdr, args })?;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail)?;
        Ok(Self {
            hdr,
            payload,
            tail,
            lifetime: PhantomData,
        })
    }
}

// BinWrite can't be derived, since not all payloads implement BinWrite.
impl<'a, P: BinWrite<Args<'a> = ()>> BinWrite for PacketCC<'_, P> {
    type Args<'b> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        options: Endian,
        _args: Self::Args<'_>,
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

impl<P: BinWrite> PacketCC<'_, P> {
    pub fn new(payload: P) -> Self {
        Self {
            hdr: PacketCCHeader::new_cmd(),
            payload,
            tail: vec![],
            lifetime: PhantomData,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Encodes a parameter read command.
#[binwrite]
#[derive(Clone, Debug)]
#[bw(big, magic = 0x2e00u16)]
pub struct ParamsReadQuery<'sdb> {
    #[bw(ignore)]
    query_set: ParamQuerySet<'sdb>,

    #[bw(calc = params.len() as u32)]
    #[br(temp)]
    param_count: u32,
    #[br(count = param_count)]
    params: Vec<ParamRead>,
    sdb_id: u32,
}

impl<'sdb> QueryPacket<'sdb> for ParamsReadQuery<'sdb> {
    type Response<'r> = ParamReadDynResponse<'sdb>;

    fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'sdb>> as BinRead>::Args<'sdb> {
        self.query_set.clone()
    }
}

impl<'sdb> ParamsReadQuery<'sdb> {
    pub fn new(sdb: &'sdb sdb::Sdb, query_set: ParamQuerySet<'sdb>) -> Self {
        let params = query_set
            .0
            .iter()
            .map(|param| ParamRead::new(param.id(), param.type_info().response_len() as u32))
            .collect();
        Self {
            query_set,
            params,
            sdb_id: sdb.sdb_id,
        }
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
    sdb_id: u32,
}

impl QueryPacket<'static> for PayloadParamWrite {
    type Response<'p> = PayloadUnknown;
    fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'_>> as BinRead>::Args<'_> {}
}

impl PayloadParamWrite {
    pub fn new(sdb: &sdb::Sdb, params: &[ParamWrite]) -> Self {
        Self {
            params: params.to_vec(),
            sdb_id: sdb.sdb_id,
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
#[derive(Clone)]
#[br(big, import_raw(read_args: ReadArgs<ParamQuerySet<'sdb>>))]
pub struct ParamReadDynResponse<'sdb> {
    pub error_code: u16,
    #[br(map(|d:u32| Duration::from_millis(d as u64)))]
    pub timestamp: Duration,
    #[br(parse_with = |reader,_,()| parse_dyn_payload(reader, &read_args.args.0))]
    pub data: Vec<Value>,
    #[br(calc = read_args.args)]
    pub query_set: ParamQuerySet<'sdb>,
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

impl Debug for ParamReadDynResponse<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct DbgMapHelper<'a>(&'a ParamQuerySet<'a>, &'a [Value]);
        impl Debug for DbgMapHelper<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                let mut m = f.debug_map();
                for (p, v) in self.0 .0.iter().zip(self.1.iter()) {
                    m.entry(&p.name(), v);
                }
                m.finish()
            }
        }
        let mut s = f.debug_struct("ParamReadDynResponse");
        s.field("error_code", &self.error_code);
        s.field("timestamp", &self.timestamp);
        let p = DbgMapHelper(&self.query_set, self.data.as_slice());
        s.field("params", &p);
        s.finish()
    }
}

impl<'sdb> ParamReadDynResponse<'sdb> {
    pub fn into_hashmap(self) -> HashMap<sdb::Parameter<'sdb>, Value> {
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
pub struct ParamQuerySetBuilder<'sdb>(Vec<sdb::Parameter<'sdb>>, &'sdb sdb::Sdb);

#[derive(Debug, Clone)]
// Use Rc instead of Box, since Clone is required
pub struct ParamQuerySet<'sdb>(pub Rc<[sdb::Parameter<'sdb>]>);

impl<'sdb> ParamQuerySetBuilder<'sdb> {
    pub fn new(sdb: &'sdb sdb::Sdb) -> Self {
        Self(vec![], sdb.get_ref())
    }
    pub fn add(&mut self, name: &str) -> Result<()> {
        self.0.push(self.1.param_by_name(name)?);
        Ok(())
    }
    pub fn add_param(&mut self, param: sdb::Parameter<'sdb>) {
        self.0.push(param);
    }

    pub fn into_query_packet(self) -> PacketCC<'sdb, ParamsReadQuery<'sdb>> {
        let mut p = PacketCC::new(ParamsReadQuery::new(self.1, ParamQuerySet(self.0.into())));
        p.hdr.one_if_data_poll_maybe = 1;
        p
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub mod cc_payloads {
    /// Specific command-reply CC packet payloads for various purposes,
    /// reconstructed from Wireshark captures.
    use super::*;

    #[binwrite]
    #[derive(Clone, Debug)]
    #[bw(big, magic = 0x11u8)]
    pub struct InstrumentVersionQuery;

    impl QueryPacket<'static> for InstrumentVersionQuery {
        type Response<'p> = InstrumentVersionResponse;
        fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'_>> as BinRead>::Args<'_> {}
    }

    #[binread]
    #[derive(Clone, Debug)]
    #[br(big, import_raw(args: ReadArgs<()>))]
    pub struct InstrumentVersionResponse {
        error_code: u16,  // ??
        sdb_version: u32, // 0x 00 02 53 34
        u32_0: u32,       // 0x 57 db e3 ce
        #[br(count = args.hdr.payload_len - (2+4+4))]
        str_descr: Vec<u8>,
    }

    #[binwrite]
    #[derive(Clone, Debug)]
    #[bw(big, magic = 0x34u8)]
    pub struct SdbVersionQuery {
        x: &'static [u8],
    }

    impl SdbVersionQuery {
        // https://product-help.schneider-electric.com/Machine%20Expert/V1.1/en/OPCDA/OPCDA/Specific_Information/Specific_Information-10.htm
        pub fn new() -> Self {
            Self {
                x: b"\0\0\x0eDOWNLOAD.SDB\0\0",
            }
        }

        pub fn pkt() -> PacketCC<'static, Self> {
            PacketCC::new(Self::new())
        }
    }

    impl QueryPacket<'static> for SdbVersionQuery {
        type Response<'p> = SdbVersionResponse;
        fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'_>> as BinRead>::Args<'_> {}
    }

    #[binread]
    #[derive(Clone, Debug)]
    #[br(big, import_raw(_hdr:ReadArgs<()>))]
    pub struct SdbVersionResponse {
        pub error_code: u16,
        pub sbd_size: u32,
        pub data: [u8; 4 * 4],
    }

    #[binwrite]
    #[derive(Clone, Debug)]
    #[bw(big, magic = 0x31u8)]
    pub struct SdbDownloadRequest {
        x: &'static [u8],
    }

    impl SdbDownloadRequest {
        // https://product-help.schneider-electric.com/Machine%20Expert/V1.1/en/OPCDA/OPCDA/Specific_Information/Specific_Information-10.htm
        pub fn new() -> Self {
            Self {
                x: b"\0\0\x0eDOWNLOAD.SDB\0\0",
            }
        }

        pub fn pkt() -> PacketCC<'static, Self> {
            PacketCC::new(Self::new())
        }
    }

    impl QueryPacket<'static> for SdbDownloadRequest {
        type Response<'p> = SdbDownload;
        fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'_>> as BinRead>::Args<'_> {}
    }

    #[binwrite]
    #[derive(Clone, Debug)]
    #[bw(big, magic = 0x32u8)]
    pub struct SdbDownloadContinue;

    impl SdbDownloadContinue {
        pub fn pkt() -> PacketCC<'static, Self> {
            PacketCC::new(Self)
        }
    }

    impl QueryPacket<'static> for SdbDownloadContinue {
        type Response<'p> = SdbDownload;
        fn get_response_read_arg(&self) -> <PacketCC<Self::Response<'_>> as BinRead>::Args<'_> {}
    }

    #[binread]
    #[derive(Clone)]
    #[br(big, import_raw(_hdr: ReadArgs<()>))]
    pub struct SdbDownload {
        #[br(try_map(|x:u32|match x {0 => Ok(false), 1 => Ok(true), _ => Err(anyhow!("Unexpected in continues field."))}))]
        pub continues: bool, // 0 if this is the last packet, 1 otherwise
        pub pkt_sdb_part_len: u16,
        #[br(count = pkt_sdb_part_len)]
        pub sdb_part: Vec<u8>,
    }

    impl Debug for SdbDownload {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "PayloadSdbDownload {{\n continues: {},\n{}}}",
                self.continues,
                hexdump(&self.sdb_part[0..100]),
            )
        }
    }
}
