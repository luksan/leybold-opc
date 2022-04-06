use anyhow::{Context, Result};
use binrw::{
    binread, BinRead, BinReaderExt, BinResult, Endian, Error as BinErr, NullString, ReadOptions,
    VecArgs,
};

use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Read, Seek};

#[binread]
#[derive(Clone, Debug)]
#[br(little)]
pub struct Sdb {
    #[br(magic = 1u32, temp)]
    hdr_len: u32,
    hdr_data: [u32; 3],
    /// Total size of the SDB in bytes
    total_sbd_size: u32,
    hdr_data_2: [u32; 3],
    #[br(temp)]
    type_descr_cnt: u32,

    #[br(count = type_descr_cnt, map = |mut vec: Vec<TypeDescription>| {
        vec.iter_mut().enumerate().for_each(|(idx, t)|t.type_idx = idx as _); vec
    })]
    type_descr: Vec<TypeDescription>,

    #[br(magic = 3u32)]
    len_xx: u32, // maybe a length field
    #[br(magic = 0u32, temp)] // consume four NUL bytes with magic
    param_cnt: u32,
    #[br(count = param_cnt)]
    parameters: Vec<Parameter>,

    #[br(magic = 6u32, temp)]
    tail_len: u32,
    #[br(count = tail_len - 8)]
    tail: Vec<u8>,
}

#[binread]
#[derive(Clone, Debug)]
#[br(little, magic = 0x04u32)]
pub struct TypeDescription {
    #[br(default)]
    type_idx: u32, // this is set in struct Sdb
    #[br(temp)]
    len: u32,
    kind: TypeKind,
    type_size: u32,
    description: SdbStr,
    #[br(args (kind, len - 4*4 - 2 - description.len as u32))]
    payload: TypeDescPayload,
}

#[derive(Copy, Clone, Debug, BinRead, PartialEq)]
#[br(repr(u32), little)]
pub enum TypeKind {
    Bool = 0,
    Int = 1,
    Byte = 2,
    Word = 3,
    Dword = 5,
    Real = 6,
    Time = 7,
    String = 8,
    Array = 9,
    Data = 11,
    Uint = 0x10,
    Udint = 0x11,
    Pointer = 0x17,
}

#[derive(Clone, Debug)]
pub enum TypeDescPayload {
    None,
    Array(ArrayDesc),
    Struct(Vec<StructMember>),
    Pointer(u32),
    Other(Vec<u8>),
}

impl BinRead for TypeDescPayload {
    type Args = (TypeKind, u32); // type, payload len

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        if args.1 == 0 {
            return Ok(Self::None);
        }
        Ok(match args.0 {
            TypeKind::Array => Self::Array(ArrayDesc::read_options(reader, options, ())?),
            TypeKind::Data => {
                let count = u32::read_options(reader, options, ())? as usize;
                let args = VecArgs { count, inner: () };
                Self::Struct(Vec::<StructMember>::read_options(reader, options, args)?)
            }
            TypeKind::Pointer => Self::Pointer(u32::read_options(reader, options, ())?),
            _ => Self::Other(reader.read_type_args(
                Endian::Little,
                VecArgs {
                    count: args.1 as usize,
                    inner: (),
                },
            )?),
        })
    }
}

#[derive(BinRead, Clone, PartialEq)]
#[br(little, magic = 0x05u32)]
pub struct Parameter {
    len: u32,
    pub value_type: ValueType, //ValueType,
    pub i2a: u16,
    pub i2: u16,
    pub i3: u32,
    pub id: u32,
    pub name: SdbStr,
}

#[derive(BinRead, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[br(little, repr=u32)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ValueType {
    Bool = 0x00,
    I16 = 0x01,
    Bstr = 0x02,
    BstrUnit = 0x03,
    BstrPrefix = 0x04,
    F32 = 0x05,
    BstrValue = 0x06,
    UI1Array = 0x07,
    x8 = 0x08,
    x9 = 0x09,
    x10 = 0x0a,
    x11 = 0x0b,
    x12 = 0x0c,
    x13 = 0x0d,
    x14 = 0x0e,
    x15 = 0x0f,
    x16 = 0x10,
    x17 = 0x11,
    x18 = 0x12,
    x19 = 0x13,
    x20 = 0x14,
    x21 = 0x15,
    x22 = 0x16,
    x23 = 0x17,
    x24 = 0x18,
    ParamGrp = 0x19,
    GaugeEntry = 0x1a,
    Gauges = 0x1b,
    Special = 0x1c,
    x29 = 0x1d,
    x30 = 0x1e,
    x31 = 0x1f,
    x32 = 0x20,
    x33 = 0x21,
    x34 = 0x22,
    x35 = 0x23,
    x36 = 0x24,
    x37 = 0x25,
    x38 = 0x26,
    x39 = 0x27,
    x40 = 0x28,
    x41 = 0x29,
    x42 = 0x2a,
    x43 = 0x2b,
    x44 = 0x2c,
    x45 = 0x2d,
}

impl Debug for Parameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:38?} id: {:05x}, type: {:?},\t i2a: {:x}, i2: {:x}, i3: {:x}",
            self.name, self.id, self.value_type, self.i2a, self.i2, self.i3
        )
    }
}

#[derive(BinRead, Clone, PartialEq)]
#[br(little)]
pub struct SdbStr {
    len: u16,
    #[br(align_after = 4)]
    s: NullString,
}

impl SdbStr {
    pub fn try_as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.s.0.as_slice())
            .with_context(|| format!("SdbStr is not valid utf-8: {:?}", self.s))
    }
}

impl Debug for SdbStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = std::str::from_utf8(self.s.0.as_slice()).unwrap();
        if let Some(width) = f.width() {
            let width = width.saturating_sub(s.len() + 2);
            write!(f, "\"{}\"{:width$}", s, "")
        } else {
            write!(f, "\"{}\"", s)
        }
    }
}

pub fn print_sdb_file() -> Result<()> {
    let sdb = read_sdb_file()?;
    println!("{} entries in SDB.", sdb.parameters.len());
    // entries.sort_by_key(|e| e.value_type);
    // entries.dedup_by_key(|e| e.value_type);

    println!("Header data {:?}, {:?}", sdb.hdr_data, sdb.hdr_data_2);

    for t in &sdb.type_descr {
        // println!("{t:?}");
        println!(
            "Type #{:02} {:30?} {:?}, read size: {:>5}, info: {:?}",
            t.type_idx, t.description, t.kind, t.type_size, t.payload
        );
    }

    for p in &sdb.parameters {
        println!("Param {p:?}");
    }

    println!("{}", hexdump(&sdb.tail));
    Ok(())
}

pub fn x04_analysis() -> Result<()> {
    let sdb = read_sdb_file()?;

    let mut x04 = sdb.type_descr.iter().collect::<Vec<_>>();

    // x04.sort_by_key(|x| x.i1);
    for e in x04.iter() {
        let idx = e.type_idx;
        let name = e.description.try_as_str()?;
        let i1 = e.kind;
        let type_size = e.type_size;
        println!("X04:{idx:2x} kind {i1:?}, tlen {type_size:5x}, {name}");
        match &e.payload {
            TypeDescPayload::None => {}
            TypeDescPayload::Array(a) => {
                println!("  {a:?}")
            }
            TypeDescPayload::Pointer(p) => {
                println!("  Pointer -> {p:x}")
            }
            TypeDescPayload::Struct(b) => {
                for b in b.iter() {
                    println!("  {b:x?}")
                }
            }
            TypeDescPayload::Other(vec) => {
                println!("{}", hexdump(vec))
            }
        }
    }
    Ok(())
}

#[binread]
#[derive(Debug, Clone)]
#[br(little)]
pub struct ArrayDesc {
    type_idx: u32,
    #[br(temp)]
    array_dim: u32,
    #[br(count = array_dim)]
    dims: Vec<(u32, u32)>,
}

#[binread]
#[derive(Debug, Clone)]
#[br(little, magic = 0x05u32)]
pub struct StructMember {
    i1: u32,
    value_type: ValueType,
    i: [u32; 2],
    id_offset: u32, // the number to add to this parameters id to get the sub entries id.
    name: SdbStr,
}

pub fn read_sdb_file() -> Result<Sdb> {
    let mut file = std::io::BufReader::new(std::fs::File::open("sdb.dat")?);
    Sdb::read(&mut file).context("Failed to parse SDB file.")
}
