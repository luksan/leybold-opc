use anyhow::{Context, Result};
use binrw::{
    binread, BinRead, BinReaderExt, BinResult, Endian, Error as BinErr, NullString, ReadOptions,
    VecArgs,
};

use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Read, Seek};

#[derive(BinRead, Clone, Debug)]
#[br(little)]
pub enum Entry {
    Header(Header),
    #[br(magic = 0x03u32)]
    X03 {
        i1: u32,
        i2: u32,
        i3: u32,
    },
    TypeDescr(TypeDescription),
    Parameter(Parameter),
    #[br(magic = 0x06u32)]
    Tail {
        len: u32,
        #[br(count = len - 8)]
        data: Vec<u8>,
    },
    #[br(magic = 0x0Du32)]
    EndOfHeader,
}

#[binread]
#[derive(Clone, Debug)]
#[br(little)]
pub struct Sdb {
    hdr: Header,
    #[br(parse_with = parse_type_descr, args (hdr.type_descr_cnt))]
    type_descr: Vec<TypeDescription>,

    #[br(magic = 3u32)]
    len_xx: u32, // maybe a length field
    #[br(magic = 0u32, temp)] // consume four NUL bytes with magic
    param_cnt: u32,
    #[br(count = param_cnt)]
    parameters: Vec<Parameter>,

    #[br(parse_with = parse_entries)]
    entries: Vec<Entry>,
}

fn parse_type_descr<Reader: Read + Seek>(
    reader: &mut Reader,
    opts: &ReadOptions,
    args: (u32,),
) -> BinResult<Vec<TypeDescription>> {
    let mut vec = Vec::with_capacity(args.0 as usize);
    for idx in 0..args.0 {
        vec.push(TypeDescription::read_options(reader, opts, (idx,))?);
    }
    Ok(vec)
}

fn parse_entries<Reader: Read + Seek>(
    reader: &mut Reader,
    opts: &ReadOptions,
    args: (),
) -> BinResult<Vec<Entry>> {
    let mut entries = vec![];
    loop {
        match Entry::read_options(reader, opts, args) {
            Ok(e) => entries.push(e),
            Err(_) => {
                break;
            }
        }
    }
    Ok(entries)
}

#[derive(BinRead, Clone, Debug, PartialEq)]
#[br(little, magic = 0x01u32)]
pub struct Header {
    len: u32,
    #[br(count = 40 - 8 - 4)]
    data: Vec<u8>,
    type_descr_cnt: u32,
}

#[derive(BinRead, Clone, Debug)]
#[br(little, magic = 0x04u32, import(idx:u32))]
pub struct TypeDescription {
    #[br(calc = idx)]
    type_idx: u32,
    len: u32,
    i1: u32,
    type_size: u32,
    description: SdbStr,
    #[br(args (i1, len - 4*4 - 2 - description.len as u32))]
    payload: TypeDescPayload,
    //#[br(count= len - 4*4 - 2 - description.len as u32)]
    //payload: Vec<u8>,
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
    type Args = (u32, u32); // type, payload len

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        if args.1 == 0 {
            return Ok(Self::None);
        }
        Ok(match args.0 {
            0x09 => Self::Array(ArrayDesc::read_options(reader, options, ())?),
            0x0b => {
                let x = X4DataXBTail::read_options(reader, options, ())?;
                Self::Struct(x.entries)
            }
            0x17 => Self::Pointer(u32::read_options(reader, options, ())?),
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
    println!("{} entries in SDB.", sdb.entries.len());
    // entries.sort_by_key(|e| e.value_type);
    // entries.dedup_by_key(|e| e.value_type);

    for t in &sdb.type_descr {
        // println!("{t:?}");
        println!(
            "Type #{:02} {:30?} read size: {:>5}, info: {:?}",
            t.type_idx, t.description, t.type_size, t.payload
        );
    }

    for p in &sdb.parameters {
        println!("Param {p:?}");
    }

    for e in sdb.entries.iter() {
        println!("{e:x?}");
        if let Entry::Parameter(ref p) = e {
            if p.value_type == ValueType::x9 {
                //println!("{p:?}");
            }
            if p.name.try_as_str()?.starts_with(".Gauge[1].Parameter[1]") {
                //println!("{p:?}");
            }
            if p.i2 != 0 {
                // println!("{:?}", p);
            }
        } else {
            //   println!("{e:?}")
        }
    }
    Ok(())
}

pub fn x04_analysis() -> Result<()> {
    let sdb = read_sdb_file()?;

    let mut x04 = sdb.type_descr.iter().collect::<Vec<_>>();

    // x04.sort_by_key(|x| x.i1);
    for e in x04.iter() {
        let idx = e.type_idx;
        let name = e.description.try_as_str()?;
        let i1 = e.i1;
        let type_size = e.type_size;
        println!("X04:{idx:2x} i1 {i1:2x}, tlen {type_size:5x}, {name}");
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
#[br(little)]
pub struct X4DataXBTail {
    count: u32,
    #[br(count = count)]
    entries: Vec<StructMember>,
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
