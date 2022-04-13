use anyhow::{Context, Result};
use binrw::{binread, BinRead, BinReaderExt, BinResult, Endian, NullString, ReadOptions, VecArgs};

use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek};

pub use api::*;

pub mod api {
    use super::*;
    pub use super::{Sdb, TypeKind};

    #[derive(Copy, Clone)]
    pub struct Parameter<'a> {
        sdb: &'a Sdb,
        param: &'a SdbParam,
        descr: &'a TypeDescription,
    }

    impl<'a> Parameter<'a> {
        pub(super) fn new(sdb: &'a Sdb, param: &'a SdbParam, descr: &'a TypeDescription) -> Self {
            Self { sdb, param, descr }
        }

        pub fn name(&self) -> &str {
            self.param.name.try_as_str().unwrap()
        }
        pub fn id(&self) -> u32 {
            self.param.id
        }

        pub fn type_info(&self) -> TypeInfo {
            TypeInfo {
                sdb: self.sdb,
                descr: self.descr,
            }
        }

        /// Returns a TypeKind enum value, describing the data type of the parameter.
        pub fn value_kind(&self) -> TypeKind {
            self.descr.kind
        }
    }

    impl Debug for Parameter<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Parameter<{}>", self.name())
        }
    }

    #[derive(Copy, Clone, Debug)]
    pub struct TypeInfo<'a> {
        sdb: &'a Sdb,
        descr: &'a TypeDescription,
    }

    impl<'a> TypeInfo<'a> {
        fn new(sdb: &'a Sdb, idx: u32) -> Result<Self> {
            let descr = sdb.get_desc(idx)?;
            Ok(Self { sdb, descr })
        }
        pub fn kind(&self) -> TypeKind {
            self.descr.kind
        }

        pub fn response_len(&self) -> usize {
            self.descr.type_size as usize
        }

        pub fn array_info(&self) -> Option<(TypeInfo, [usize; 2])> {
            if let TypeDescPayload::Array(ref arr) = self.descr.payload {
                let mut dims = [0; 2];
                for d in 0..arr.dims.len() {
                    let x = arr.dims[d];
                    dims[d] = (x.1 - x.0 + 1) as usize;
                }
                Some((TypeInfo::new(self.sdb, arr.type_idx).ok()?, dims))
            } else {
                None
            }
        }
        pub fn struct_info(&self) -> Option<Vec<StructMemberInfo>> {
            if let TypeDescPayload::Struct(ref v) = self.descr.payload {
                Some(
                    v.iter()
                        .map(|m| {
                            Some(StructMemberInfo {
                                name: m.name.try_as_str().ok()?,
                                type_info: Self::new(self.sdb, m.type_descr_idx).ok()?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?,
                )
            } else {
                None
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    pub struct StructMemberInfo<'a> {
        pub name: &'a str,
        pub type_info: TypeInfo<'a>,
    }

    pub fn read_sdb_file() -> Result<Sdb> {
        let mut file = std::io::BufReader::new(std::fs::File::open("sdb.dat")?);
        Sdb::read(&mut file).context("Failed to parse SDB file.")
    }
}

#[binread]
#[derive(Clone, Debug)]
#[br(little)]
pub struct Sdb {
    #[br(magic = 1u32, temp)]
    hdr_len: u32,
    #[br(magic = 1u32)]
    /// Sent at the end of every parameter read packet
    sdb_id: u32,
    maybe_checksum: u32,
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
    parameters: Vec<SdbParam>,

    #[br(magic = 6u32, temp)]
    tail_len: u32,
    #[br(count = tail_len - 8)]
    tail: Vec<u8>,
}

impl Sdb {
    pub fn param_by_name(&self, name: &str) -> Result<Parameter> {
        let param = self
            .parameters
            .iter()
            .find(|p| p.name == name)
            .with_context(|| format!("Parameter name '{}' not found", name))?;

        let descr = self.get_desc(param.type_descr_idx)?;
        Ok(Parameter::new(self, param, descr))
    }

    fn param_by_id(&self, idx: u32) -> Result<Parameter> {
        let param = self
            .parameters
            .iter()
            .find(|p| p.id == idx)
            .context("Parameter ID not found")?;

        let descr = self.get_desc(param.type_descr_idx)?;
        Ok(Parameter::new(self, param, descr))
    }

    fn get_desc(&self, idx: u32) -> Result<&TypeDescription> {
        self.type_descr
            .get(idx as usize)
            .context("Type descriptor not found")
    }
}

#[binread]
#[derive(Clone, Debug)]
#[br(little, magic = 0x04u32)]
struct TypeDescription {
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

impl TypeDescription {
    pub fn kind(&self) -> TypeKind {
        self.kind
    }

    pub fn read_len(&self) -> usize {
        self.type_size as usize
    }
}

/// The various parameter data types
#[derive(Copy, Clone, Debug, BinRead, PartialEq)]
#[br(repr(u32), little)]
pub enum TypeKind {
    Bool = 0,
    /// Signed 2-byte int
    Int = 1,
    Byte = 2,
    /// Unsigned 2-byte int
    Word = 3,
    /// Unsigned 4-byte int
    Dword = 5,
    /// 32 bit float
    Real = 6,
    Time = 7,
    String = 8,
    /// Array data, see array_info()
    Array = 9,
    /// Structured data, see struct_info()
    Data = 11,
    /// Unsigned 2-byte int
    Uint = 0x10,
    /// Unsigned 4-byte int
    Udint = 0x11,
    Pointer = 0x17,
}

#[derive(Clone, Debug)]
enum TypeDescPayload {
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

#[binread]
#[derive(Clone, PartialEq)]
#[br(little, magic = 0x05u32)]
struct SdbParam {
    #[br(temp)]
    len: u32,
    type_descr_idx: u32,
    flags: [u16; 2],
    rw: AccessMode,
    #[br(magic(0x03u16))]
    id: u32,
    name: SdbStr,
}

#[derive(BinRead, Debug, Copy, Clone, PartialEq)]
#[br(little, repr(u16))]
pub enum AccessMode {
    Read = 0x72,
    Write = 0xFF, // FIXME: I don't know.
    ReadWrite = 0x62,
}

impl Debug for SdbParam {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:38?} id: {:05x}, type: {:?},\t flags: {:x?}, rw: {:?}",
            self.name, self.id, self.type_descr_idx, self.flags, self.rw
        )
    }
}

#[derive(BinRead, Clone, PartialEq)]
#[br(little)]
struct SdbStr {
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

impl PartialEq<&str> for SdbStr {
    fn eq(&self, other: &&str) -> bool {
        self.try_as_str().ok().map(|s| s == *other).unwrap_or(false)
    }
}

pub fn print_sdb_file() -> Result<()> {
    let sdb = read_sdb_file()?;
    println!("{} entries in SDB.", sdb.parameters.len());
    // entries.sort_by_key(|e| e.value_type);
    // entries.dedup_by_key(|e| e.value_type);

    println!("Header data {:?}, {:?}", sdb.maybe_checksum, sdb.hdr_data_2);

    for t in &sdb.type_descr {
        // println!("{t:?}");
        println!(
            "Type #{:02} {:30?} {:?}, read size: {:>5}, info: {:#?}",
            t.type_idx, t.description, t.kind, t.type_size, t.payload
        );
    }

    for p in &sdb.parameters {
        let descr = sdb.get_desc(p.type_descr_idx).expect("Invalid type idx.");
        let name = p.name.try_as_str().expect("Name not valid utf-8");
        let kind = format!("{:?}~{}", descr.kind, descr.read_len());
        if descr.kind != TypeKind::Pointer {
            //    continue;
        }
        println!(
            "{name:38} id: {:05x}, type: {kind:12} {:4x?}, {:?}",
            p.id, p.flags, p.rw,
        )
    }

    println!("{}", hexdump(&sdb.tail));
    Ok(())
}

#[binread]
#[derive(Clone)]
#[br(little)]
struct ArrayDesc {
    type_idx: u32,
    #[br(temp)]
    array_dim: u32,
    #[br(count = array_dim)]
    dims: Vec<(u32, u32)>,
}

impl Debug for ArrayDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "type: {} size: {:?}", self.type_idx, self.dims)
    }
}

#[binread]
#[derive(Clone)]
#[br(little, magic = 0x05u32)]
struct StructMember {
    #[br(temp)]
    len: u32,
    type_descr_idx: u32,
    i: [u32; 2],
    id_offset: u32, // the number to add to this parameters id to get the sub entries id.
    name: SdbStr,
}

impl Debug for StructMember {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} type: {}",
            self.name.try_as_str().unwrap(),
            self.type_descr_idx
        )
    }
}
