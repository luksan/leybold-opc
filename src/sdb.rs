#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use binrw::{binread, BinRead, BinResult, Endian, VecArgs};
use rhexdump::hexdump;

use std::fmt::{Debug, Formatter};
use std::io::{BufReader, ErrorKind, Read, Seek};
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;

pub use api::*;

pub mod api {
    use super::*;
    pub use super::{Sdb, TypeKind};
    use crate::opc_values::Value;
    use std::hash::{Hash, Hasher};

    #[derive(Clone)]
    pub struct Parameter<'sdb> {
        sdb: &'sdb Sdb,
        param: usize,
        descr: usize,
    }

    impl<'sdb> Parameter<'sdb> {
        pub(super) fn new(sdb: &'sdb Sdb, param: usize, descr: usize) -> Self {
            Self { sdb, param, descr }
        }

        pub fn name(&self) -> &str {
            self.sdb.parameters[self.param].name.as_str()
        }

        pub fn id(&self) -> u32 {
            self.sdb.parameters[self.param].id
        }

        pub fn type_info(&self) -> TypeInfo<'_> {
            TypeInfo {
                sdb: self.sdb,
                descr: self.descr,
            }
        }

        /// Returns a TypeKind enum value, describing the data type of the parameter.
        pub fn value_kind(&self) -> TypeKind {
            self.sdb.type_descr[self.descr].kind
        }

        pub fn value_from_str(&self, val: &str) -> Result<Value> {
            Value::from_str(val, &self.type_info())
        }
    }

    impl Hash for Parameter<'_> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            (&self.sdb as *const _ as u64).hash(state);
            self.param.hash(state);
            self.descr.hash(state);
        }
    }

    impl PartialEq<Self> for Parameter<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.param == other.param
                && self.descr == other.descr
                && core::ptr::eq(&self.sdb, &other.sdb)
        }
    }
    impl Eq for Parameter<'_> {}

    impl Debug for Parameter<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Parameter<{}>", self.name())
        }
    }

    #[derive(Clone, Debug)]
    pub struct TypeInfo<'sdb> {
        sdb: &'sdb Sdb,
        descr: usize,
    }

    impl<'sdb> TypeInfo<'sdb> {
        fn new(sdb: &'sdb Sdb, idx: u32) -> Self {
            let descr = idx as usize;
            Self { sdb, descr }
        }

        fn descr(&self) -> &TypeDescription {
            &self.sdb.type_descr[self.descr]
        }

        pub fn kind(&self) -> TypeKind {
            self.descr().kind
        }

        pub fn response_len(&self) -> usize {
            self.descr().type_size as usize
        }

        pub fn array_info(&self) -> Option<(TypeInfo, [usize; 2])> {
            let TypeDescPayload::Array(ref arr) = self.descr().payload else { return None; };
            let mut dims = [0; 2];
            for d in 0..arr.dims.len() {
                let x = arr.dims[d];
                dims[d] = (x.1 - x.0 + 1) as usize;
            }
            Some((Self::new(self.sdb, arr.type_idx), dims))
        }

        pub fn struct_info(&self) -> Option<Vec<StructMemberInfo>> {
            let TypeDescPayload::Struct(ref v) = self.descr().payload else { return None };
            v.iter()
                .map(|m| {
                    Some(StructMemberInfo {
                        name: m.name.as_str(),
                        type_info: Self::new(self.sdb, m.type_descr_idx),
                    })
                })
                .collect::<Option<Vec<_>>>()
        }
    }

    #[derive(Clone, Debug)]
    pub struct StructMemberInfo<'a> {
        pub name: &'a str,
        pub type_info: TypeInfo<'a>,
    }

    pub fn read_sdb_file() -> Result<Rc<Sdb>> {
        Sdb::from_file("sdb.dat")
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
    pub(crate) sdb_id: u32,
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
    #[br(args(param_cnt,))]
    parameters: SdbParams,

    #[br(magic = 6u32, temp)]
    tail_len: u32,
    #[br(count = tail_len - 8)]
    tail: Vec<u8>,
}

#[derive(Clone, Debug)]
struct SdbParams(Box<[SdbParam]>);

impl BinRead for SdbParams {
    type Args<'a> = (u32,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let count = args.0 as usize;
        let mut x = Vec::with_capacity(count);
        for _ in 0..count {
            x.push(SdbParam::read_options(reader, endian, ())?);
        }
        Ok(Self(x.into_boxed_slice()))
    }
}

impl Deref for SdbParams {
    type Target = [SdbParam];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Sdb {
    pub fn from_file(file: impl AsRef<Path>) -> Result<Rc<Sdb>> {
        let mut file = std::fs::File::open(file)?;

        let mut reader = std::io::Cursor::new(Vec::new());
        file.read_to_end(reader.get_mut())?;

        let sdb = Sdb::read(&mut reader).context("Failed to parse SDB file.")?;
        Ok(Rc::new(sdb))
    }

    pub fn get_ref(&self) -> &Sdb {
        self
    }

    /// Returns an iterator over all the parameters in the SDB.
    pub fn parameters(&self) -> impl Iterator<Item = Parameter> + '_ {
        self.parameters
            .iter()
            .map(|p| p.type_descr_idx)
            .enumerate()
            .map(move |(param_idx, type_idx)| Parameter::new(self, param_idx, type_idx as usize))
    }

    pub fn param_by_name(&self, name: &str) -> Result<Parameter> {
        let param = self
            .parameters
            .iter()
            .position(|p| p.name == name)
            .with_context(|| format!("Parameter name '{name}' not found"))?;

        let type_idx = self.parameters[param].type_descr_idx as usize;
        if type_idx >= self.type_descr.len() {
            bail!("Invalid type descriptor index for parameter {}.", name)
        }
        Ok(Parameter::new(self, param, type_idx))
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
    #[br(args(kind,))]
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
#[derive(Copy, Clone, Debug, BinRead, PartialEq, Eq)]
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
}

impl BinRead for TypeDescPayload {
    type Args<'a> = (TypeKind,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        Ok(match args.0 {
            TypeKind::Array => Self::Array(ArrayDesc::read_options(reader, options, ())?),
            TypeKind::Data => {
                let count = u32::read_options(reader, options, ())? as usize;
                let args = VecArgs { count, inner: () };
                Self::Struct(Vec::<StructMember>::read_options(reader, options, args)?)
            }
            TypeKind::Pointer => Self::Pointer(u32::read_options(reader, options, ())?),
            _ => Self::None,
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

#[derive(BinRead, Debug, Copy, Clone, PartialEq, Eq)]
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

#[binread]
#[derive(Clone, PartialEq)]
#[br(little)]
struct SdbStr {
    #[br(temp)]
    len: u16,
    #[br(args(len), parse_with = parse_sdbstr)]
    s: SdbStrStorage,
}
const SDB_STR_MAX_LEN: usize = 81;
type SdbStrStorage = compact_str::CompactString;

fn parse_sdbstr<R: Read + Seek>(
    reader: &mut R,
    _endian: Endian,
    args: (u16,),
) -> BinResult<SdbStrStorage> {
    assert!(args.0 as usize <= SDB_STR_MAX_LEN);
    let mut len = args.0 as usize;
    let mut buffer = [0u8; SDB_STR_MAX_LEN];
    reader.read_exact(&mut buffer[..len])?;
    // "len" includes 0 to 3 bytes of NUL padding
    for _ in 0..3 {
        if buffer[len - 1] != 0 {
            break;
        }
        len -= 1;
    }
    SdbStrStorage::from_utf8(&buffer[..len])
        .map_err(|e| binrw::io::Error::new(ErrorKind::InvalidData, e).into())
}

impl SdbStr {
    pub fn as_str(&self) -> &str {
        self.s.as_str()
    }
}

impl Debug for SdbStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s: &str = self.as_str();
        if let Some(width) = f.width() {
            let width = width.saturating_sub(s.len() + 2);
            write!(f, "\"{}\"{:width$}", s, "")
        } else {
            write!(f, "\"{s}\"")
        }
    }
}

impl PartialEq<&str> for SdbStr {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
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

    for p in &*sdb.parameters {
        let descr = sdb.get_desc(p.type_descr_idx).expect("Invalid type idx.");
        let name = p.name.as_str();
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
        write!(f, "{} type: {}", self.name.as_str(), self.type_descr_idx)
    }
}
