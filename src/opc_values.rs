use crate::sdb::{TypeInfo, TypeKind};

use anyhow::{anyhow, bail, Result};
use binrw::{BinRead, BinReaderExt, BinResult, ReadOptions};

use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Read, Seek};

/// Used when parsing the response from the instrument,
/// for converting OPC types to native Rust types.
#[derive(Clone)]
pub enum Value {
    /// A Vec with Values
    Array(Vec<Value>),
    Matrix(Vec<Vec<Value>>),
    Bool(bool),
    Int(i64),
    Float(f32),
    String(String),
    Struct(Vec<(String, Value)>),
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pad = f.width().unwrap_or(0) + 2;
        match self {
            Self::Array(vec) => {
                write!(f, "Array[{}] {vec:pad$?}", vec.len())
            }
            Self::Matrix(m) => write!(f, "{m:?})"),
            Self::Struct(s) => {
                writeln!(f, "Struct {{")?;
                for m in s {
                    writeln!(f, "{:>pad$}{}: {:pad$?}", "", m.0, m.1)?;
                }
                write!(f, "{:>pad$}}}", "", pad = pad - 2)
            }

            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(i) => write!(f, "{i:?}"),
            Self::String(s) => write!(f, "\"{s}\""),
        }
    }
}

impl Value {
    pub fn parse(data: &[u8], param: &TypeInfo) -> BinResult<Self> {
        let mut cur = Cursor::new(data);
        Self::parse_param(&mut cur, param)
    }

    fn parse_param(cur: &mut Cursor<&[u8]>, param: &TypeInfo) -> BinResult<Self> {
        let start_pos = cur.position();
        macro_rules! int {
            ($ty:ty) => {{
                let read_len = param.response_len() as usize;
                assert_eq!(
                    read_len,
                    std::mem::size_of::<$ty>(),
                    "Type size and specified size are unequal."
                );
                if read_len > 1 && start_pos & 1 == 1 {
                    // adjust alignment to 2 bytes
                    cur.set_position(start_pos + 1);
                }
                Value::Int(cur.read_be::<$ty>()? as i64)
            }};
        }
        let value = match param.kind() {
            TypeKind::Array => {
                let (ty, dims) = param.array_info().unwrap();
                match dims {
                    [len, 0] => {
                        let mut v = Vec::with_capacity(len);
                        for _ in 0..len {
                            v.push(Self::parse_param(cur, &ty)?);
                        }
                        Value::Array(v)
                    }
                    [_a, _b] => {
                        todo!("Have to check the order the elements are stored.")
                    }
                }
            }
            TypeKind::Data => {
                let info = param.struct_info().unwrap();
                let mut ret = Vec::with_capacity(info.len());
                for m in info {
                    let name = m.name.to_string();
                    let value = Self::parse_param(cur, &m.type_info)?;
                    ret.push((name, value));
                }
                Value::Struct(ret)
            }
            TypeKind::Bool => Value::Bool(cur.read_be::<u8>()? != 0),
            TypeKind::Int => int!(i16),
            TypeKind::Byte => int!(u8),
            TypeKind::Word | TypeKind::Uint => int!(u16),
            TypeKind::Dword | TypeKind::Udint | TypeKind::Pointer => int!(u32),
            TypeKind::Real => {
                if start_pos & 1 == 1 {
                    // Adjust alignment
                    cur.set_position(start_pos + 1);
                }
                Value::Float(cur.read_be::<f32>()?)
            }
            TypeKind::Time => int!(u32),
            TypeKind::String => {
                let mut v = vec![0; param.response_len()];
                cur.read_exact(v.as_mut_slice())?;
                if let Some(nul_pos) = v.iter().position(|&b| b == 0) {
                    v.truncate(nul_pos);
                }
                Value::String(String::from_utf8_lossy(&v).to_string())
            }
        };
        Ok(value)
    }

    pub fn from_str(val: &str, desc: &TypeInfo) -> Result<Self> {
        Ok(match desc.kind() {
            TypeKind::Bool => Value::Bool(val.parse()?),
            TypeKind::Real => Value::Float(val.parse()?),
            TypeKind::Time => unimplemented!(),
            TypeKind::String => Value::String(val.to_string()),
            TypeKind::Array => unimplemented!(),
            TypeKind::Data => unimplemented!(),
            TypeKind::Pointer => unimplemented!(),
            _ => Value::Int(val.parse()?),
        })
    }
}

impl BinRead for Value {
    type Args = TypeInfo;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let mut buf = vec![0; args.response_len()];
        reader.read_exact(buf.as_mut_slice())?;
        Self::parse(&buf, &args)
    }
}

pub trait EncodeOpcValue {
    fn opc_encode(self, desc: &TypeInfo) -> Result<Vec<u8>>;
}

impl EncodeOpcValue for &Value {
    fn opc_encode(self, desc: &TypeInfo) -> Result<Vec<u8>> {
        match self {
            Value::Bool(b) if desc.kind() == TypeKind::Bool => return Ok(vec![*b as u8]),
            Value::Int(i) => return i.opc_encode(desc),
            Value::Float(_) => todo!("Implement OPC value encoding for f32."),
            Value::String(s) => return s.as_bytes().opc_encode(desc),
            _ => {}
        }
        bail!("Can't encode value {:?} as {:?}", self, desc.kind())
    }
}

macro_rules! impl_enc_int {
    ($($int:ty),+) => {$(
        impl EncodeOpcValue for $int {
            fn opc_encode(self, desc: &TypeInfo) -> Result<Vec<u8>> {
                let mut ret = Vec::with_capacity(desc.response_len());
                macro_rules! try_into {
                    ($ty:ty) => {{
                        let x: $ty = self
                            .try_into()
                            .map_err(|_| anyhow!("Int didn't fit in OPC size."))?;
                        ret.extend_from_slice(&x.to_be_bytes());
                    }};
                }
                match desc.kind() {
                    TypeKind::Byte => try_into!(u8),
                    TypeKind::Int => try_into!(i16),
                    TypeKind::Word | TypeKind::Uint => try_into!(u16),
                    TypeKind::Dword | TypeKind::Udint => try_into!(u32),
                    _ => bail!("Can't encode value"),
                }
                Ok(ret)
            }
        })+
    };
}
impl_enc_int!(u8, i8, u16, i16, u32, i32, u64, i64, usize, isize);

impl EncodeOpcValue for &[u8] {
    fn opc_encode(self, desc: &TypeInfo) -> Result<Vec<u8>> {
        if desc.kind() == TypeKind::String {
            if self.len() > desc.response_len() {
                bail!("Slice to big to fit in parameter")
            }
            let mut ret = Vec::from(self);
            ret.resize(desc.response_len(), 0);
            Ok(ret)
        } else {
            bail!("&[u8] can only be sent to String type parameters.")
        }
    }
}

impl<const N: usize> EncodeOpcValue for &[u8; N] {
    fn opc_encode(self, desc: &TypeInfo) -> Result<Vec<u8>> {
        self.as_slice().opc_encode(desc)
    }
}
