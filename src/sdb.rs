use anyhow::{Context, Result};
use binrw::{BinRead, NullString};

use std::fmt::{Debug, Formatter};

#[derive(BinRead, Clone, Debug, PartialEq)]
#[br(little)]
pub enum Entry {
    #[br(magic = 0x01u32)]
    X01 {
        len: u32,
        #[br(count = 40-8)]
        data: Vec<u8>,
    },
    #[br(magic = 0x03u32)]
    X03 { i1: u32, i2: u32, i3: u32 },
    #[br(magic = 0x04u32)]
    X04 {
        len: u32,
        i1: u32,
        i2: u32,
        name: SdbStr,
        #[br(count = len - 4*4 - 2 - name.len as u32)]
        tail: Vec<u8>,
    },
    #[br(magic = 0x05u32)]
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

#[derive(BinRead, Clone, PartialEq)]
#[br(little)]
pub struct Parameter {
    len: u32,
    pub value_type: ValueType, //ValueType,
    pub i2: u32,
    pub i3: u32,
    pub id: u32,
    pub name: SdbStr,
}

#[derive(BinRead, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[br(little, repr=u32)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ValueType {
    x0 = 0x00,
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
    x25 = 0x19,
    x26 = 0x1a,
    x27 = 0x1b,
    x28 = 0x1c,
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
            "{:38?} id: {:05x}, type: {:?}, i2: {:8x}, i3: {:x}",
            self.name, self.id, self.value_type, self.i2, self.i3
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
