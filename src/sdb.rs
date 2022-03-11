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
    pub i1: u32,
    pub i2: u32,
    pub i3: u32,
    pub id: u32,
    pub name: SdbStr,
}

impl Debug for Parameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:36?} id: {:05x}, i1: {:02x}, i2: {:8x}, i3: {:x}",
            self.name, self.id, self.i1, self.i2, self.i3
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
