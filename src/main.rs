use anyhow::{Context, Result};
use binrw::{binrw, io::Cursor, BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Deref;

fn hex<H: Deref<Target = [u8]>>(hex: &H) {
    println!("{}", hexdump(hex.as_ref()));
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32)]
struct PacketCCHeader {
    payload_len: u32, // total packet len - 24
    b8_f: u64,        // 0?
    b10_13: u32,      // 0 or 1
    b_14_15: u16,     // 0
    b16: u8,          // 23 or 27
    b17: u8,          //
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big)]
struct PacketCC {
    hdr: PacketCCHeader,
    #[br(count = hdr.payload_len)]
    payload: Vec<u8>,
}

fn query_fw_ver() -> PacketCC {
    let payload = vec![0x11];
    PacketCC {
        hdr: PacketCCHeader {
            payload_len: payload.len() as u32,
            b8_f: 0,
            b10_13: 1,
            b_14_15: 0,
            b16: 1,
            b17: 0x23,
        },
        payload,
    }
}

fn query_download_sdb() -> PacketCC {
    let mut payload = b"1\0\0\x0eDOWNLOAD.SDB\0\0".to_vec();

    PacketCC {
        hdr: PacketCCHeader {
            payload_len: payload.len() as u32,
            b8_f: 0,
            b10_13: 1,
            b_14_15: 0,
            b16: 0x12,
            b17: 0x23,
        },
        payload,
    }
}

fn send<P>(pkt: &P, buf: &mut Vec<u8>, stream: &mut TcpStream) -> Result<()>
where
    P: BinWrite,
    <P as BinWrite>::Args: Default,
{
    pkt.write_to(&mut Cursor::new(&mut *buf))?;
    // hex(&buf);
    stream
        .write_all(buf.as_slice())
        .context("Write to TCP stream failed.")
}

fn receive_response(stream: &mut TcpStream) -> Result<PacketCC> {
    let mut buf = vec![0; 24];
    stream.read_exact(buf.as_mut_slice())?;
    let hdr =
        PacketCCHeader::read(&mut Cursor::new(&buf)).context("Response header parse error")?;
    buf.resize(hdr.payload_len as usize + 24, 0);
    stream.read_exact(&mut buf[24..])?;
    hex(&buf);
    Cursor::new(buf).read_be().context("Response parse error.")
}

fn query(pkt: &PacketCC) -> Result<PacketCC> {
    let mut stream = TcpStream::connect("192.168.1.51:1202")?;
    let mut buf = vec![];
    send(pkt, &mut buf, &mut stream)?;
    receive_response(&mut stream)
}

fn main() -> Result<()> {
    let pkt = query_download_sdb();
    // let pkt = query_fw_ver();
    let r = query(&pkt)?;
    println!("{:x?}", r);
    Ok(())
}
