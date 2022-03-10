#![allow(dead_code)]

use anyhow::{Context, Result};
use binrw::{binrw, io::Cursor, BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;
use std::fmt::{Debug, Formatter};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Deref;

fn hex<H: Deref<Target = [u8]>>(hex: &H) {
    println!("{}", hexdump(hex.as_ref()));
}

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[binrw]
#[br(big, magic = 0xCCCC0001u32)]
#[bw(big, magic = 0xCCCC0001u32)]
struct PacketCCHeader {
    payload_len: u32, // total packet len - 24
    u64_8_f: u64,     // 0?
    u32_10_13: u32,   // 0 or 1
    u16_14_15: u16,   // 0
    b16: u8,          // 23 or 27
    b17: u8,          //
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big)]
struct PacketCC<Payload = PayloadUnknown>
where
    Payload: 'static + BinRead<Args = (PacketCCHeader,)> + BinWrite<Args = ()>,
{
    hdr: PacketCCHeader,
    #[br(args(hdr))]
    payload: Payload,
}

trait Payload: BinRead<Args = (PacketCCHeader,)> + BinWrite<Args = ()> {
    fn len(&self) -> u32;
}

#[derive(Clone, Debug, PartialEq)]
#[binrw]
#[br(big, import (hdr: PacketCCHeader))]
struct PayloadUnknown {
    #[br(count = hdr.payload_len)]
    data: Vec<u8>,
}

impl Payload for PayloadUnknown {
    fn len(&self) -> u32 {
        self.data.len() as u32
    }
}

impl<T: AsRef<[u8]>> From<T> for PayloadUnknown {
    fn from(d: T) -> Self {
        Self {
            data: d.as_ref().to_vec(),
        }
    }
}

#[derive(Clone, PartialEq)]
#[binrw]
#[br(big, import(hdr: PacketCCHeader))]
struct PayloadSdbDownload {
    continues: u32, // 0 if this is the last packet, 1 otherwise
    #[br(count = (hdr.payload_len - 4) as usize)]
    tail: Vec<u8>,
}

impl Payload for PayloadSdbDownload {
    fn len(&self) -> u32 {
        4 + self.tail.len() as u32
    }
}

impl Debug for PayloadSdbDownload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PayloadSdbDownload {{\n continues: {},\n{}\n}}",
            self.continues,
            hexdump(&self.tail[0..100])
        )
    }
}

fn query_fw_ver() -> PacketCC<PayloadUnknown> {
    let payload = PayloadUnknown::from([0x11]);
    PacketCC {
        hdr: PacketCCHeader {
            payload_len: payload.len() as u32,
            u64_8_f: 0,
            u32_10_13: 1,
            u16_14_15: 0,
            b16: 1,
            b17: 0x23,
        },
        payload,
    }
}

fn query_download_sdb() -> PacketCC {
    let payload = PayloadUnknown::from(b"1\0\0\x0eDOWNLOAD.SDB\0\0");
    PacketCC {
        hdr: PacketCCHeader {
            payload_len: payload.len() as u32,
            u64_8_f: 0,
            u32_10_13: 1,
            u16_14_15: 0,
            b16: 0x12,
            b17: 0x23,
        },
        payload,
    }
}

fn query_continue_download() -> PacketCC {
    let payload = PayloadUnknown::from([b'2']); // 0x32
    PacketCC {
        hdr: PacketCCHeader {
            payload_len: payload.len() as u32,
            u64_8_f: 0,
            u32_10_13: 1,
            u16_14_15: 0,
            b16: 0x01,
            b17: 0x23,
        },
        payload,
    }
}

fn send<P>(pkt: &P, stream: &mut TcpStream) -> Result<()>
where
    P: BinWrite,
    <P as BinWrite>::Args: Default,
{
    let mut buf = Vec::with_capacity(0);
    pkt.write_to(&mut Cursor::new(&mut buf))
        .context("Writing packet to send buffer.")?;
    // hex(&buf);
    stream
        .write_all(buf.as_slice())
        .context("Write to TCP stream failed.")
}

fn receive_response<P: Payload>(stream: &mut TcpStream) -> Result<PacketCC<P>> {
    let mut buf = vec![0; 24];
    stream.read_exact(buf.as_mut_slice())?;
    let hdr =
        PacketCCHeader::read(&mut Cursor::new(&buf)).context("Response header parse error")?;
    buf.resize(hdr.payload_len as usize + 24, 0);
    stream.read_exact(&mut buf[24..])?;
    // hex(&buf);
    Cursor::new(buf).read_be().context("Response parse error.")
}

fn connect() -> Result<TcpStream> {
    TcpStream::connect("192.168.1.51:1202").context("Failed to connect to PLC")
}

fn query(pkt: &PacketCC) -> Result<PacketCC> {
    let mut stream = TcpStream::connect("192.168.1.51:1202")?;
    send(pkt, &mut stream)?;
    receive_response(&mut stream)
}

fn download_sbd() -> Result<()> {
    let mut stream = &mut connect()?;
    send(&query_download_sdb(), stream)?;
    let mut r = receive_response::<PayloadSdbDownload>(stream)?;
    println!("{:?}", r);
    while r.payload.continues == 1 {
        send(&query_continue_download(), stream)?;
        r = receive_response(stream)?;
        println!("{:?}", r);
        break;
    }
    Ok(())
}

fn main() -> Result<()> {
    let pkt = query_download_sdb();
    // let pkt = query_fw_ver();
    // let r = query(&pkt)?;
    let r = download_sbd()?;
    println!("{:x?}", r);
    Ok(())
}
