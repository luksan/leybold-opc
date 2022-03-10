#![allow(dead_code)]

mod packets;

use anyhow::{Context, Result};
use binrw::{binrw, io::Cursor, BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;

use packets::{PacketCC, PacketCCHeader, Payload, PayloadSdbDownload, PayloadUnknown};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Deref;

fn hex<H: Deref<Target = [u8]>>(hex: &H) {
    println!("{}", hexdump(hex.as_ref()));
}

fn query_fw_ver() -> PacketCC<PayloadUnknown> {
    let payload = PayloadUnknown::from([0x11]);
    PacketCC::new(payload)
}

fn query_download_sdb() -> PacketCC {
    let payload = PayloadUnknown::from(b"1\0\0\x0eDOWNLOAD.SDB\0\0");
    PacketCC::new(payload)
}

fn query_continue_download() -> PacketCC {
    let payload = PayloadUnknown::from([b'2']); // 0x32
    PacketCC::new(payload)
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
    let stream = &mut connect()?;
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
    // let pkt = query_download_sdb();
    // let pkt = query_fw_ver();
    // let r = query(&pkt)?;
    let r = download_sbd()?;
    println!("{:x?}", r);
    Ok(())
}
