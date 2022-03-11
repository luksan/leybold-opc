#![allow(dead_code)]

mod packets;

use anyhow::{bail, Context, Result};
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

struct Connection {
    stream: TcpStream,
}

impl Connection {
    fn connect() -> Result<Self> {
        let stream = TcpStream::connect("192.168.1.51:1202").context("Failed to connect to PLC")?;
        Ok(Self { stream })
    }

    fn send<P>(&mut self, pkt: &P) -> Result<()>
    where
        P: BinWrite,
        <P as BinWrite>::Args: Default,
    {
        let mut buf = Vec::with_capacity(0);
        pkt.write_to(&mut Cursor::new(&mut buf))
            .context("Writing packet to send buffer.")?;
        // hex(&buf);
        self.stream
            .write_all(buf.as_slice())
            .context("Write to TCP stream failed.")
    }

    fn receive_response<P: Payload>(&mut self) -> Result<PacketCC<P>> {
        let mut buf = vec![0; 24];
        self.stream.read_exact(buf.as_mut_slice())?;
        let hdr =
            PacketCCHeader::read(&mut Cursor::new(&buf)).context("Response header parse error")?;
        buf.resize(hdr.payload_len as usize + 24, 0);
        self.stream.read_exact(&mut buf[24..])?;
        // hex(&buf);
        Cursor::new(buf).read_be().context("Response parse error.")
    }

    fn send_66_ack(&mut self) -> Result<()> {
        self.stream.write_all(
            hex_literal::hex!(
                "66 66 00 01 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 01 02 00 00 04"
            )
            .as_slice(),
        )?;
        let mut rbuf = [0; 24];
        self.stream
            .read_exact(&mut rbuf)
            .context("Reading 66 ack response")?;
        if rbuf
            != hex_literal::hex!(
                "66 66 00 00 00 00 00 00  00 00 00 00 00 00 00 19  00 00 00 00 00 00 00 04"
            )
            .as_slice()
        {
            // bail!("Unexpected 66 ack response {:x?}", rbuf);
        }
        Ok(())
    }
}

fn query(pkt: &PacketCC) -> Result<PacketCC> {
    let mut conn = Connection::connect()?;
    conn.send(pkt)?;
    conn.receive_response()
}

fn download_sbd() -> Result<()> {
    let mut conn = Connection::connect()?;
    let mut sdb_file = std::fs::File::create("sdb_new.dat")?;
    let mut pkt_cnt = 0;
    conn.send(&query_download_sdb())?;
    loop {
        let r = conn.receive_response::<PayloadSdbDownload>()?;
        sdb_file.write_all(r.payload.sdb_part.as_slice())?;

        pkt_cnt += 1;
        conn.send_66_ack()?;

        if pkt_cnt > 1000 {
            bail!("Received more than 1000 packets.")
        }
        println!("Pkt cnt {pkt_cnt} / 838.");
        if r.payload.continues != 1 {
            break;
        }
        conn.send(&query_continue_download())?;
    }
    conn.send_66_ack()?;
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
