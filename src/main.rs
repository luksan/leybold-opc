#![allow(dead_code)]

mod packets;
mod sdb;

use anyhow::{bail, Context, Result};
use binrw::{binrw, io::Cursor, BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;

use crate::packets::PayloadParamsResponse;
use packets::{PacketCC, PacketCCHeader, Payload, PayloadSdbDownload, PayloadUnknown};
use std::io::{BufRead, Read, Seek, Write};
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

fn print_sdb_file() -> Result<()> {
    use sdb::Entry;

    let mut file = std::io::BufReader::new(std::fs::File::open("sdb.dat")?);
    let mut entries = vec![];
    loop {
        match Entry::read(&mut file) {
            Ok(e) => {
                //    if let Entry::Parameter(e) = e {
                entries.push(e);
                //      }
                if file.fill_buf()?.is_empty() {
                    break;
                }
            }
            Err(e) => {
                let x: i32 = file.read_le()?;
                Err(e).with_context(|| {
                    format!("u32 at {:x} {:4}", file.stream_position().unwrap(), x)
                })?;
            }
        }
    }
    println!("{} entries in SDB.", entries.len());
    // entries.sort_by_key(|e| e.value_type);
    // entries.dedup_by_key(|e| e.value_type);

    for e in entries.iter() {
        // dbg!(e);
        if let Entry::Parameter(ref p) = e {
            if p.value_type == sdb::ValueType::UI1Array {
                //if p.name.as_str()?.starts_with(".Gauge[1].Parameter[1]") {
                println!("{:?}", e);
            }
        }
    }
    Ok(())
}

fn poll_pressure() -> Result<()> {
    let mut cmd = PacketCC::new(PayloadUnknown::from(hex_literal::hex!(
         "2e 00 00 00 00 04" // the last byte is the number of parameters in the request
         "00 03 00 04 78 7c 00 00 00 15" // last byte is byte len of the response
         "00 03 00 04 78 78 00 00 00 04"
         "00 03 00 04 78 78 00 00 00 04"
         "00 03 00 04 78 7c 00 00 01 04"
         "00 02 53 34"
    )));
    cmd.hdr.one_if_data_poll_maybe = 1;

    let mut last_timestamp = 0;
    let mut last_time = std::time::Instant::now();
    let mut conn = Connection::connect()?;
    loop {
        conn.send(&cmd)?;
        //     let r = conn.receive_response::<PayloadUnknown>()?;
        let r = conn.receive_response::<PayloadParamsResponse>()?;
        let now = std::time::Instant::now();
        println!(
            "time delta {} == {} ms",
            r.payload.timestamp_ms - last_timestamp,
            now.duration_since(last_time).as_secs_f32() * 1000.0
        );
        last_time = now;
        last_timestamp = r.payload.timestamp_ms;
        println!("{:x?}", r.payload);
        conn.send_66_ack()?;
    }
    Ok(())
}

fn main() -> Result<()> {
    // let pkt = query_download_sdb();
    // let pkt = query_fw_ver();
    // let r = query(&pkt)?;
    // let r = download_sbd()?;
    // println!("{:x?}", r);

    print_sdb_file()?;
    // poll_pressure()?;
    Ok(())
}
