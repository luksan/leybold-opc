use crate::packets::{
    PacketCC, PacketCCHeader, PayloadSdbDownload, PayloadSdbVersionQuery,
    PayloadSdbVersionResponse, PayloadUnknown, QueryPacket,
};

use anyhow::{bail, Context, Result};
use binrw::{BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;

use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    pub fn connect(ip: IpAddr) -> anyhow::Result<Self> {
        let stream = TcpStream::connect((ip, 1202)).context("Failed to connect to PLC")?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        Ok(Self { stream })
    }

    pub fn query<Cmd>(&mut self, pkt: &PacketCC<Cmd>) -> Result<PacketCC<Cmd::Response>>
    where
        Cmd: QueryPacket,
        PacketCC<Cmd::Response>: BinRead<Args = ()>,
    {
        self.send(pkt)?;
        let r = self.receive_response();
        self.send_66_ack()?;
        r
    }

    pub fn query_response_args<Cmd, Args>(
        &mut self,
        pkt: &PacketCC<Cmd>,
        response_args: Args,
    ) -> Result<PacketCC<Cmd::Response>>
    where
        Cmd: QueryPacket,
        PacketCC<Cmd::Response>: BinRead<Args = Args>,
    {
        self.send(pkt)?;
        let r = self.receive_response_args(response_args);
        self.send_66_ack()?;
        r
    }

    fn send<P>(&mut self, pkt: &P) -> anyhow::Result<()>
    where
        P: BinWrite,
        <P as BinWrite>::Args: Default,
    {
        let mut buf = Vec::with_capacity(0);
        pkt.write_be(&mut Cursor::new(&mut buf))
            .context("Writing packet to send buffer.")?;
        // hex(&buf);
        self.stream
            .write_all(buf.as_slice())
            .context("Write to TCP stream failed.")
    }

    fn receive_response<P>(&mut self) -> anyhow::Result<PacketCC<P>>
    where
        PacketCC<P>: BinRead<Args = ()>,
    {
        self.receive_response_args(())
    }

    fn receive_response_args<P, Args>(&mut self, args: Args) -> anyhow::Result<PacketCC<P>>
    where
        PacketCC<P>: BinRead<Args = Args>,
    {
        let mut buf = vec![0; 24];
        self.stream.read_exact(buf.as_mut_slice())?;
        let hdr =
            PacketCCHeader::read(&mut Cursor::new(&buf)).context("Response header parse error")?;
        buf.resize(hdr.payload_len as usize + 24, 0);
        self.stream.read_exact(&mut buf[24..])?;
        // hex(&buf);
        Cursor::new(buf)
            .read_be_args(args)
            .context("Response parse error.")
    }

    fn send_66_ack(&mut self) -> anyhow::Result<()> {
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

fn _query_fw_ver() -> PacketCC<PayloadUnknown> {
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

pub fn download_sbd(conn: &mut Connection) -> anyhow::Result<()> {
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
        if r.payload.continues {
            break;
        }
        conn.send(&query_continue_download())?;
    }
    conn.send_66_ack()?;
    Ok(())
}

fn _check_sdb(conn: &mut Connection) -> anyhow::Result<()> {
    conn.send(&PacketCC::new(PayloadSdbVersionQuery::new()))?;
    let r = conn.receive_response::<PayloadSdbVersionResponse>()?;
    conn.send_66_ack()?;
    println!("{r:?}\n{}", hexdump(&r.tail));

    Ok(())
}
