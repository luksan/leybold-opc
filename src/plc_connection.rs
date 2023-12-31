use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use binrw::{BinRead, BinReaderExt, BinWrite};
use tracing::debug;

use crate::packets::cc_payloads::*;
use crate::packets::{PacketCC, PacketCCHeader, QueryPacket};

pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    pub fn connect(ip: IpAddr) -> anyhow::Result<Self> {
        debug!("Connecting to PLC at {}:1202", ip);
        let stream = TcpStream::connect_timeout(&(ip, 1202).into(), Duration::from_secs(1))
            .context("Failed to connect to PLC")?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        Ok(Self { stream })
    }

    pub fn query<'a, Cmd>(&mut self, pkt: &PacketCC<Cmd>) -> Result<PacketCC<'a, Cmd::Response<'a>>>
    where
        Cmd: QueryPacket<'a> + BinWrite<Args<'a> = ()>,
        PacketCC<'a, Cmd::Response<'a>>: BinRead,
        <PacketCC<'a, <Cmd as QueryPacket<'a>>::Response<'a>> as BinRead>::Args<'a>: Clone,
    {
        self.send(pkt)?;
        let args = pkt.payload.get_response_read_arg();
        let r = self.receive_response_args(args);
        self.send_66_ack()?;
        r
    }

    fn send<'a, P>(&mut self, pkt: &P) -> anyhow::Result<()>
    where
        P: BinWrite,
        <P as BinWrite>::Args<'a>: Default,
        for<'b> <P as BinWrite>::Args<'b>: binrw::__private::Required,
    {
        let mut buf = Vec::with_capacity(0);
        pkt.write_be(&mut Cursor::new(&mut buf))
            .context("Writing packet to send buffer.")?;
        // hex(&buf);
        self.stream
            .write_all(buf.as_slice())
            .context("Write to TCP stream failed.")
    }

    fn receive_response_args<'a, P: 'a, Args>(
        &mut self,
        args: Args,
    ) -> anyhow::Result<PacketCC<'a, P>>
    where
        PacketCC<'a, P>: BinRead<Args<'a> = Args>,
        Args: Clone,
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

pub fn download_sbd(conn: &mut Connection) -> anyhow::Result<()> {
    let sdb_info = conn.query(&SdbVersionQuery::pkt())?;
    let sdb_len = sdb_info.payload.sbd_size as usize;

    let mut sdb_file = std::fs::File::create("sdb_new.dat")?;
    let mut pkt_cnt = 0;
    let mut r = conn.query(&SdbDownloadRequest::pkt())?;
    let tot_est = (sdb_len / r.payload.pkt_sdb_part_len as usize) + 1;
    loop {
        sdb_file.write_all(r.payload.sdb_part.as_slice())?;

        pkt_cnt += 1;
        conn.send_66_ack()?;

        if pkt_cnt > tot_est * 2 {
            bail!("Received more than twice the amount of expected sdb download packets.")
        }
        println!("Pkt cnt {pkt_cnt} / {tot_est}.");
        if !r.payload.continues {
            println!("Download complete.");
            break;
        }
        r = conn.query(&SdbDownloadContinue::pkt())?;
    }
    conn.send_66_ack()?;
    Ok(())
}
