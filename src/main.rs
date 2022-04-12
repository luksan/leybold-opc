#![allow(dead_code, unused_mut)]

mod opc_values;
mod packets;
mod sdb;

use anyhow::{bail, Context, Result};
use binrw::{io::Cursor, BinRead, BinReaderExt, BinWrite};
use rhexdump::hexdump;

use packets::{
    Bstr, PacketCC, PacketCCHeader, PayloadParamsResponse, PayloadSdbDownload, PayloadUnknown,
    ResponsePayload,
};

use opc_values::Value;
use packets::{ParamWrite, PayloadDynResponse, PayloadParamWrite, PayloadParamsQuery, QueryParam};
use sdb::{Parameter, TypeInfo, TypeKind};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Deref;
use std::time::Duration;

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

    fn receive_response<P: ResponsePayload>(&mut self) -> Result<PacketCC<P>> {
        self.receive_response_args(())
    }

    fn receive_response_args<P, Args>(&mut self, args: Args) -> Result<PacketCC<P>>
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

fn poll_pressure() -> Result<()> {
    let mut _cmd = PacketCC::new(PayloadUnknown::from(hex_literal::hex!(
         "2e 00 00 00 00 04" // the last 2 bytes is the number of parameters in the request
         "00 03 00 04 78 7c 00 00 00 15" // last 2 bytes is byte len of the response
         "00 03 00 04 78 78 00 00 00 04"
         "00 03 00 04 78 78 00 00 00 04"
         "00 03 00 04 78 7c 00 00 00 04"
         "00 02 53 34"
    )));

    let mut cmd = PacketCC::new(PayloadParamsQuery::new(&[
        QueryParam::new(0x4787c, 0x15),
        QueryParam::new(0x47878, 4),
        QueryParam::new(0x47878, 4),
        QueryParam::new(0x4787c, 4),
    ]));
    cmd.hdr.one_if_data_poll_maybe = 1;

    let mut last_timestamp = 0.0;
    let mut last_time = std::time::Instant::now();
    let mut conn = Connection::connect()?;
    conn.stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    loop {
        conn.send(&cmd)?;
        //     let r = conn.receive_response::<PayloadUnknown>()?;
        let r =
            conn.receive_response::<PayloadParamsResponse<(Bstr<0x15>, f32, f32, Bstr<0x04>)>>()?;
        let now = std::time::Instant::now();
        println!(
            "time delta {:.2} == {:.2} ms",
            (r.payload.timestamp.as_secs_f64() - last_timestamp) * 1000.0,
            now.duration_since(last_time).as_secs_f32() * 1000.0
        );
        last_time = now;
        last_timestamp = r.payload.timestamp.as_secs_f64();
        println!("{:x?}", r.payload);
        conn.send_66_ack()?;
    }
}

#[derive(Debug, Default, Clone)]
struct ParamQuerySet<'a>(Vec<Parameter<'a>>);

impl<'a> ParamQuerySet<'a> {
    pub fn add_param(&mut self, param: Parameter<'a>) {
        self.0.push(param);
    }

    pub fn create_query_packet(&self) -> PacketCC<PayloadParamsQuery> {
        let params: Vec<_> = self
            .0
            .iter()
            .map(|p| QueryParam::new(p.id(), p.type_info().response_len() as u32))
            .collect();
        let mut p = PacketCC::new(PayloadParamsQuery::new(params.as_slice()));
        p.hdr.one_if_data_poll_maybe = 1;
        p
    }

    pub fn response_param_len(&self) -> Vec<usize> {
        self.0
            .iter()
            .map(|p| p.type_info().response_len())
            .collect()
    }

    pub fn parse_response(&self, bytes: &Vec<Vec<u8>>) -> Result<Vec<Value>> {
        let ret = self
            .0
            .iter()
            .zip(bytes.iter())
            .map(|(param, bytes)| {
                Value::parse(bytes, &param.type_info())
                    .with_context(|| format!("Parsing {:?}\n{}", param, hexdump(bytes)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ret)
    }
}

fn read_dyn_params() -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let mut param_set = ParamQuerySet::default();
    param_set.add_param(sdb.param_by_name(".CockpitUser")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].StringValue")?);

    let mut conn = Connection::connect()?;
    conn.stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    conn.send(&param_set.create_query_packet())?;
    let r = conn.receive_response_args::<PayloadDynResponse, _>(param_set.response_param_len());
    conn.send_66_ack()?;

    let r = r?;
    let resp = param_set.parse_response(&r.payload.data)?;
    for (r, p) in resp.iter().zip(param_set.0.iter()) {
        println!("{} {:?}", p.name(), r);
    }
    println!("Tail data: '{}'", hexdump(&r.tail));
    Ok(())
}

fn write_param() -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let param = sdb.param_by_name(".CockpitUser")?;

    let packet = PacketCC::new(PayloadParamWrite::new(&[ParamWrite::new(
        param,
        b"User1234",
    )?]));
    let mut conn = Connection::connect()?;
    conn.stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    conn.send(&packet)?;
    let r = conn.receive_response::<PayloadUnknown>();
    conn.send_66_ack()?;
    println!("{r:?}");
    r?;
    Ok(())
}

fn main() -> Result<()> {
    // let pkt = query_download_sdb();
    // let pkt = query_fw_ver();
    // let r = query(&pkt)?;
    // let r = download_sbd()?;
    // println!("{:x?}", r);

    // sdb::print_sdb_file()?;
    //poll_pressure()?;
    // read_dyn_params()?;

    write_param()?;
    read_dyn_params()?;
    Ok(())
}
