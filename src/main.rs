#![allow(dead_code, unused_mut)]

use anyhow::{bail, Context, Result};
use binrw::{io::Cursor, BinRead, BinReaderExt, BinWrite};
use clap::{CommandFactory, ErrorKind as ClapError, Parser, Subcommand};
use rhexdump::hexdump;

use leybold_opc_rs::opc_values::Value;
use leybold_opc_rs::packets::{
    PacketCC, PacketCCHeader, ParamRead, ParamWrite, PayloadDynResponse, PayloadParamWrite,
    PayloadParamsRead, PayloadSdbDownload, PayloadSdbVersionQuery, PayloadSdbVersionResponse,
    PayloadUnknown,
};
use leybold_opc_rs::sdb::{self, Parameter};

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
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
    pub fn connect(ip: IpAddr) -> Result<Self> {
        let stream = TcpStream::connect((ip, 1202)).context("Failed to connect to PLC")?;
        Ok(Self { stream })
    }

    pub fn query(&mut self, pkt: &PacketCC) -> Result<PacketCC> {
        self.send(pkt)?;
        let r = self.receive_response();
        self.send_66_ack()?;
        r
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

    fn receive_response<P>(&mut self) -> Result<PacketCC<P>>
    where
        PacketCC<P>: BinRead<Args = ()>,
    {
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

fn download_sbd(conn: &mut Connection) -> Result<()> {
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

fn check_sdb(conn: &mut Connection) -> Result<()> {
    conn.send(&PacketCC::new(PayloadSdbVersionQuery::new()))?;
    let r = conn.receive_response::<PayloadSdbVersionResponse>()?;
    conn.send_66_ack()?;
    println!("{r:?}\n{}", hexdump(&r.tail));

    Ok(())
}

fn poll_pressure(conn: &mut Connection) -> Result<()> {
    let mut param_set = ParamQuerySet::default();
    let sdb = sdb::read_sdb_file()?;
    param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);

    let mut last_timestamp = 0.0;
    let mut last_time = std::time::Instant::now();
    conn.stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    let pkt = param_set.create_query_packet();
    loop {
        conn.send(&pkt)?;
        let r =
            conn.receive_response_args::<PayloadDynResponse, _>(param_set.response_param_len())?;
        let now = std::time::Instant::now();
        println!(
            "time delta {:.2} == {:.2} ms",
            (r.payload.timestamp.as_secs_f64() - last_timestamp) * 1000.0,
            now.duration_since(last_time).as_secs_f32() * 1000.0
        );
        last_time = now;
        last_timestamp = r.payload.timestamp.as_secs_f64();
        let response = param_set.parse_response(&r.payload.data)?;
        println!("Pressure {response:x?} mbar.");
        conn.send_66_ack()?;
    }
}
#[derive(Debug, Default, Clone)]
struct ParamQuerySet<'a>(Vec<Parameter<'a>>);

impl<'a> ParamQuerySet<'a> {
    pub fn add_param(&mut self, param: Parameter<'a>) {
        self.0.push(param);
    }

    pub fn create_query_packet(&self) -> PacketCC<PayloadParamsRead> {
        let params: Vec<_> = self
            .0
            .iter()
            .map(|p| ParamRead::new(p.id(), p.type_info().response_len() as u32))
            .collect();
        let mut p = PacketCC::new(PayloadParamsRead::new(params.as_slice()));
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

fn read_dyn_params(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let mut param_set = ParamQuerySet::default();
    param_set.add_param(sdb.param_by_name(".CockpitUser")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].StringValue")?);

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

fn write_param(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let param = sdb.param_by_name(".CockpitUser")?;

    let packet = PacketCC::new(PayloadParamWrite::new(&[ParamWrite::new(
        param,
        b"User1234",
    )?]));
    conn.stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    conn.send(&packet)?;
    let r = conn.receive_response::<PayloadUnknown>();
    conn.send_66_ack()?;
    println!("{r:?}");
    r?;
    Ok(())
}

#[derive(Parser)]
#[clap(author = "Lukas Sandström", version, about)]
struct CmdlineArgs {
    /// The IP address of the Vacvision unit.
    ip: Option<IpAddr>,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    PollPressure,
    SdbDownload,
    SdbPrint,
    Test,
}

fn main() -> Result<()> {
    let args: CmdlineArgs = Parser::parse();

    let conn: &mut _ = &mut None;
    macro_rules! connect {
        () => {{
            let ip = args.ip.unwrap_or_else(|| {
                CmdlineArgs::command()
                    .error(ClapError::ArgumentNotFound, "Missing IP address.")
                    .exit()
            });
            *conn = Some(Connection::connect(ip).expect("Connection failed"));
            conn.as_mut().unwrap()
        }};
    }

    match &args.command {
        Commands::PollPressure => poll_pressure(connect!()),
        Commands::SdbDownload => download_sbd(connect!()),
        Commands::SdbPrint => sdb::print_sdb_file(),
        Commands::Test => {
            let conn = connect!();
            write_param(conn)?;
            read_dyn_params(conn)
        }
    }
}
