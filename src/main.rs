#![allow(dead_code, unused_mut)]

use anyhow::Result;
use clap::{
    Arg, ArgMatches, Args, Command, CommandFactory, Error, ErrorKind as ClapError, FromArgMatches,
    Parser, Subcommand,
};
use rhexdump::hexdump;

use leybold_opc_rs::packets::{PacketCC, ParamQuerySetBuilder, ParamWrite, PayloadParamWrite};
use leybold_opc_rs::{plc_connection, sdb};

use leybold_opc_rs::plc_connection::Connection;
use std::net::IpAddr;
use std::ops::Deref;

fn hex<H: Deref<Target = [u8]>>(hex: &H) {
    println!("{}", hexdump(hex.as_ref()));
}

fn poll_pressure(conn: &mut Connection) -> Result<()> {
    let mut param_set = ParamQuerySetBuilder::default();
    let sdb = sdb::read_sdb_file()?;
    param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);

    let param_set = param_set.complete();

    let mut last_timestamp = 0.0;
    let mut last_time = std::time::Instant::now();

    let pkt = param_set.create_query_packet();
    loop {
        let r = conn.query_response_args(&pkt, param_set.clone())?;
        let now = std::time::Instant::now();
        println!(
            "time delta {:.2} == {:.2} ms",
            (r.payload.timestamp.as_secs_f64() - last_timestamp) * 1000.0,
            now.duration_since(last_time).as_secs_f32() * 1000.0
        );
        last_time = now;
        last_timestamp = r.payload.timestamp.as_secs_f64();
        let response = &r.payload.data;
        println!("Pressure {response:x?} mbar.");
    }
}

fn read_dyn_params(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let mut param_set = ParamQuerySetBuilder::default();
    param_set.add_param(sdb.param_by_name(".CockpitUser")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].StringValue")?);

    let param_set = param_set.complete();

    let r = conn.query_response_args(&param_set.create_query_packet(), param_set.clone())?;

    let resp = &r.payload.data;
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
    let r = conn.query(&packet)?;
    println!("{r:?}");
    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author = "Lukas Sandström", version, about)]
struct CmdlineArgs {
    /// The IP address of the Vacvision unit.
    #[clap(global = true, long = "ip")]
    ip: Option<IpAddr>,
    #[clap(flatten)]
    readwrite: RwCmds,
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    PollPressure,
    SdbDownload,
    SdbPrint,
    Test,
}

#[derive(Debug)]
enum Rw {
    Read(String),
    Write(String),
}
#[derive(Debug)]
struct RwCmds(Vec<Rw>);

impl Deref for RwCmds {
    type Target = [Rw];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Args for RwCmds {
    fn augment_args(cmd: Command<'_>) -> Command<'_> {
        let read = Arg::new("read")
            .short('r')
            .help("Read the parameter from the instrument")
            .takes_value(true)
            .multiple_occurrences(true)
            .requires("ip")
            .display_order(10);
        let write = read
            .clone()
            .id("write")
            .short('w')
            .help("Write the given value to the parameter on the instrument.");
        cmd.arg(read).arg(write)
    }

    fn augment_args_for_update(_cmd: Command<'_>) -> Command<'_> {
        todo!()
    }
}
impl FromArgMatches for RwCmds {
    fn from_arg_matches(matches: &ArgMatches) -> std::result::Result<Self, Error> {
        let mut s = Self(vec![]);
        s.update_from_arg_matches(matches)?;
        Ok(s)
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> std::result::Result<(), Error> {
        let mut args: Vec<_> = matches
            .indices_of("read")
            .map(|read| {
                read.zip(
                    matches
                        .values_of("read")
                        .unwrap()
                        .map(|param| Rw::Read(param.to_string())),
                )
                .collect()
            })
            .unwrap_or_default();
        if let Some(write) = matches.indices_of("write") {
            args.extend(
                write.zip(
                    matches
                        .values_of("write")
                        .unwrap()
                        .map(|param| Rw::Write(param.to_string())),
                ),
            );
        }

        args.sort_unstable_by_key(|a| a.0);
        self.0.extend(args.into_iter().map(|a| a.1));
        Ok(())
    }
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
    if let Some(command) = &args.command {
        return match command {
            Commands::PollPressure => poll_pressure(connect!()),
            Commands::SdbDownload => plc_connection::download_sbd(connect!()),
            Commands::SdbPrint => sdb::print_sdb_file(),
            Commands::Test => {
                let conn = connect!();
                write_param(conn)?;
                read_dyn_params(conn)
            }
        };
    }
    if args.readwrite.is_empty() {
        return Ok(());
    }
    Ok(())
}
