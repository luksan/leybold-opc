#![allow(dead_code, unused_mut)]

use anyhow::{Context, Result};
use clap::{
    error::ErrorKind as ClapError, Arg, ArgAction, ArgMatches, Args, Command, CommandFactory,
    FromArgMatches, Parser, Subcommand,
};
use rhexdump::hexdump;
use serde::ser::*;

use leybold_opc_rs::opc_values::Value;
use leybold_opc_rs::packets::{PacketCC, ParamQuerySetBuilder, ParamWrite, PayloadParamWrite};
use leybold_opc_rs::plc_connection::{self, Connection};
use leybold_opc_rs::sdb;

use std::net::IpAddr;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

fn hex<H: Deref<Target = [u8]>>(hex: &H) {
    println!("{}", hexdump(hex.as_ref()));
}

fn poll_pressure(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let mut param_set = ParamQuerySetBuilder::new(&sdb);
    param_set.add(".Gauge[1].Parameter[1].Value")?;

    let mut last_timestamp = 0.0;
    let mut last_time = std::time::Instant::now();

    let pkt = param_set.into_query_packet();
    loop {
        let r = conn.query(&pkt)?;
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
    let mut param_set = ParamQuerySetBuilder::new(&sdb);
    param_set.add(".CockpitUser")?;
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].Value")?);
    // param_set.add_param(sdb.param_by_name(".Gauge[1].Parameter[1].StringValue")?);

    let r = conn.query(&param_set.into_query_packet())?;

    let resp_values = &r.payload.data;
    let param_set = &r.payload.query_set.0;
    for (r, p) in resp_values.iter().zip(param_set.iter()) {
        println!("{} {:?}", p.name(), r);
    }
    println!("Tail data: '{}'", hexdump(&r.tail));
    Ok(())
}

fn write_param(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let param = sdb.param_by_name(".CockpitUser")?;

    let packet = PacketCC::new(PayloadParamWrite::new(
        &sdb,
        &[ParamWrite::new(&param, b"User1234")?],
    ));
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
    readwrite: RwCmds<String, String>,
    /// Read out the values continuously
    #[clap(long, value_name = "SECONDS")]
    poll: Option<f32>,
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    CmdlineArgs::command().debug_assert();
}

#[derive(Subcommand, Debug)]
enum Commands {
    PollPressure,
    SdbDownload,
    SdbPrint,
    ReadAllParams,
    Test,
}

#[derive(Debug)]
enum Rw<Param, Value> {
    Read(Param),
    Write(Param, Value),
}
#[derive(Debug)]
struct RwCmds<Param, Value>(Vec<Rw<Param, Value>>);

impl<Param, Value> Deref for RwCmds<Param, Value> {
    type Target = [Rw<Param, Value>];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl RwCmds<String, String> {
    pub fn try_to_param_value<'sdb>(
        &self,
        sdb: &'sdb sdb::Sdb,
    ) -> Result<RwCmds<sdb::Parameter<'sdb>, Value>> {
        let inner: Result<Vec<_>> = self
            .0
            .iter()
            .map(|rw| match rw {
                Rw::Read(param) => Ok(Rw::Read(sdb.param_by_name(param)?)),
                Rw::Write(param, value) => {
                    let param = sdb.param_by_name(param)?;
                    let value = param.value_from_str(value).with_context(|| {
                        format!(
                            "Failed to parse '{}' as valid value for {}.",
                            value,
                            param.name()
                        )
                    })?;
                    Ok(Rw::Write(param, value))
                }
            })
            .collect();
        Ok(RwCmds(inner?))
    }
}

impl Args for RwCmds<String, String> {
    fn augment_args(cmd: Command) -> Command {
        let read = Arg::new("read")
            .short('r')
            .help("Read the parameter from the instrument")
            .action(ArgAction::Append)
            .requires("ip")
            .display_order(10);
        let write = read
            .clone()
            .id("write")
            .short('w')
            .action(ArgAction::Append)
            .help("Write the given value to the parameter on the instrument.");
        cmd.arg(read).arg(write)
    }

    fn augment_args_for_update(_cmd: Command) -> Command {
        todo!()
    }
}
impl FromArgMatches for RwCmds<String, String> {
    fn from_arg_matches(matches: &ArgMatches) -> std::result::Result<Self, clap::Error> {
        let mut s = Self(vec![]);
        s.update_from_arg_matches(matches)?;
        Ok(s)
    }

    fn update_from_arg_matches(
        &mut self,
        matches: &ArgMatches,
    ) -> std::result::Result<(), clap::Error> {
        let mut args: Vec<(usize, Rw<String, String>)> = matches
            .indices_of("read")
            .map(|read| {
                read.zip(
                    matches
                        .get_many::<String>("read")
                        .unwrap()
                        .map(|param| Rw::Read(param.to_string())),
                )
                .collect()
            })
            .unwrap_or_default();
        if let Some(write) = matches.indices_of("write") {
            for (idx, arg) in write.zip(matches.get_many::<String>("write").unwrap()) {
                let (param, val) = arg.split_once('=').ok_or_else(|| {
                    clap::Error::raw(
                        ClapError::InvalidValue,
                        "Invalid write argument, should be 'param=value'.",
                    )
                })?;
                args.push((idx, Rw::Write(param.to_string(), val.to_string())));
            }
        }

        args.sort_unstable_by_key(|a| a.0);
        self.0.extend(args.into_iter().map(|a| a.1));
        Ok(())
    }
}

static CTRL_C_PRESSED: AtomicBool = AtomicBool::new(false);

fn cmd_read_all(conn: &mut Connection) -> Result<()> {
    let sdb = sdb::read_sdb_file()?;
    let mut params = ParamQuerySetBuilder::new(&sdb);
    let mut tot_response_len = 0;
    let mut serializer = serde_json::Serializer::pretty(std::io::stdout());
    let mut json_map = serializer.serialize_map(None)?;
    for param in sdb.parameters() {
        tot_response_len += param.type_info().response_len();
        params.add_param(param);
        if tot_response_len < 0x300 {
            continue;
        }

        let r = conn.query(&params.into_query_packet())?;

        for (param, value) in r.payload.iter() {
            json_map.serialize_key(param.name())?;
            json_map.serialize_value(value)?;
        }

        params = ParamQuerySetBuilder::new(&sdb);
        tot_response_len = 0;
    }
    SerializeMap::end(json_map)?;
    println!(); // newline after json output
    Ok(())
}

fn test_cmd(connect: impl FnOnce() -> Result<Connection>) -> Result<()> {
    // let _conn = &mut connect()?;
    sdb::read_sdb_file()?;

    // let pkt = PacketCC::new(SdbVersionQuery::new());
    // let r = conn.query(&pkt)?;
    // println!("{:#?}\n{}", r, hexdump(r.payload.data.as_slice()));

    // write_param(conn)?;
    // read_dyn_params(conn)

    Ok(())
}

fn main() -> Result<()> {
    let args: CmdlineArgs = Parser::parse();

    let connect = || {
        let ip = args.ip.unwrap_or_else(|| {
            CmdlineArgs::command()
                .error(ClapError::MissingRequiredArgument, "Missing IP address.")
                .exit()
        });
        Connection::connect(ip)
    };

    if let Some(command) = &args.command {
        return match command {
            Commands::PollPressure => poll_pressure(&mut connect()?),
            Commands::SdbDownload => plc_connection::download_sbd(&mut connect()?),
            Commands::SdbPrint => sdb::print_sdb_file(),
            Commands::ReadAllParams => cmd_read_all(&mut connect()?),
            Commands::Test => test_cmd(connect),
        };
    }
    if args.readwrite.is_empty() {
        return Ok(());
    }
    let sdb = sdb::read_sdb_file()?;
    let readwrite = args.readwrite.try_to_param_value(&sdb)?;

    // install signal handler for ctrl-c
    ctrlc::set_handler(|| {
        let again = CTRL_C_PRESSED.fetch_or(true, SeqCst);
        if again {
            std::process::exit(1);
        }
    })
    .context("Failed to set signal handler.")?;

    let mut conn = connect()?;

    loop {
        // Poll loop
        execute_queries(&sdb, &readwrite, &mut conn)?;

        if CTRL_C_PRESSED.load(SeqCst) {
            break;
        }

        if let Some(delay) = args.poll {
            let d = std::time::Duration::from_secs_f32(delay);
            std::thread::park_timeout(d);
        } else {
            break;
        }
    }
    Ok(())
}

fn execute_queries(
    sdb: &sdb::Sdb,
    readwrite: &RwCmds<sdb::Parameter, Value>,
    conn: &mut Connection,
) -> Result<()> {
    let mut parm_iter = readwrite.iter();
    let mut query_builder = ParamQuerySetBuilder::new(sdb);
    loop {
        if CTRL_C_PRESSED.load(SeqCst) {
            break;
        }
        let param = parm_iter.next();
        // build read set
        if let Some(Rw::Read(param)) = param {
            query_builder.add_param(param.clone());
            continue; // Batch consecutive parameter reads into one read request.
        }
        // perform read query
        if !query_builder.is_empty() {
            let packet = query_builder.into_query_packet();
            let r = conn.query(&packet)?;
            for (param, value) in r.payload.iter() {
                println!("{}: {value:?}", param.name());
            }
            query_builder = ParamQuerySetBuilder::new(sdb);
        }

        if CTRL_C_PRESSED.load(SeqCst) {
            break;
        }

        // perform write
        if let Some(Rw::Write(param, value)) = param {
            let x = ParamWrite::new(param, value)?;
            let r = conn.query(&PacketCC::new(PayloadParamWrite::new(sdb, &[x])))?;
            dbg!(r);
        }
        // repeat until iterator empty
        if param.is_none() {
            break;
        }
    }
    Ok(())
}
