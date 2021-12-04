use std::process;

use anyhow::Result;
use clap::{App, AppSettings, Arg};

mod steg86;

fn run() -> Result<()> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            App::new("profile")
                .about("profile a binary for steganographic storage capacity")
                // TODO(ww): --json flag.
                .arg(
                    Arg::new("raw")
                        .about("treat the input as a raw binary")
                        .long("raw")
                        .short('r'),
                )
                .arg(
                    Arg::new("bitness")
                        .about("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .takes_value(true)
                        .possible_values(&["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .about("the binary to profile")
                        .index(1)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("embed")
                .about("embed some data into a binary steganographically")
                .arg(
                    Arg::new("raw")
                        .about("treat the input as a raw binary")
                        .long("raw")
                        .short('r'),
                )
                .arg(
                    Arg::new("bitness")
                        .about("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .takes_value(true)
                        .possible_values(&["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .about("the binary to embed into")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .about("the path to write the steg'd binary to")
                        .index(2)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("extract")
                .about("extract the hidden data from a binary")
                .arg(
                    Arg::new("raw")
                        .about("treat the input as a raw binary")
                        .long("raw")
                        .short('r'),
                )
                .arg(
                    Arg::new("bitness")
                        .about("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .takes_value(true)
                        .possible_values(&["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .about("the binary to extract from")
                        .index(1)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("profile", matches)) => steg86::command::profile(matches),
        Some(("embed", matches)) => steg86::command::embed(matches),
        Some(("extract", matches)) => steg86::command::extract(matches),
        _ => unreachable!(),
    }
}

fn main() {
    env_logger::init();

    process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Fatal: {}", e);
            1
        }
    });
}
