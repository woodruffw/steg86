use anyhow::Result;
use clap::{App, AppSettings, Arg};

use std::process;

mod steg86;

fn run() -> Result<()> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            App::new("profile")
                .about("profile a binary for steganographic storage capacity")
                // TODO(ww): --json flag.
                .arg(
                    Arg::with_name("input")
                        .about("the binary to profile")
                        .index(1)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("embed")
                .about("embed some data into a binary steganographically")
                .arg(
                    Arg::with_name("input")
                        .about("the binary to embed into")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("output")
                        .about("the path to write the steg'd binary to")
                        .index(2)
                        .required(false),
                ),
        )
        .subcommand(
            App::new("extract")
                .about("extract the hidden data from a binary")
                .arg(
                    Arg::with_name("input")
                        .about("the binary to extract from")
                        .index(1)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("profile", Some(matches)) => steg86::command::profile(&matches),
        ("embed", Some(matches)) => steg86::command::embed(&matches),
        ("extract", Some(matches)) => steg86::command::extract(&matches),
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
