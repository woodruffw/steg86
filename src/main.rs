use std::process;

use anyhow::Result;
use clap::{Arg, ArgAction, Command};

mod steg86;

fn app() -> Command {
    Command::new(env!("CARGO_PKG_NAME"))
        .subcommand_required(true)
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("profile")
                .about("profile a binary for steganographic storage capacity")
                // TODO(ww): --json flag.
                .arg(
                    Arg::new("raw")
                        .help("treat the input as a raw binary")
                        .long("raw")
                        .short('r')
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("bitness")
                        .help("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .value_parser(["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .help("the binary to profile")
                        .index(1)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("embed")
                .about("embed some data into a binary steganographically")
                .arg(
                    Arg::new("raw")
                        .help("treat the input as a raw binary")
                        .long("raw")
                        .short('r')
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("bitness")
                        .help("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .value_parser(["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .help("the binary to embed into")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .help("the path to write the steg'd binary to")
                        .index(2)
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("extract")
                .about("extract the hidden data from a binary")
                .arg(
                    Arg::new("raw")
                        .help("treat the input as a raw binary")
                        .long("raw")
                        .short('r')
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("bitness")
                        .help("the bitness of the raw binary")
                        .long("bitness")
                        .short('b')
                        .value_parser(["16", "32", "64"])
                        .requires("raw"),
                )
                .arg(
                    Arg::new("input")
                        .help("the binary to extract from")
                        .index(1)
                        .required(true),
                ),
        )
}

fn run() -> Result<()> {
    let matches = app().get_matches();

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
            eprintln!("Fatal: {e}");
            1
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app() {
        app().debug_assert();
    }
}
