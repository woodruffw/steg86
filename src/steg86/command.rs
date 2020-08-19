use anyhow::Result;
use clap::ArgMatches;

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::steg86::binary::Text;

/// Display the steganographic profile for the input.
/// See `steg86 profile -h`.
pub fn profile(matches: &ArgMatches) -> Result<()> {
    let path = matches.value_of("input").unwrap();
    let profile = {
        let text = if matches.is_present("raw") {
            let bitness: u32 = matches.value_of_t("bitness").unwrap_or(64);
            Text::from_raw(Path::new(path), bitness)?
        } else {
            Text::from_program(Path::new(path))?
        };

        text.profile()?
    };

    println!(
        "Summary for {}:\n\
        \t{} total instructions\n\
        \t{} potential semantic pairs\n\
        \t{} bits of information capacity ({} bytes, approx. {}KB)",
        path,
        profile.instruction_count,
        profile.semantic_pairs,
        profile.information_capacity,
        profile.information_capacity / 8,
        profile.information_capacity / 8 / 1024,
    );

    Ok(())
}

/// Embed a message (provided via `stdin`) into the input.
/// See `steg86 embed -h`.
pub fn embed(matches: &ArgMatches) -> Result<()> {
    let input = Path::new(matches.value_of("input").unwrap());
    let output = match matches.value_of("output") {
        Some(output) => PathBuf::from(output),
        None => Path::new(input).with_extension("steg"),
    };

    let text = if matches.is_present("raw") {
        let bitness: u32 = matches.value_of_t("bitness").unwrap_or(64);
        Text::from_raw(Path::new(input), bitness)?
    } else {
        Text::from_program(Path::new(input))?
    };

    let message = {
        let mut message = Vec::new();
        io::stdin().read_to_end(&mut message)?;
        message
    };

    let new_text = text.embed(&message)?;

    let patched = new_text.patch_program(input)?;
    fs::write(output, patched)?;

    Ok(())
}

/// Extract a message (and stream it to `stdout`) from the input.
/// See `steg86 extract -h`.
pub fn extract(matches: &ArgMatches) -> Result<()> {
    let input = Path::new(matches.value_of("input").unwrap());

    let text = if matches.is_present("raw") {
        let bitness: u32 = matches.value_of_t("bitness").unwrap_or(64);
        Text::from_raw(Path::new(input), bitness)?
    } else {
        Text::from_program(Path::new(input))?
    };

    io::stdout().write_all(&text.extract()?)?;

    Ok(())
}
