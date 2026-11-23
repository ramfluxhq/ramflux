// SPDX-License-Identifier: BSD-3-Clause
//! Publish host fixtures by opening each case on the signed card library.
mod cases;
mod publish;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("card-fixtures: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("usage: card-fixtures --write|--check")?;
    if args.next().is_some() {
        return Err("usage: card-fixtures --write|--check".into());
    }
    let package = publish::signed_library()?;
    let catalog = cases::load()?;
    match command.as_str() {
        "--write" => publish::write_all(&package, &catalog),
        "--check" => publish::check_all(&package, &catalog),
        _ => Err("usage: card-fixtures --write|--check".into()),
    }
}
