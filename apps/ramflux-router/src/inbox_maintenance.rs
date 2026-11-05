// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline inbox restore commands. These never initialize a service or listener.
use std::{io::Write, path::PathBuf};

pub(crate) struct Command {
    quarantine: Option<PathBuf>,
}
pub(crate) fn parse(args: &[String]) -> anyhow::Result<Option<Command>> {
    let rotate = args.iter().filter(|arg| *arg == "--rotate-inbox-incarnations").count();
    let quarantine = args.iter().position(|arg| arg == "--quarantine-wal-segment");
    if rotate == 0 && quarantine.is_none() {
        return Ok(None);
    }
    anyhow::ensure!(
        rotate == 1,
        "--quarantine-wal-segment requires --rotate-inbox-incarnations exactly once"
    );
    let mut config = false;
    let mut segment = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--rotate-inbox-incarnations" => {}
            "--config" | "--quarantine-wal-segment" => {
                let flag = &args[index];
                let value = args
                    .get(index + 1)
                    .filter(|s| !s.starts_with("--"))
                    .ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))?;
                if flag == "--config" {
                    anyhow::ensure!(!config, "--config must occur once");
                    config = true;
                } else {
                    anyhow::ensure!(segment.is_none(), "--quarantine-wal-segment must occur once");
                    segment = Some(PathBuf::from(value));
                }
                index += 1;
            }
            flag => anyhow::bail!("{flag} is mutually exclusive with inbox rotation"),
        }
        index += 1;
    }
    anyhow::ensure!(config, "--rotate-inbox-incarnations requires --config");
    Ok(Some(Command { quarantine: segment }))
}
pub(crate) fn run(
    args: &[String],
    command: &Command,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    let config = ramflux_node_core::read_config_from_args(args.iter().cloned(), "ramflux-router")?
        .ok_or_else(|| anyhow::anyhow!("--rotate-inbox-incarnations requires --config"))?;
    writeln!(
        output,
        "Restore procedure: 1. Stop every gateway serving this router. 2. Stop the router. 3. Run this command. 4. Start the router. 5. Start the gateways; clients re-establish sessions with the new incarnation. Never move or delete WAL segments by hand."
    )?;
    output.flush()?;
    let count = ramflux_node_core::RouterRedbStore::rotate_inbox_incarnations(
        super::operator::resolved_store_path(&config)?,
        command.quarantine.as_deref(),
    )?;
    writeln!(output, "ramflux-router:inbox-rotation-complete inboxes={count}")?;
    Ok(())
}
#[cfg(test)]
mod tests;
