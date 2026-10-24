// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use clap::Parser;
use ramflux_agent_host::{AgentHost, Config, Error, RfdBus, RuleEngine};
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Deterministic headless participant using an existing rfd account")]
struct Args {
    #[arg(long)]
    config: PathBuf,
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("agent host stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> ramflux_agent_host::Result<()> {
    let config = Config::load(&Args::parse().config)?;
    let mut host = AgentHost::new(config.clone(), RuleEngine::new(&config)?)?;
    loop {
        let attempt = async {
            let mut bus = RfdBus::connect(&config.socket, &config.account_id).await?;
            host.start(&mut bus).await?;
            host.run(&mut bus).await
        };
        tokio::select! {
            result=attempt=>match result{
                Err(error) if !error.stops_host()=>{},other=>return other,
            },
            result=tokio::signal::ctrl_c()=>{result.map_err(|_|Error::Bus)?;return Ok(());}
        }
        // No response bodies, plaintext, credentials or endpoint paths enter logs.
        eprintln!("agent host reconnecting");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
