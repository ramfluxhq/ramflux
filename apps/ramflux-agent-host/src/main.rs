// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use clap::Parser;
use ramflux_agent_host::{AgentHost, Config, Error, RfdBus, RuleEngine};
use std::path::PathBuf;
mod reconnect;
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
    let mut backoff = reconnect::ReconnectBackoff::default();
    loop {
        let started = std::time::Instant::now();
        let attempt = async {
            let mut bus = RfdBus::connect(&config.socket, &config.account_id).await?;
            host.start(&mut bus).await?;
            host.run(&mut bus).await
        };
        let error = tokio::select! {
            result=attempt=>match result {
                Err(error) if !error.stops_host()=>error,
                other=>return other,
            },
            result=tokio::signal::ctrl_c()=>{result.map_err(|_|Error::State)?;return Ok(());}
        };
        let delay = backoff.failed(started.elapsed());
        // No response bodies, plaintext, credentials or endpoint paths enter logs.
        eprintln!("agent host reconnecting: {error}; retry in {}s", delay.as_secs());
        if backoff.failures() >= 4 {
            eprintln!(
                "agent host retry backoff: {} consecutive failures; next attempt in {}s",
                backoff.failures(),
                delay.as_secs()
            );
        }
        tokio::select! {
            ()=tokio::time::sleep(delay)=>{},
            result=tokio::signal::ctrl_c()=>{result.map_err(|_|Error::State)?;return Ok(());}
        }
    }
}
