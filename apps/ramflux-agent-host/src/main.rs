// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use clap::Parser;
use ramflux_agent_host::{
    AgentHost, Config, CredentialVault, EngineProvider, Error, PrxEngine, RuleEngine, SyncTask,
    import_provisioning_bundle, unlock_provisioned_account,
};
use std::path::PathBuf;
mod reconnect;
#[derive(Parser)]
#[command(about = "Deterministic headless participant using an existing rfd account")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    provisioning_bundle: Option<PathBuf>,
    #[cfg(feature = "itest-memory-vault")]
    #[arg(long)]
    itest_memory_vault: bool,
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
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    #[cfg(feature = "itest-memory-vault")]
    let vault = if args.itest_memory_vault {
        CredentialVault::itest_memory()
    } else {
        CredentialVault::production()
    };
    #[cfg(not(feature = "itest-memory-vault"))]
    let vault = CredentialVault::production();
    if let Some(path) = &args.provisioning_bundle {
        import_provisioning_bundle(&vault, path, &config.account_id)?;
    }
    unlock_provisioned_account(&vault, &config.socket, &config.account_id).await?;
    if let Some(engine) = &config.engine {
        let provider = PrxEngine::new(&engine.prx, config.max_conversations)?;
        let sync =
            SyncTask::spawn(&engine.prx, &config.state_file, &config.socket, &config.account_id);
        let result = run_provider(config, provider).await;
        sync.shutdown().await;
        result
    } else {
        let provider = RuleEngine::new(&config)?;
        run_provider(config, provider).await
    }
}
async fn run_provider(
    config: Config,
    provider: impl EngineProvider,
) -> ramflux_agent_host::Result<()> {
    let mut host = AgentHost::new(config.clone(), provider)?;
    let mut backoff = reconnect::ReconnectBackoff::default();
    let mut owner = None;
    loop {
        let started = std::time::Instant::now();
        // The attempt future borrows `host`. Drop it before `stop_host` borrows `host` again.
        let outcome = tokio::select! {
            result = reconnect::one_attempt(&config, &mut host, &mut owner) => result,
            result = tokio::signal::ctrl_c() => {
                result.map_err(|_| Error::State)?;
                return Ok(());
            }
        };
        let error = match outcome {
            Err(error) if !error.stops_host() => error,
            Err(error) => return stop_host(&mut host, error).await,
            Ok(()) => return Ok(()),
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
        if reconnect::wait_and_forward(&config, &mut host, &mut owner, delay).await?
            == reconnect::Wait::Stop
        {
            return Ok(());
        }
    }
}

async fn stop_host(
    host: &mut AgentHost<impl EngineProvider>,
    error: Error,
) -> ramflux_agent_host::Result<()> {
    if matches!(error, Error::IdentityLost)
        && let Err(cancel_error) = host.cancel_live_runs().await
    {
        eprintln!("prx run cancel was not stored: {cancel_error}");
    }
    Err(error)
}
