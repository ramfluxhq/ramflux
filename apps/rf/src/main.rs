// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod cli;
mod handlers;
mod keychain;
#[cfg(target_os = "linux")]
mod linux_paths;
mod logging;
#[cfg(unix)]
mod prx;
mod utils;
#[cfg(windows)]
mod windows_paths;

use clap::Parser;
use cli::{Cli, Command};

#[cfg(not(target_os = "linux"))]
pub(crate) const DEFAULT_SOCKET: &str = "/tmp/ramflux/rfd.sock";
#[cfg(not(target_os = "linux"))]
pub(crate) const DEFAULT_DATA_ROOT: &str = "/tmp/ramflux/rfd-data";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RfError {
    #[cfg(unix)]
    #[error("Pairing command did not complete.")]
    PairingExit { code: i32 },
    #[cfg(not(unix))]
    #[error("{command} is unsupported on this platform.")]
    UnsupportedPlatform { command: &'static str },
    #[error("{code}: {message}")]
    Refused { code: &'static str, message: String },
    #[error("{0}")]
    Message(String),
    #[error("SDK error: {0}")]
    Sdk(#[from] ramflux_sdk::SdkError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("address parse error: {0}")]
    Addr(#[from] std::net::AddrParseError),
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(match error {
            #[cfg(unix)]
            RfError::PairingExit { code } => code,
            #[cfg(not(unix))]
            RfError::UnsupportedPlatform { .. } => 2,
            _ => 1,
        });
    }
}

async fn run() -> Result<(), RfError> {
    let cli = Cli::parse();
    #[cfg(windows)]
    let cli = windows_paths::with_defaults(cli)?;
    #[cfg(target_os = "linux")]
    let socket = linux_paths::resolve_socket(cli.socket)?;
    #[cfg(not(target_os = "linux"))]
    let socket = cli.socket;
    #[cfg(target_os = "linux")]
    {
        if let Command::Daemon(ref command) = cli.command
            && let cli::DaemonAction::Start(ref start) = command.action
        {
            linux_paths::require_resolved(
                &start.data_root,
                "the data directory is unset or not absolute",
            )?;
            let _ = linux_paths::state_dir()?;
        }
    }
    match cli.command {
        Command::Vault(command) => handlers::vault::handle(command).await,
        Command::Node(command) => handlers::node::handle_node(socket, command).await,
        Command::Daemon(command) => handlers::daemon::handle_daemon(socket, command).await,
        Command::Account(command) => handlers::account::handle_account(socket, command).await,
        Command::Contact(command) => handlers::contact::handle_contact(socket, command).await,
        Command::Username(command) => handlers::username::handle(socket, command).await,
        Command::Device(command) => handlers::device::handle_device(socket, command).await,
        Command::Pairing(command) => handlers::pairing::handle(socket, command).await,
        Command::Agent(command) => handlers::agent::handle_agent(socket, command).await,
        Command::Prx(command) => handlers::prx::handle(command).await,
        Command::Transfer(command) => handlers::pairing::handle_transfer(socket, command).await,
        Command::Dm(command) => handlers::dm::handle_dm(socket, command).await,
        Command::Conversation(command) => handlers::conversation_ops::handle(socket, command).await,
        Command::Group(command) => handlers::group::handle_group(socket, command).await,
        Command::Object(command) => handlers::object::handle_object(socket, command).await,
        Command::Call(command) => handlers::call::handle_call(socket, command).await,
        Command::Bot(command) => handlers::bot::handle_bot(socket, command).await,
        Command::Mcp(command) => handlers::mcp::handle_mcp(socket, command).await,
        Command::Grant(command) => handlers::grant::handle_grant(socket, command).await,
        Command::Keychain(command) => handlers::keychain::handle_keychain(command),
        Command::A2i(command) => handlers::a2i::handle_a2i(socket, command).await,
        Command::Surface(command) => handlers::surface::handle_surface(socket, command).await,
        Command::Task(command) => handlers::task::handle_task(socket, command).await,
        Command::Admin(command) => handlers::admin::handle_admin(command),
        Command::Diag(command) => handlers::diag::handle(socket, command).await,
        Command::Attachment(command) => handlers::attachment::handle(socket, command).await,
    }
}
