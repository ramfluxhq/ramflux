mod cli;
mod handlers;
mod keychain;
mod utils;

use clap::Parser;
use cli::{Cli, Command};

pub(crate) const DEFAULT_SOCKET: &str = "/tmp/ramflux/rfd.sock";
pub(crate) const DEFAULT_DATA_ROOT: &str = "/tmp/ramflux/rfd-data";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RfError {
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
        std::process::exit(1);
    }
}

async fn run() -> Result<(), RfError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon(command) => handlers::daemon::handle_daemon(cli.socket, command).await,
        Command::Account(command) => handlers::account::handle_account(cli.socket, command).await,
        Command::Contact(command) => handlers::contact::handle_contact(cli.socket, command).await,
        Command::Dm(command) => handlers::dm::handle_dm(cli.socket, command).await,
        Command::Group(command) => handlers::group::handle_group(cli.socket, command).await,
        Command::Object(command) => handlers::object::handle_object(cli.socket, command).await,
        Command::Call(command) => handlers::call::handle_call(cli.socket, command).await,
        Command::Bot(command) => handlers::bot::handle_bot(cli.socket, command).await,
        Command::Mcp(command) => handlers::mcp::handle_mcp(cli.socket, command).await,
        Command::Grant(command) => handlers::grant::handle_grant(cli.socket, command).await,
        Command::Keychain(command) => handlers::keychain::handle_keychain(command),
        Command::A2i(command) => handlers::a2i::handle_a2i(cli.socket, command).await,
        Command::A2ui(command) => handlers::a2ui::handle_a2ui(cli.socket, command).await,
        Command::Admin(command) => handlers::admin::handle_admin(command),
    }
}
