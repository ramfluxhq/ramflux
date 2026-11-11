// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub(crate) use crate::{DEFAULT_DATA_ROOT, DEFAULT_SOCKET};

mod a2i_a2ui;
mod account;
mod admin;
mod call_bot;
mod contact;
mod daemon;
mod device;
mod dm;
mod grant;
mod group;
mod keychain;
mod vault;
pub(crate) use vault::*;
mod mcp;
mod node;
mod object;
mod surface;
pub(crate) use node::*;
pub(crate) use surface::*;

pub(crate) use a2i_a2ui::*;
pub(crate) use account::*;
pub(crate) use admin::*;
pub(crate) use call_bot::*;
pub(crate) use contact::*;
pub(crate) use daemon::*;
pub(crate) use device::*;
mod pairing;
pub(crate) use dm::*;
pub(crate) use grant::*;
pub(crate) use group::*;
pub(crate) use keychain::*;
pub(crate) use mcp::*;
pub(crate) use object::*;
pub(crate) use pairing::*;

#[derive(Parser)]
#[command(name = "rf", about = "Ramflux reference CLI over the local SDK bus")]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    pub(crate) socket: PathBuf,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Daemon(DaemonCommand),
    Node(NodeCommand),
    Account(AccountCommand),
    Contact(ContactCommand),
    Device(DeviceCommand),
    /// Native SAS pairing preview (default-off).
    Pairing(PairingCommand),
    Dm(DmCommand),
    Group(GroupCommand),
    Object(ObjectCommand),
    Call(CallCommand),
    Bot(BotCommand),
    Mcp(McpCommand),
    Grant(GrantCommand),
    Keychain(KeychainCommand),
    Vault(VaultCommand),
    A2i(A2iCommand),
    A2ui(A2uiCommand),
    Surface(SurfaceCommand),
    Admin(AdminCommand),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn retired_relay_service_key_flags_are_typed_parse_refusals()
    -> Result<(), Box<dyn std::error::Error>> {
        for arguments in [
            vec!["rf", "dm", "send", "--relay-service-key", "retired"],
            vec!["rf", "dm", "read", "--relay-service-key", "retired"],
            vec!["rf", "device", "sync", "export", "--relay-service-key-base64", "retired"],
            vec!["rf", "device", "sync", "import", "--relay-service-key-base64", "retired"],
        ] {
            let error =
                Cli::try_parse_from(arguments).err().ok_or("test: retired relay flag accepted")?;
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "retired flag must fail during parsing rather than be silently ignored"
            );
        }
        Ok(())
    }

    #[test]
    fn a2i_append_defaults_created_at_to_runtime_now() {
        let cli = Cli::try_parse_from([
            "rf",
            "a2i",
            "append",
            "--account",
            "alice",
            "--event",
            "evt",
            "--type",
            "a2i.control",
            "--source-device",
            "alice_device",
            "--target-device",
            "cli_device",
            "--control-domain",
            "message",
            "--action",
            "context_share",
            "--subject",
            "hello",
        ])
        .expect("parse a2i append");
        let Command::A2i(command) = cli.command else {
            panic!("expected a2i command");
        };
        let A2iAction::Append(append) = command.action else {
            panic!("expected a2i append");
        };
        assert_eq!(append.created_at, None);
    }

    #[test]
    fn a2i_append_preserves_explicit_created_at() {
        let cli = Cli::try_parse_from([
            "rf",
            "a2i",
            "append",
            "--account",
            "alice",
            "--event",
            "evt",
            "--type",
            "a2i.control",
            "--source-device",
            "alice_device",
            "--target-device",
            "cli_device",
            "--control-domain",
            "message",
            "--action",
            "context_share",
            "--subject",
            "hello",
            "--created-at",
            "1760000700",
        ])
        .expect("parse a2i append with created_at");
        let Command::A2i(command) = cli.command else {
            panic!("expected a2i command");
        };
        let A2iAction::Append(append) = command.action else {
            panic!("expected a2i append");
        };
        assert_eq!(append.created_at, Some(1_760_000_700));
    }

    #[test]
    fn admin_peer_defaults_now_to_runtime_now() {
        let cli = Cli::try_parse_from([
            "rf",
            "admin",
            "federation",
            "peer",
            "--node-a-admin-url",
            "http://127.0.0.1:1",
            "--node-a-token",
            "token-a",
            "--node-a-id",
            "node-a",
            "--node-a-well-known-url",
            "http://node-a/.well-known/ramflux",
            "--node-b-admin-url",
            "http://127.0.0.1:2",
            "--node-b-token",
            "token-b",
            "--node-b-id",
            "node-b",
            "--node-b-well-known-url",
            "http://node-b/.well-known/ramflux",
        ])
        .expect("parse admin peer");
        let Command::Admin(command) = cli.command else {
            panic!("expected admin command");
        };
        let AdminAction::Federation(command) = command.action;
        let AdminFederationAction::Peer(peer) = command.action;
        assert_eq!(peer.now, None);
    }

    #[test]
    fn admin_peer_preserves_explicit_now() {
        let cli = Cli::try_parse_from([
            "rf",
            "admin",
            "federation",
            "peer",
            "--node-a-admin-url",
            "http://127.0.0.1:1",
            "--node-a-token",
            "token-a",
            "--node-a-id",
            "node-a",
            "--node-a-well-known-url",
            "http://node-a/.well-known/ramflux",
            "--node-b-admin-url",
            "http://127.0.0.1:2",
            "--node-b-token",
            "token-b",
            "--node-b-id",
            "node-b",
            "--node-b-well-known-url",
            "http://node-b/.well-known/ramflux",
            "--now",
            "1760000020",
        ])
        .expect("parse admin peer with now");
        let Command::Admin(command) = cli.command else {
            panic!("expected admin command");
        };
        let AdminAction::Federation(command) = command.action;
        let AdminFederationAction::Peer(peer) = command.action;
        assert_eq!(peer.now, Some(1_760_000_020));
    }
}

#[cfg(test)]
#[path = "opaque_id_tests.rs"]
mod opaque_id_tests;

#[cfg(test)]
mod free_text_tests;
