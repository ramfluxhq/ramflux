// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional explicitly provisioned username services. Witness owns every public response writer.
mod client;
mod dns;
mod home;
mod home_profile;
mod home_status;
mod ipc;
mod primary;
mod primary_peer;
mod quic;
mod rpc;
mod source;
mod tcp;
mod tls;
mod wire;
mod witness;
pub(crate) use home::{local as local_home, start as start_home};

use ramflux_node_core::username_directory as directory;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

fn error(message: &'static str) -> Error {
    std::io::Error::other(message).into()
}
fn refuse<T>(message: &'static str) -> Result<T> {
    Err(error(message))
}

pub(crate) fn start(
    config: &ramflux_node_core::NodeServiceConfig,
) -> std::result::Result<bool, ramflux_node_core::NodeCoreError> {
    let directory = directory::DirectoryConfig::from_env().map_err(node_error)?;
    let Some(directory) = directory else {
        return Ok(false);
    };
    if !ramflux_protocol::username_directory::enabled() {
        return Err(node_error("complete username path is not released"));
    }
    match &directory.role {
        directory::DirectoryRole::Center { .. } => primary::run(&directory).map_err(node_error)?,
        directory::DirectoryRole::Witness { .. } => {
            witness::run(config, &directory).map_err(node_error)?;
        }
        directory::DirectoryRole::Home { .. } => return Ok(false),
    }
    Ok(true)
}

fn node_error(error: impl std::fmt::Display) -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::InvalidConfiguration(format!("username directory: {error}"))
}

fn flag(name: &str) -> bool {
    std::env::args().any(|arg| arg == name)
}
