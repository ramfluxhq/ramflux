// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Windows defaults for the data root and the local-bus name file. The Unix defaults under
//! `/tmp` have no meaning on Windows; an explicit `--socket` or `--data-root` is kept as given.

use std::path::Path;

use crate::cli::{Cli, Command, DaemonAction};
use crate::{DEFAULT_DATA_ROOT, DEFAULT_SOCKET, RfError};

/// File inside the data root that publishes the name of the daemon's named pipe.
const NAME_FILE: &str = "rfd.sock";

/// Replace untouched Unix defaults with `%LOCALAPPDATA%\ramflux\default` and the name file in it.
///
/// # Errors
/// Returns an error when the shell does not report the local application-data folder.
pub(crate) fn with_defaults(mut cli: Cli) -> Result<Cli, RfError> {
    if cli.socket == Path::new(DEFAULT_SOCKET) {
        cli.socket = ramflux_sdk::windows_default_data_root(None)?.join(NAME_FILE);
    }
    if let Command::Daemon(command) = &mut cli.command
        && let DaemonAction::Start(start) = &mut command.action
        && start.data_root == Path::new(DEFAULT_DATA_ROOT)
    {
        start.data_root = ramflux_sdk::windows_default_data_root(None)?;
    }
    Ok(cli)
}
