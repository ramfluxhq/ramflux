// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf prx` handler. Unix only: the ancestor rule and the user service are Unix.

#[cfg(unix)]
use super::PrxAction;
use super::{PrxCommand, RfError};

pub(crate) async fn handle(socket: std::path::PathBuf, command: PrxCommand) -> Result<(), RfError> {
    #[cfg(not(unix))]
    {
        let _ = (socket, command);
        return Err(RfError::UnsupportedPlatform { command: "prx" });
    }
    #[cfg(unix)]
    match command.action {
        PrxAction::Bootstrap(opts) if opts.via_bus => {
            crate::prx::bootstrap_via_bus(
                socket,
                opts.provider,
                opts.model,
                opts.native_tools,
                opts.no_native_tools,
            )
            .await
        }
        PrxAction::Bootstrap(opts) => {
            let _ = socket;
            crate::prx::bootstrap(crate::prx::Options {
                state_dir: opts.state_dir,
                provider: opts.provider,
                model: opts.model,
                native_tools: opts.native_tools,
                no_native_tools: opts.no_native_tools,
                binary: opts.binary,
            })
            .await
        }
        PrxAction::Status(opts) => {
            let _ = socket;
            crate::prx::status(opts.state_dir).await
        }
    }
}
