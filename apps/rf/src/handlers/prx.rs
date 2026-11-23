// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf prx` handler. Unix only: the ancestor rule and the user service are Unix.

#[cfg(unix)]
use super::PrxAction;
use super::{PrxCommand, RfError};

pub(crate) async fn handle(command: PrxCommand) -> Result<(), RfError> {
    #[cfg(not(unix))]
    {
        let _ = command;
        return Err(RfError::UnsupportedPlatform { command: "prx" });
    }
    #[cfg(unix)]
    match command.action {
        PrxAction::Bootstrap(opts) => {
            crate::prx::bootstrap(crate::prx::Options {
                state_dir: opts.state_dir,
                provider: opts.provider,
                model: opts.model,
                binary: opts.binary,
            })
            .await
        }
        PrxAction::Status(opts) => crate::prx::status(opts.state_dir).await,
    }
}
