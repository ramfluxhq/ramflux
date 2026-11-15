// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit refusal until private pairing-file ownership has a platform implementation.
use crate::{
    RfError,
    cli::{PairingCommand, TransferCommand},
};
use std::path::PathBuf;

pub(crate) async fn handle(_: PathBuf, _: PairingCommand) -> Result<(), RfError> {
    Err(RfError::UnsupportedPlatform { command: "Pairing" })
}

pub(crate) async fn handle_transfer(_: PathBuf, _: TransferCommand) -> Result<(), RfError> {
    Err(RfError::UnsupportedPlatform { command: "Account transfer" })
}
