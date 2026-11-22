// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct DeviceCommand {
    #[command(subcommand)]
    pub(crate) action: DeviceAction,
}

#[derive(Subcommand)]
pub(crate) enum DeviceAction {
    Revoke(DeviceRevoke),
    /// Observe a root-signed device set and apply revocation/key-rotation safety changes.
    Refresh(DeviceRefresh),
    List(AccountSelector),
    Sync(DeviceSyncCommand),
}

#[derive(Args)]
pub(crate) struct DeviceRevoke {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) device: String,
}

#[derive(Args)]
pub(crate) struct DeviceSyncCommand {
    #[command(subcommand)]
    pub(crate) action: DeviceSyncAction,
}

#[derive(Subcommand)]
pub(crate) enum DeviceSyncAction {
    Export(DeviceSyncExport),
}

#[derive(Args)]
pub(crate) struct DeviceSyncExport {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target_device: String,
    #[arg(long)]
    pub(crate) relay_endpoint: String,
    #[arg(long)]
    pub(crate) chunk_size: Option<usize>,
}

#[derive(Args)]
pub(crate) struct DeviceRefresh {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) principal_commitment: Option<String>,
}
