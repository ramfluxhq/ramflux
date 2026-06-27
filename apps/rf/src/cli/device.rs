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
    Activate(DeviceActivate),
    Revoke(DeviceRevoke),
    List(AccountSelector),
    Sync(DeviceSyncCommand),
}

#[derive(Args)]
pub(crate) struct DeviceActivate {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) device: String,
    #[arg(long)]
    pub(crate) target: String,
    #[arg(long, default_value = "22")]
    pub(crate) device_seed_byte_hex: String,
    #[arg(long)]
    pub(crate) device_epoch: Option<u64>,
}

#[derive(Args)]
pub(crate) struct DeviceRevoke {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
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
    Import(DeviceSyncImport),
}

#[derive(Args)]
pub(crate) struct DeviceSyncExport {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) target_device: String,
    #[arg(long)]
    pub(crate) relay_endpoint: String,
    #[arg(long)]
    pub(crate) relay_service_key_base64: Option<String>,
    #[arg(long)]
    pub(crate) chunk_size: Option<usize>,
}

#[derive(Args)]
pub(crate) struct DeviceSyncImport {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) envelope_json: Option<String>,
    #[arg(long)]
    pub(crate) envelope_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) relay_service_key_base64: Option<String>,
}
