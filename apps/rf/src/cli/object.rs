// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct ObjectCommand {
    #[command(subcommand)]
    pub(crate) action: ObjectAction,
}

#[derive(Subcommand)]
pub(crate) enum ObjectAction {
    Put(ObjectPut),
    Get(ObjectGet),
    Status(ObjectStatus),
    Resume(ObjectResume),
    Import(ObjectImport),
    List(AccountSelector),
    Share(ObjectShare),
    Delete(ObjectDelete),
}

#[derive(Args)]
pub(crate) struct ObjectPut {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
    #[arg(long, default_value_t = 1024)]
    pub(crate) chunk_size: usize,
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    #[arg(long)]
    pub(crate) relay_service_key: Option<String>,
    #[arg(long)]
    pub(crate) relay_interrupt_after_chunks: Option<u32>,
    pub(crate) file: PathBuf,
}

#[derive(Args)]
pub(crate) struct ObjectGet {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    #[arg(long)]
    pub(crate) relay_service_key: Option<String>,
    #[arg(long)]
    pub(crate) relay_ack: bool,
    #[arg(long)]
    pub(crate) relay_interrupt_after_chunks: Option<u32>,
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct ObjectStatus {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
    #[arg(long)]
    pub(crate) direction: Option<String>,
}

#[derive(Args)]
pub(crate) struct ObjectResume {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
    #[arg(long)]
    pub(crate) direction: String,
    #[arg(long)]
    pub(crate) relay_url: String,
    #[arg(long)]
    pub(crate) relay_service_key: Option<String>,
    #[arg(long)]
    pub(crate) relay_interrupt_after_chunks: Option<u32>,
}

#[derive(Args)]
pub(crate) struct ObjectShare {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
    #[arg(long)]
    pub(crate) to: String,
    #[arg(long)]
    pub(crate) sender: Option<String>,
    #[arg(long)]
    pub(crate) recipient_device: Option<String>,
    #[arg(long)]
    pub(crate) recipient_principal_commitment: Option<String>,
    #[arg(long)]
    pub(crate) target: Option<String>,
    #[arg(long)]
    pub(crate) out_package: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct ObjectDelete {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) object: String,
}

#[derive(Args)]
pub(crate) struct ObjectImport {
    #[arg(long)]
    pub(crate) account: String,
    pub(crate) package: PathBuf,
}
