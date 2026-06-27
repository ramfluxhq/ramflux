// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct AdminCommand {
    #[command(subcommand)]
    pub(crate) action: AdminAction,
}

#[derive(Subcommand)]
pub(crate) enum AdminAction {
    Federation(AdminFederationCommand),
}

#[derive(Args)]
pub(crate) struct AdminFederationCommand {
    #[command(subcommand)]
    pub(crate) action: AdminFederationAction,
}

#[derive(Subcommand)]
pub(crate) enum AdminFederationAction {
    Peer(AdminFederationPeer),
}

#[derive(Args)]
pub(crate) struct AdminFederationPeer {
    #[arg(long)]
    pub(crate) node_a_admin_url: String,
    #[arg(long)]
    pub(crate) node_a_token: String,
    #[arg(long)]
    pub(crate) node_a_id: String,
    #[arg(long)]
    pub(crate) node_a_well_known_url: String,
    #[arg(long)]
    pub(crate) node_b_admin_url: String,
    #[arg(long)]
    pub(crate) node_b_token: String,
    #[arg(long)]
    pub(crate) node_b_id: String,
    #[arg(long)]
    pub(crate) node_b_well_known_url: String,
    #[arg(long, value_delimiter = ',', default_value = "opaque_delivery,federation_relay")]
    pub(crate) capabilities: Vec<String>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
}
