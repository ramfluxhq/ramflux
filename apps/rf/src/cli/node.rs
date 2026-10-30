// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct NodeCommand {
    #[command(subcommand)]
    pub(crate) action: NodeAction,
}

#[derive(Subcommand)]
pub(crate) enum NodeAction {
    Add(NodeAdd),
    Confirm(NodeConfirm),
    List,
    Probe(NodeSelector),
    Remove(NodeSelector),
    SetDefault(NodeSelector),
    Enable(NodeSelector),
    Disable(NodeSelector),
    /// Provision a gateway proxy using the existing pinned discovery identity; no daemon required.
    CustodyInit(NodeCustody),
    /// Prepare a successor record and fresh proxy seed; applying rotation is a separate operation.
    #[command(mut_arg("deployed_record", |arg| arg.required(true)))]
    CustodyRenew(NodeCustody),
}

#[derive(Args)]
pub(crate) struct NodeCustody {
    #[arg(long)]
    pub(crate) node_id: String,
    /// Existing certs/node-identity/node-signing.key, never generated or overwritten.
    #[arg(long)]
    pub(crate) node_signing_seed: std::path::PathBuf,
    /// Independently retained `DEMO_EXPECTED_NODE_PUBLIC_KEY` from the demo identity.env.
    #[arg(long)]
    pub(crate) expected_public_key: String,
    #[arg(long)]
    pub(crate) output_dir: std::path::PathBuf,
    #[arg(long, default_value_t = 30)]
    pub(crate) validity_days: u64,
    /// Signed record currently installed on the node, required for every renewal.
    #[arg(long)]
    pub(crate) deployed_record: Option<std::path::PathBuf>,
    /// Prepare another immutable fragment for an already prepared epoch; preserve all prior output.
    #[arg(long)]
    pub(crate) force_new_proxy: bool,
}

#[derive(Args)]
pub(crate) struct NodeAdd {
    pub(crate) url: String,
    #[arg(long)]
    pub(crate) refresh: bool,
}

#[derive(Args)]
pub(crate) struct NodeConfirm {
    pub(crate) node_id: String,
    #[arg(long, default_value = "tofu", value_parser = ["tofu", "operator", "invitation"])]
    pub(crate) pin_source: String,
    #[arg(long)]
    pub(crate) expected_public_key: Option<String>,
}

#[derive(Args)]
pub(crate) struct NodeSelector {
    pub(crate) node_id: String,
}
