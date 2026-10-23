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
