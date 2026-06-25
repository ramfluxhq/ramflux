#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct A2iCommand {
    #[command(subcommand)]
    pub(crate) action: A2iAction,
}

#[derive(Subcommand)]
pub(crate) enum A2iAction {
    Append(A2iAppend),
    List(AccountSelector),
    Ack(A2iAck),
}

#[derive(Args)]
pub(crate) struct A2iAppend {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) event: String,
    #[arg(long = "type")]
    pub(crate) event_type: String,
    #[arg(long)]
    pub(crate) source_device: String,
    #[arg(long)]
    pub(crate) target_device: String,
    #[arg(long = "control-domain")]
    pub(crate) control_domain: String,
    #[arg(long)]
    pub(crate) action: String,
    #[arg(long)]
    pub(crate) subject: String,
    #[arg(long)]
    pub(crate) created_at: Option<i64>,
    #[arg(long)]
    pub(crate) target_delivery: Option<String>,
}

#[derive(Args)]
pub(crate) struct A2iAck {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) event: String,
}

#[derive(Args)]
pub(crate) struct A2uiCommand {
    #[command(subcommand)]
    pub(crate) action: A2uiAction,
}

#[derive(Subcommand)]
pub(crate) enum A2uiAction {
    Render(A2uiRender),
    Action(A2uiActionSubmit),
}

#[derive(Args)]
pub(crate) struct A2uiRender {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) surface: PathBuf,
    #[arg(long = "catalog", default_value = "ramflux.basic.v1")]
    pub(crate) supported_catalog: Vec<String>,
    #[arg(long = "permission")]
    pub(crate) permission: Vec<String>,
}

#[derive(Args)]
pub(crate) struct A2uiActionSubmit {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) surface: PathBuf,
    #[arg(long)]
    pub(crate) action: PathBuf,
}
