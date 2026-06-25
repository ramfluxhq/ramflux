#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct McpCommand {
    #[command(subcommand)]
    pub(crate) action: McpAction,
}

#[derive(Subcommand)]
pub(crate) enum McpAction {
    Server(McpServerCommand),
    Tool(McpToolCommand),
    Approval(McpApprovalCommand),
}

#[derive(Args)]
pub(crate) struct McpServerCommand {
    #[command(subcommand)]
    pub(crate) action: McpServerAction,
}

#[derive(Subcommand)]
pub(crate) enum McpServerAction {
    Add(McpServerAdd),
    List(AccountSelector),
    Refresh(AccountSelector),
}

#[derive(Args)]
pub(crate) struct McpServerAdd {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) server: String,
    #[arg(long, default_value = "stdio-echo")]
    pub(crate) command: String,
    #[arg(long, default_value = "echo")]
    pub(crate) tool: String,
    #[arg(long, default_value = "external_tool_invoke.echo")]
    pub(crate) capability: String,
    #[arg(long, default_value = "low")]
    pub(crate) risk: String,
}

#[derive(Args)]
pub(crate) struct McpToolCommand {
    #[command(subcommand)]
    pub(crate) action: McpToolAction,
}

#[derive(Subcommand)]
pub(crate) enum McpToolAction {
    List(AccountSelector),
    Call(McpToolCall),
}

#[derive(Args)]
pub(crate) struct McpToolCall {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) server: String,
    #[arg(long)]
    pub(crate) tool: String,
    #[arg(long, default_value = "{}")]
    pub(crate) args_json: String,
}

#[derive(Args)]
pub(crate) struct McpApprovalCommand {
    #[command(subcommand)]
    pub(crate) action: McpApprovalAction,
}

#[derive(Subcommand)]
pub(crate) enum McpApprovalAction {
    List(AccountSelector),
    Show(McpApprovalSelector),
    Approve(McpApprovalSelector),
    Deny(McpApprovalSelector),
}

#[derive(Args)]
pub(crate) struct McpApprovalSelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) approval: String,
}
