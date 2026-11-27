// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use clap::{Args, Subcommand};

/// Large groups (pseudonymous posting, up to 1 000 members).
#[derive(Args)]
pub(crate) struct LargeCommand {
    #[command(subcommand)]
    pub(crate) action: LargeAction,
}

#[derive(Subcommand)]
pub(crate) enum LargeAction {
    /// Create a large group (this account becomes the owner).
    Create(LargeCreate),
    /// Mint an invite link (owner or admin).
    Invite(LargeGroupArg),
    /// Join with an invite link.
    Join(LargeJoin),
    /// Approve pending joins (ON: admin) or welcome joiners (OFF: any keyed member).
    Ratchet(LargeAccountGroup),
    /// Refill posting tokens (one fixed batch of 20).
    Tokens(LargeTokens),
    /// Post a text message.
    Post(LargePost),
    /// Read and verify the log.
    Read(LargeRead),
    /// Local state of one large group.
    Status(LargeAccountGroup),
    /// Promote or demote an admin.
    Admin(LargeAdmin),
}

#[derive(Args)]
pub(crate) struct LargeAccountGroup {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
}

#[derive(Args)]
pub(crate) struct LargeGroupArg {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) max_uses: Option<u32>,
    #[arg(long)]
    pub(crate) ttl_ms: Option<u64>,
}

#[derive(Args)]
pub(crate) struct LargeCreate {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    /// Join approval: `on` (admin approves) or `off` (automatic).
    #[arg(long, default_value = "on")]
    pub(crate) approval: String,
    #[arg(long, default_value = "home")]
    pub(crate) host: String,
}

#[derive(Args)]
pub(crate) struct LargeJoin {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) link: String,
}

#[derive(Args)]
pub(crate) struct LargeTokens {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Args)]
pub(crate) struct LargePost {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) text: String,
}

#[derive(Args)]
pub(crate) struct LargeRead {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) limit: Option<u32>,
}

#[derive(Args)]
pub(crate) struct LargeAdmin {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    /// `promote` or `demote`.
    #[arg(long)]
    pub(crate) action: String,
    /// Target pseudonym (base64url).
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) target: String,
}

/// Hidden fixtures for real runs (clock, fault injection, known-answer checks).
#[derive(Args)]
pub(crate) struct DebugCommand {
    #[command(subcommand)]
    pub(crate) action: DebugAction,
}

#[derive(Subcommand)]
pub(crate) enum DebugAction {
    /// Large-group fixtures.
    Lg(DebugLgCommand),
    /// Known-answer checks.
    Kat(DebugKatCommand),
}

#[derive(Args)]
pub(crate) struct DebugKatCommand {
    #[command(subcommand)]
    pub(crate) action: DebugKatAction,
}

#[derive(Subcommand)]
pub(crate) enum DebugKatAction {
    /// RFC 9497 A.1.3 POPRF vectors 1 to 3.
    Poprf,
}

#[derive(Args)]
pub(crate) struct DebugLgCommand {
    #[command(subcommand)]
    pub(crate) action: DebugLgAction,
}

#[derive(Subcommand)]
pub(crate) enum DebugLgAction {
    /// Shift the client clock and/or the (debug) host clock.
    Clock(DebugClock),
    /// Inject one host fault: `roll`, `hold`, `appended`, `wrong_slot`, `alt_head`, `garbage_w`.
    Fault(DebugFault),
    /// Join N synthetic pseudonyms with real keys (state discarded).
    BulkJoin(DebugBulkJoin),
}

#[derive(Args)]
pub(crate) struct DebugClock {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) client_offset_ms: Option<i64>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) host_offset_ms: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DebugFault {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) reason: Option<u64>,
    #[arg(long)]
    pub(crate) from_seq: Option<u64>,
    #[arg(long)]
    pub(crate) ms: Option<u64>,
    #[arg(long)]
    pub(crate) n: Option<u64>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) p: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) except: Option<String>,
}

#[derive(Args)]
pub(crate) struct DebugBulkJoin {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) link: String,
    #[arg(long)]
    pub(crate) count: u64,
}
