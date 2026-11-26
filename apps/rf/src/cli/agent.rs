// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf agent` drivers (AGENT-IDENTITY-01 E5). Each subcommand is one thin call of an agent bus
//! method on the desktop; the SDK decides every refusal. Shaped like the pairing group.
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct AgentCommand {
    /// Local human account that owns the agent.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[command(subcommand)]
    pub(crate) action: AgentAction,
}

/// The persona of an agent (contract 1 `AgentPersona`).
#[derive(Args)]
pub(crate) struct AgentPersonaArgs {
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long, default_value = "")]
    pub(crate) avatar: String,
    #[arg(long)]
    pub(crate) responsibility: String,
}

/// The model the agent will use (contract 1 `AgentConfigData`). The creation plan freezes both in
/// the public profile the primary approves, so a creation without them is refused.
#[derive(Args)]
pub(crate) struct AgentModelArgs {
    /// The model provider the agent uses, for example `openai`.
    #[arg(long)]
    pub(crate) provider: String,
    /// The model of that provider.
    #[arg(long)]
    pub(crate) model: String,
    /// Admission limit: concurrent turns for this agent (`1..=1024`).
    #[arg(long)]
    pub(crate) max_concurrent_turns: Option<u32>,
    /// Admission limit: daily cost in cents (`1..=1000000000`).
    #[arg(long)]
    pub(crate) max_cost_per_day_cents: Option<u64>,
    /// `full`, `supervised` or `readonly`. PRX's default is `full`.
    #[arg(long)]
    pub(crate) autonomy: Option<String>,
    /// The agent's system prompt (at most 32768 bytes). PRX composes one when omitted.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) prompt: Option<String>,
    /// Tool names, comma separated. `*` or no flag means all of Main's tools.
    #[arg(long, value_delimiter = ',')]
    pub(crate) tools: Option<Vec<String>>,
}

/// What `rf agent update` may change. Every field is optional; a field left out stays as it is.
#[derive(Args)]
pub(crate) struct AgentUpdateArgs {
    #[arg(long)]
    pub(crate) provider: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    /// `full`, `supervised` or `readonly`.
    #[arg(long)]
    pub(crate) autonomy: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) prompt: Option<String>,
    /// Tool names, comma separated; `*` is all of Main's tools.
    #[arg(long, value_delimiter = ',')]
    pub(crate) tools: Option<Vec<String>>,
    /// `true` or `false`.
    #[arg(long, action = clap::ArgAction::Set)]
    pub(crate) enabled: Option<bool>,
    #[arg(long)]
    pub(crate) max_concurrent_turns: Option<u32>,
    #[arg(long)]
    pub(crate) max_cost_per_day_cents: Option<u64>,
    /// Remove both admission limits.
    #[arg(long, conflicts_with_all = ["max_concurrent_turns", "max_cost_per_day_cents"])]
    pub(crate) clear_limits: bool,
    /// Confirm a change PRX marks high risk.
    #[arg(long)]
    pub(crate) confirm_high_risk: bool,
}

/// The access policy of an agent (contract 1 `AgentAccessPolicy`).
#[derive(Args)]
pub(crate) struct AgentAccessArgs {
    /// `owner`, `contacts`, `allowlist` or `open`.
    #[arg(long, default_value = "owner")]
    pub(crate) dm: String,
    /// `owner`, `contacts`, `allowlist` or `open`.
    #[arg(long, default_value = "owner")]
    pub(crate) group_inviters: String,
    /// A canonical anchor allowed by `allowlist`; repeat the flag for more.
    #[arg(long = "allowed-human")]
    pub(crate) allowed_humans: Vec<String>,
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Start an agent creation. The desktop is the only device that can start one.
    Create {
        #[command(flatten)]
        persona: AgentPersonaArgs,
        #[command(flatten)]
        model: AgentModelArgs,
        #[command(flatten)]
        access: AgentAccessArgs,
        #[arg(long, default_value = "named")]
        role: String,
        /// Confirm after the owner has reviewed the persona and access on this desktop.
        #[arg(long)]
        confirm: bool,
    },
    /// On the primary: show the next creation request that waits for this device's decision, with
    /// what the owner must review (agent name, responsibility, provider, model, the requesting
    /// desktop, the expiry) and the `request_id` and `request_hash` that `decide` needs.
    Pending,
    /// Answer the primary phone's creation request. `approved` is required.
    Decide {
        #[arg(long, allow_hyphen_values = true)]
        request_id: String,
        #[arg(long, allow_hyphen_values = true)]
        request_hash: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        approved: bool,
    },
    /// List the agents of this owner, one page.
    List {
        #[arg(long, allow_hyphen_values = true)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Show one agent record.
    Show {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
    },
    /// Change the persona of an agent.
    Edit {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[command(flatten)]
        persona: AgentPersonaArgs,
        #[arg(long)]
        confirm: bool,
    },
    /// Change the access policy of an agent. `--base` is the `identity` of the record shown last.
    Access {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[command(flatten)]
        access: AgentAccessArgs,
        /// The `identity` object of `rf agent show` as JSON.
        #[arg(long, allow_hyphen_values = true)]
        base: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Delete an agent in state U. The node retires the custody record and the local account goes.
    Delete {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Retire an agent from the current primary. The node retires the custody record.
    Retire {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Change the PRX config of an agent (AGENT-MGMT-01A). `--revision` is the `revision` of the
    /// record shown last; PRX refuses a stale view with `revision_conflict`.
    Update {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[arg(long, allow_hyphen_values = true)]
        revision: Option<String>,
        #[command(flatten)]
        update: AgentUpdateArgs,
    },
    /// Turn an agent off in PRX. PRX refuses its turns until `resume`.
    Pause {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[arg(long, allow_hyphen_values = true)]
        revision: Option<String>,
    },
    /// Turn a paused agent on again.
    Resume {
        #[arg(long, allow_hyphen_values = true)]
        agent: String,
        #[arg(long, allow_hyphen_values = true)]
        revision: Option<String>,
    },
    /// The models (with credential readiness), tools and defaults PRX offers.
    Catalog,
    /// Show the state of one creation operation.
    Status {
        #[arg(long, allow_hyphen_values = true)]
        operation_id: String,
    },
    /// List, pause, resume, or remove one agent's jobs, or list job-run sessions.
    Job(AgentJobCommand),
}

#[derive(Args)]
pub(crate) struct AgentJobCommand {
    #[command(subcommand)]
    pub(crate) action: AgentJobAction,
}

#[derive(Subcommand)]
pub(crate) enum AgentJobAction {
    /// List cron jobs, xin tasks, and xin goals for one agent.
    List {
        #[arg(long)]
        agent: String,
    },
    /// Pause one job. `kind` is `cron`, `xin_task`, or `xin_goal`.
    Pause {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        id: String,
    },
    /// Resume one job.
    Resume {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        id: String,
    },
    /// Remove one job.
    Remove {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        id: String,
    },
    /// List job-run sessions published for one agent.
    Sessions {
        #[arg(long)]
        agent: String,
    },
}
