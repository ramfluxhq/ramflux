// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf task` commands: thin drivers over the existing `task.*` bus methods.

use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct TaskCommand {
    #[command(subcommand)]
    pub(crate) action: TaskAction,
}

#[derive(Subcommand)]
pub(crate) enum TaskAction {
    /// `task.list`: tasks in one conversation, optionally filtered by state.
    List(TaskList),
    /// `task.get`: one task by id.
    Get(TaskGet),
    /// `task.propose`: a proposal; the body file is the typed `TaskProposal`.
    Propose(TaskBodyFile),
    /// `task.accept`: accept a proposal or start at a given task version.
    Accept(TaskVersioned),
    /// `task.decline`: decline a proposal or start at a given task version.
    Decline(TaskVersioned),
    /// `task.start`: a request; the body file is the typed `TaskStart`.
    Start(TaskBodyFile),
    /// `task.update`: a typed `TaskUpdate` body (state, steps, result).
    Update(TaskBodyFile),
    /// `task.resolve`: a typed `TaskResolve` body that links an existing decision.
    Resolve(TaskBodyFile),
    /// `task.cancel`: cancel at the task's base revision.
    Cancel(TaskCancel),
}

#[derive(Args)]
pub(crate) struct TaskList {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) state: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) cursor: Option<String>,
    #[arg(long, default_value_t = 50)]
    pub(crate) limit: u32,
}

#[derive(Args)]
pub(crate) struct TaskGet {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) task_id: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: Option<String>,
}

/// A typed task body read from a bounded JSON file. The bus validates every field.
#[derive(Args)]
pub(crate) struct TaskBodyFile {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) body_file: String,
}

#[derive(Args)]
pub(crate) struct TaskVersioned {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) task_id: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: Option<String>,
    #[arg(long)]
    pub(crate) version: u64,
}

#[derive(Args)]
pub(crate) struct TaskCancel {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) task_id: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: Option<String>,
    #[arg(long)]
    pub(crate) base_revision: u64,
}

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, Command, TaskAction};
    use clap::Parser;

    fn parse(args: &[&str]) -> TaskAction {
        let cli = Cli::try_parse_from(args).expect("test: task command parses");
        let Command::Task(command) = cli.command else {
            panic!("test: expected a task command");
        };
        command.action
    }

    #[test]
    fn task_list_and_get_parse_with_hyphen_safe_ids() {
        let TaskAction::List(list) = parse(&[
            "rf",
            "task",
            "list",
            "--account",
            "bob",
            "--conversation",
            "-thread",
            "--state",
            "pending",
        ]) else {
            panic!("test: expected list");
        };
        assert_eq!(list.conversation, "-thread", "test: hyphen-prefixed conversation id kept");
        assert_eq!(list.limit, 50, "test: list defaults to 50 rows");
        let TaskAction::Get(get) =
            parse(&["rf", "task", "get", "--account", "bob", "--task-id", "-task"])
        else {
            panic!("test: expected get");
        };
        assert_eq!(get.task_id, "-task", "test: hyphen-prefixed task id kept");
        assert!(get.conversation.is_none(), "test: conversation is optional for get");
    }

    #[test]
    fn task_accept_requires_a_numeric_version() {
        let result = Cli::try_parse_from([
            "rf",
            "task",
            "accept",
            "--account",
            "bob",
            "--task-id",
            "t1",
            "--version",
            "not-a-number",
        ]);
        assert!(result.is_err(), "test: accept rejects a non-numeric version");
        let TaskAction::Accept(accept) = parse(&[
            "rf",
            "task",
            "accept",
            "--account",
            "bob",
            "--task-id",
            "t1",
            "--version",
            "3",
        ]) else {
            panic!("test: expected accept");
        };
        assert_eq!(accept.version, 3, "test: accept keeps the task version");
    }

    #[test]
    fn task_cancel_requires_base_revision() {
        let result =
            Cli::try_parse_from(["rf", "task", "cancel", "--account", "bob", "--task-id", "t1"]);
        assert!(result.is_err(), "test: cancel without base-revision is refused at parse time");
    }
}
