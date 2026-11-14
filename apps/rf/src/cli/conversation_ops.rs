// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf conversation` commands for send, reply, edit, react, delete and typing.

use clap::{Args, Subcommand, ValueEnum};

#[derive(Args)]
pub(crate) struct ConversationCommand {
    #[command(subcommand)]
    pub(crate) action: ConversationAction,
}

#[derive(Subcommand)]
pub(crate) enum ConversationAction {
    Send(ConversationSend),
    Reply(ConversationText),
    Edit(ConversationText),
    React(ConversationReact),
    Delete(ConversationDelete),
    Typing(TypingCommand),
}

#[derive(Args)]
pub(crate) struct ConversationSend {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) text: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: String,
}

#[derive(Args)]
pub(crate) struct ConversationText {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) text: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: String,
}

#[derive(Args)]
pub(crate) struct ConversationReact {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) token: String,
    #[arg(long)]
    pub(crate) remove: bool,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ConversationDeleteScope {
    Local,
    Everyone,
}

impl ConversationDeleteScope {
    #[must_use]
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Everyone => "everyone",
        }
    }
}

#[derive(Args)]
pub(crate) struct ConversationDelete {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, value_enum)]
    pub(crate) scope: ConversationDeleteScope,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: String,
}

#[derive(Args)]
pub(crate) struct TypingCommand {
    #[command(subcommand)]
    pub(crate) action: TypingAction,
}

#[derive(Subcommand)]
pub(crate) enum TypingAction {
    Start(TypingEmit),
    Stop(TypingEmit),
    Watch(TypingWatch),
}

#[derive(Args)]
pub(crate) struct TypingEmit {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: String,
}

#[derive(Args)]
pub(crate) struct TypingWatch {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    /// How long to collect `message.transient` typing rows, from 1 to 30 seconds.
    #[arg(long, default_value_t = 6, value_parser = for_secs_in_range)]
    pub(crate) for_secs: u64,
    /// Created after `bus.subscribe` succeeds, before the observation window.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) ready_file: Option<String>,
}

fn for_secs_in_range(raw: &str) -> Result<u64, String> {
    let value = raw.parse::<u64>().map_err(|_| "for-secs must be an integer".to_owned())?;
    if (1..=30).contains(&value) {
        Ok(value)
    } else {
        Err("for-secs must be from 1 to 30".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConversationAction, ConversationDeleteScope, TypingAction, for_secs_in_range};
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn parse(args: &[&str]) -> ConversationAction {
        let cli = Cli::try_parse_from(args).expect("conversation command");
        let Command::Conversation(command) = cli.command else {
            panic!("expected conversation command");
        };
        command.action
    }

    #[test]
    fn conversation_commands_parse_send_reply_edit_react_and_delete() {
        let ConversationAction::Send(send) = parse(&[
            "rf",
            "conversation",
            "send",
            "--account",
            "alice",
            "--conversation",
            "thread",
            "--text",
            "hello",
            "--operation-id",
            "op-send",
        ]) else {
            panic!("expected send");
        };
        assert_eq!(send.operation_id, "op-send");

        let ConversationAction::Edit(edit) = parse(&[
            "rf",
            "conversation",
            "edit",
            "--account",
            "alice",
            "--conversation",
            "thread",
            "--message",
            "m1",
            "--text",
            "revised",
            "--operation-id",
            "op-edit",
        ]) else {
            panic!("expected edit");
        };
        assert_eq!(edit.message, "m1");

        let ConversationAction::React(react) = parse(&[
            "rf",
            "conversation",
            "react",
            "--account",
            "alice",
            "--conversation",
            "thread",
            "--message",
            "m1",
            "--token",
            "thumb",
            "--remove",
            "--operation-id",
            "op-react",
        ]) else {
            panic!("expected react");
        };
        assert!(react.remove);

        let ConversationAction::Delete(delete) = parse(&[
            "rf",
            "conversation",
            "delete",
            "--account",
            "alice",
            "--conversation",
            "thread",
            "--message",
            "m1",
            "--scope",
            "everyone",
            "--operation-id",
            "op-delete",
        ]) else {
            panic!("expected delete");
        };
        assert_eq!(delete.scope, ConversationDeleteScope::Everyone);
        assert_eq!(delete.scope.as_wire(), "everyone");
    }

    #[test]
    fn typing_watch_defaults_for_secs_and_rejects_out_of_range() {
        let ConversationAction::Typing(typing) = parse(&[
            "rf",
            "conversation",
            "typing",
            "watch",
            "--account",
            "bob",
            "--conversation",
            "thread",
        ]) else {
            panic!("expected typing watch");
        };
        let TypingAction::Watch(watch) = typing.action else {
            panic!("expected watch");
        };
        assert_eq!(watch.for_secs, 6);
        assert!(watch.ready_file.is_none());
        assert!(for_secs_in_range("0").is_err());
        assert!(for_secs_in_range("31").is_err());
        assert_eq!(for_secs_in_range("30").expect("upper bound"), 30);
    }

    #[test]
    fn reply_requires_operation_id() {
        let Err(error) = Cli::try_parse_from([
            "rf",
            "conversation",
            "reply",
            "--account",
            "alice",
            "--conversation",
            "thread",
            "--message",
            "m1",
            "--text",
            "hi",
        ]) else {
            panic!("missing operation id was accepted");
        };
        assert_eq!(error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
