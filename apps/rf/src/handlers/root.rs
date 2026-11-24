// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf root snapshot` and `rf root commit` for one shared data root.
#![allow(clippy::wildcard_imports)]
use super::*;
use ramflux_sdk::{DirectMessageCommit, commit_direct_message, read_committed_snapshot};
use zeroize::Zeroizing;

pub(crate) fn handle(command: &RootCommand) -> Result<(), RfError> {
    match &command.action {
        RootAction::Snapshot(snapshot) => read_snapshot(snapshot),
        RootAction::Commit(commit) => write_commit(commit),
    }
}

fn read_snapshot(snapshot: &RootSnapshot) -> Result<(), RfError> {
    let code = account_code(snapshot.passphrase_env.as_deref())?;
    let read = read_committed_snapshot(&snapshot.data_root, &snapshot.account, code.as_bytes());
    print_json(&serde_json::to_value(map_shared(read)?)?)
}

fn write_commit(commit: &RootCommit) -> Result<(), RfError> {
    let code = account_code(commit.passphrase_env.as_deref())?;
    let wrote = commit_direct_message(
        &commit.data_root,
        &commit.account,
        code.as_bytes(),
        DirectMessageCommit {
            conversation_id: &commit.conversation,
            message_id: &commit.message_id,
            sender_id: &commit.sender,
        },
    );
    map_shared(wrote)?;
    print_json(&serde_json::json!({
        "committed": true,
        "message_id": commit.message_id,
    }))
}

fn account_code(passphrase_env: Option<&str>) -> Result<Zeroizing<String>, RfError> {
    let name = passphrase_env.unwrap_or("RAMFLUX_ACCOUNT_PASSPHRASE");
    let value = std::env::var(name).map_err(|_| {
        RfError::Message(format!("required passphrase environment variable {name} is not set"))
    })?;
    if value.is_empty() || value.len() > 1024 {
        return Err(RfError::Refused {
            code: "invalid_argument",
            message: "account code length".to_owned(),
        });
    }
    Ok(Zeroizing::new(value))
}

fn map_shared<T>(result: Result<T, ramflux_sdk::SdkError>) -> Result<T, RfError> {
    result.map_err(|error| match ramflux_sdk::shared_root_refusal(&error) {
        Some(code) => RfError::Refused { code, message: error.to_string() },
        None => RfError::Sdk(error),
    })
}
