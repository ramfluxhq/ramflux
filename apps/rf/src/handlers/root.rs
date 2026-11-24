// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf root snapshot` and `rf root commit` for one shared data root.
#![allow(clippy::wildcard_imports)]
use super::*;
use ramflux_sdk::custody::PrimaryVault;
use ramflux_sdk::{DirectMessageCommit, commit_direct_message, read_committed_snapshot};
use std::sync::Arc;

pub(crate) fn handle(command: &RootCommand) -> Result<(), RfError> {
    match &command.action {
        RootAction::Snapshot(snapshot) => read_snapshot(snapshot),
        RootAction::Commit(commit) => write_commit(commit),
    }
}

fn read_snapshot(snapshot: &RootSnapshot) -> Result<(), RfError> {
    let vault = root_vault(
        &snapshot.data_root,
        #[cfg(feature = "itest-memory-vault")]
        snapshot.itest_memory_vault,
    )?;
    let read = read_committed_snapshot(&snapshot.data_root, &snapshot.account, vault.as_ref());
    print_json(&serde_json::to_value(map_shared(read)?)?)
}

fn write_commit(commit: &RootCommit) -> Result<(), RfError> {
    let vault = root_vault(
        &commit.data_root,
        #[cfg(feature = "itest-memory-vault")]
        commit.itest_memory_vault,
    )?;
    let wrote = commit_direct_message(
        &commit.data_root,
        &commit.account,
        vault.as_ref(),
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

fn root_vault(
    root: &std::path::Path,
    #[cfg(feature = "itest-memory-vault")] fixture: bool,
) -> Result<Arc<dyn PrimaryVault>, RfError> {
    let config = LocalBusConfig::new(root.join("unused.sock"), root);
    #[cfg(feature = "itest-memory-vault")]
    let config = {
        let mut config = config;
        if fixture {
            config.custody_vault =
                Some(Arc::new(ramflux_sdk::custody::MemoryPrimaryVault::persist_at(
                    root.join("itest-memory-vault.json"),
                )?));
        }
        config
    };
    Ok(ramflux_sdk::shared_root_vault(&config))
}

fn map_shared<T>(result: Result<T, ramflux_sdk::SdkError>) -> Result<T, RfError> {
    result.map_err(|error| match ramflux_sdk::shared_root_refusal(&error) {
        Some(code) => RfError::Refused { code, message: error.to_string() },
        None => RfError::Sdk(error),
    })
}
