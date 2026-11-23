// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary commands wait out another account's in-flight pairing publication.
//!
//! The custody check stays a typed `PublicationPending`. This module only decides
//! whether the command may try again before that refusal is returned. A wait on
//! this account's own marker would hold the actor that has to finish the install.

use std::path::Path;
use std::time::Duration;

use tokio::time::Instant;

use super::actor::{AccountCommand, ActorResponse};
use super::runtime_limits::COMMAND_DEADLINE;
use super::state::LocalBusDaemonState;
use crate::SdkError;

const SCAN_CAP: usize = 128;
const ACCOUNT_ID_MAX: usize = 128;

pub(super) async fn dispatch(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
    command_timeout: Duration,
) -> Result<ActorResponse, SdkError> {
    let deadline = command
        .admission
        .as_ref()
        .map_or_else(|| Instant::now() + command_timeout, |admission| admission.command_deadline);
    super::command_admission::COMMAND_CONTEXT
        .scope(deadline, dispatch_bounded(state, account_id, command, deadline))
        .await
}

async fn dispatch_bounded(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
    deadline: Instant,
) -> Result<ActorResponse, SdkError> {
    if !ordinary(&command.request.method) {
        return attempt(state, account_id, command, deadline).await;
    }
    let wait_deadline = earlier(deadline, Instant::now() + COMMAND_DEADLINE);
    loop {
        let settled = crate::custody::pairing::activate::INSTALL_SETTLED.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        match attempt(state, account_id, command, deadline).await {
            Ok(response) => return Ok(response),
            Err(error) if should_wait(&error, wait_deadline, state, account_id) => {
                if let Err(release_error) = release_pending(state, account_id, command) {
                    tracing::warn!(
                        %release_error,
                        "publication wait left the operation receipt pending"
                    );
                    return Err(error);
                }
                let expired = tokio::time::timeout_at(wait_deadline, settled).await.is_err();
                if expired || Instant::now() >= wait_deadline {
                    return attempt(state, account_id, command, deadline).await;
                }
            }
            Err(error) => return Err(error),
        }
    }
}

async fn attempt(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
    deadline: Instant,
) -> Result<ActorResponse, SdkError> {
    match tokio::time::timeout_at(deadline, super::mutations::execute(state, account_id, command))
        .await
    {
        Ok(result) => result,
        Err(_elapsed) => {
            Err(super::command_admission::unavailable("account command deadline expired"))
        }
    }
}

fn should_wait(
    error: &SdkError,
    wait_deadline: Instant,
    state: &LocalBusDaemonState,
    account_id: &str,
) -> bool {
    publication_pending(error)
        && Instant::now() < wait_deadline
        && other_install_blocks(&state.config.data_root, account_id)
}

fn ordinary(method: &str) -> bool {
    if method.starts_with("account.create")
        || method.starts_with("device.pair")
        || method.starts_with("device.transfer")
    {
        return false;
    }
    method != "account.unlock" && method != "account.backup.import"
}

fn publication_pending(error: &SdkError) -> bool {
    let mut current = error;
    for _ in 0..4 {
        match current {
            SdkError::PairingCode("PublicationPending") => return true,
            SdkError::GroupRefused { source, .. }
            | SdkError::ContactUnavailable(source)
            | SdkError::DirectoryAuthorityUnavailable { source, .. } => current = source,
            _ => return false,
        }
    }
    false
}

fn release_pending(
    state: &LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
) -> Result<(), SdkError> {
    let intent = super::mutation_intent::MutationIntent::new(&command.request)?;
    let Some(key) = intent.key else {
        return Ok(());
    };
    let Some(account) = state.accounts.get(account_id) else {
        return Ok(());
    };
    account.client.account_db()?.release_pending_operation(key)?;
    Ok(())
}

fn other_install_blocks(root: &Path, self_id: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root.join("custody_accounts")) else {
        return false;
    };
    for (seen, entry) in entries.enumerate() {
        if seen == SCAN_CAP {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        if account_blocks(root, self_id, &entry) {
            return true;
        }
    }
    false
}

fn account_blocks(root: &Path, self_id: &str, entry: &std::fs::DirEntry) -> bool {
    let Ok(kind) = entry.file_type() else {
        return false;
    };
    if !kind.is_dir() {
        return false;
    }
    let Ok(name) = entry.file_name().into_string() else {
        return false;
    };
    if name == self_id || !account_name(&name) {
        return false;
    }
    let pending = crate::custody::pairing::install_store::list_pending(root, &name);
    let installed = crate::custody::pairing::install_store::read_installed(root, &name);
    match (pending, installed) {
        (Ok(pending), Ok(installed)) => {
            crate::custody::pairing::install_store::pending_blocks_network(
                &pending,
                installed.as_ref(),
            )
        }
        _ => false,
    }
}

fn account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= ACCOUNT_ID_MAX
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

fn earlier(left: Instant, right: Instant) -> Instant {
    left.min(right)
}
