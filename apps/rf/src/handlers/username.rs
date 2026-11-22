// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! User entry point for exact directory reads and a transient, local-only master ceremony.
use crate::{RfError, cli::{UsernameAction, UsernameAuthorize, UsernameCommand}};
use ramflux_sdk::{LocalBusClient, username_directory::{self as directory, UsernameChange, UsernameDraft}};
use std::{io::Read, path::PathBuf, time::{Duration, Instant}};
use zeroize::Zeroizing;

pub(crate) async fn handle(socket: PathBuf, command: UsernameCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        UsernameAction::Resolve(input) => super::print_json(&bus.request(Some(input.account), "username", "username.resolve", serde_json::json!({"name": input.name})).await?),
        UsernameAction::Status(input) => super::print_json(&bus.request(Some(input.account), "username", "username.status", serde_json::json!({"operation_id":input.operation_id})).await?),
        UsernameAction::Set(input) => mutate(&mut bus, input.authorization, UsernameChange::Set { name: input.name }).await,
        UsernameAction::Release(input) => mutate(&mut bus, input, UsernameChange::Release).await,
        UsernameAction::Delete(input) => mutate(&mut bus, input, UsernameChange::Delete).await,
        UsernameAction::Profile(input) => mutate(&mut bus, input.authorization, UsernameChange::Profile { bio: input.bio, display_name: input.display_name }).await,
    }
}

async fn mutate(bus: &mut LocalBusClient, input: UsernameAuthorize, change: UsernameChange) -> Result<(), RfError> {
    let method = if matches!(change, UsernameChange::Profile { .. }) { "profile.update" } else { "username.mutate" };
    let prepared = bus.request(Some(input.account.clone()), "username", method, serde_json::json!({"phase":"prepare", "change": change})).await?;
    let Some(draft) = prepared.get("draft").filter(|value| !value.is_null()) else { return super::print_json(&prepared); };
    let draft: UsernameDraft = serde_json::from_value(draft.clone())?;
    let pin = directory::configured_center()?;
    let words = if let Some(path) = input.recovery_phrase_file {
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 4096 { return Err(RfError::Message("Recovery phrase file must be a small private regular file.".into())); }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(RfError::Message("Recovery phrase file must be owned by this user with mode0600.".into()));
            }
        }
        let mut words = Zeroizing::new(String::new()); file.take(4097).read_to_string(&mut words)?;
        if words.len() > 4096 { return Err(RfError::Message("Recovery phrase file exceeds its limit.".into())); }
        words
    } else { super::account_ceremony::Terminal::open()?.line("Recovery phrase: ", true)? };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| RfError::Message("Clock unavailable.".into()))?.as_secs();
    let signed = directory::authorize_username_draft(words, draft, &pin, &change, now)?;
    let operation_id = signed.operation.body.operation_id.clone();
    let mut status = bus.request(Some(input.account.clone()), "username", method, serde_json::json!({"phase":"submit", "signed":signed})).await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while status.get("state").and_then(serde_json::Value::as_str) == Some("pending") && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(2)).await;
        status = bus.request(Some(input.account.clone()), "username", "username.status", serde_json::json!({"operation_id":operation_id})).await?;
    }
    super::print_json(&status)
}
