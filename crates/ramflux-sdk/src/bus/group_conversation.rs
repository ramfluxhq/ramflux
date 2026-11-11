// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical native group links for account opening, dispatch and read-model capture.
use crate::prelude::*;
use ramflux_storage::AccountDb;

/// Repair saved links independently; per-group errors warn and leave that group unchanged.
/// Directory-list errors remain fatal because the remaining groups cannot be enumerated.
pub(crate) fn repair_on_open(db: &AccountDb) -> Result<(), SdkError> {
    let mut after = String::new();
    loop {
        let groups = db.client_directory_ids("group", &after, 100)?;
        let Some(last) = groups.last() else { return Ok(()) };
        for group in &groups {
            let repaired = db.shared_group_state(group).map_err(SdkError::from).and_then(|state| {
                state.map_or(Ok(()), |state| repair_link(db, group, &state.view().conversation_id))
            });
            if let Err(error) = repaired {
                let error_class = match error {
                    SdkError::Storage(StorageError::Serde(_)) => "record_decode",
                    SdkError::Storage(StorageError::Crypto(_) | StorageError::Protocol(_)) => {
                        "state_verification"
                    }
                    _ => "storage",
                };
                tracing::warn!(
                    group_id = %group,
                    error_class,
                    "native group link startup repair skipped"
                );
            }
        }
        after.clone_from(last);
    }
}

pub(crate) fn resolve(
    client: &RamfluxClient,
    group: &str,
    requested: &str,
) -> Result<String, SdkError> {
    ramflux_protocol::message::dm_scope::validate_group(requested)
        .map_err(|_| SdkError::InboundRejected("reserved DM conversation namespace".into()))?;
    if client.born_v3_account.is_some()
        && let Some(state) = client.account_db()?.shared_group_state(group)?
    {
        let conversation = &state.view().conversation_id;
        repair_link(client.account_db()?, group, conversation)?;
        return Ok(conversation.clone());
    }
    Ok(requested.to_owned())
}

fn repair_link(db: &AccountDb, group: &str, conversation: &str) -> Result<(), SdkError> {
    ramflux_protocol::message::dm_scope::validate_group(conversation)
        .map_err(|_| SdkError::InboundRejected("reserved DM conversation namespace".into()))?;
    let mut link = db.client_record("group", group)?.unwrap_or_else(|| serde_json::json!({}));
    // Earlier CLI reads could leave aliases that disable the single-thread binding. Repair
    // only this derived link, retaining unrelated metadata and all conversation/history rows.
    let expected = serde_json::json!([conversation]);
    if link["conversation_id"] != conversation || link["conversation_ids"] != expected {
        link["conversation_id"] = serde_json::json!(conversation);
        link["conversation_ids"] = expected;
        db.persist_client_record("group", group, &link)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
