// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical native group links for account opening, dispatch and read-model capture.
use crate::prelude::*;
use ramflux_storage::AccountDb;

pub(crate) fn repair_on_open(db: &AccountDb) -> Result<(), SdkError> {
    let mut after = String::new();
    loop {
        let groups = db.client_directory_ids("group", &after, 100)?;
        let Some(last) = groups.last() else { return Ok(()) };
        for group in &groups {
            if let Some(state) = db.shared_group_state(group)? {
                repair_link(db, group, &state.view().conversation_id)?;
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
