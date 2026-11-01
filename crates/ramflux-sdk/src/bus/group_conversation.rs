// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The signed native group thread is shared by dispatch and read-model capture.
use crate::prelude::*;

pub(crate) fn resolve(
    client: &RamfluxClient,
    group: &str,
    requested: &str,
) -> Result<String, SdkError> {
    if client.born_v3_account.is_some()
        && let Some(state) = client.account_db()?.shared_group_state(group)?
    {
        let conversation = &state.view().conversation_id;
        let db = client.account_db()?;
        let mut link = db.client_record("group", group)?.unwrap_or_else(|| serde_json::json!({}));
        // Earlier CLI reads could leave several cached aliases and disable the single-thread
        // binding. Native shared state signs exactly one thread; repair only this derived link,
        // retaining unrelated metadata and all existing conversation/history records.
        let expected = serde_json::json!([conversation]);
        if link["conversation_id"] != *conversation || link["conversation_ids"] != expected {
            link["conversation_id"] = serde_json::json!(conversation);
            link["conversation_ids"] = expected;
            db.persist_client_record("group", group, &link)?;
        }
        return Ok(conversation.clone());
    }
    Ok(requested.to_owned())
}
