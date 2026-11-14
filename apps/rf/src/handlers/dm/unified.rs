// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unified message read model for `rf dm list` and `rf dm read`.
//!
//! Message schema v1 reads use the durable typed projection. Output is the contract in
//! `docs/unified_message_read_model.md`, read from the durable store through `message.read`.
//! The in-memory delivery page of `message.receive` is never printed on this path.
use super::*;

pub(super) struct Query {
    pub(super) account: String,
    pub(super) conversation: String,
    pub(super) limit: Option<u32>,
    pub(super) before: Option<String>,
    pub(super) after_seq: Option<u64>,
    pub(super) message: Option<String>,
}

impl Query {}

/// Request body of the durable reader. Exactly one of page, change batch or single message.
pub(super) fn request_body(query: &Query) -> Result<serde_json::Value, RfError> {
    let mut body = serde_json::json!({ "conversation_id": query.conversation });
    if let Some(limit) = query.limit {
        body["limit"] = serde_json::json!(limit);
    }
    if let Some(message) = query.message.as_deref() {
        if query.before.is_some() || query.after_seq.is_some() {
            return Err(RfError::Message("--message excludes --before and --after-seq".to_owned()));
        }
        body["message_id"] = serde_json::json!(message);
        return Ok(body);
    }
    if let Some(after) = query.after_seq {
        if query.before.is_some() {
            return Err(RfError::Message("--after-seq excludes --before".to_owned()));
        }
        body["after_sequence"] = serde_json::json!(after);
        return Ok(body);
    }
    if let Some(before) = query.before.as_deref() {
        body["before_order_key"] = serde_json::from_str(before)?;
    }
    body["read_model"] = serde_json::json!(true);
    Ok(body)
}

/// Print one read-model response. `sync` first asks the daemon to pull and commit deliveries;
/// its response page is discarded because only the durable store is authoritative.
pub(super) async fn read(
    bus: &mut LocalBusClient,
    query: &Query,
    sync: bool,
) -> Result<serde_json::Value, RfError> {
    let body = request_body(query)?;
    if sync {
        bus.request(
            Some(query.account.clone()),
            "message",
            "message.receive",
            serde_json::json!({
                "limit": 100,
                "conversation_id": query.conversation,
                "auto_fetch_attachments": true,
            }),
        )
        .await?;
    }
    Ok(bus.request(Some(query.account.clone()), "message", "message.read", body).await?)
}

/// `rf group read` on the unified path: sync the group through the daemon, then print the
/// durable read-model page of its conversation. Returns false while the generation is dormant.
pub(crate) async fn print_group_read(
    bus: &mut LocalBusClient,
    account: &str,
    group: &str,
    conversation: &str,
) -> Result<(), RfError> {
    bus.request(
        Some(account.to_owned()),
        "group",
        "group.read",
        serde_json::json!({ "group_id": group, "conversation_id": conversation, "limit": 100 }),
    )
    .await?;
    let query = Query {
        account: account.to_owned(),
        conversation: conversation.to_owned(),
        limit: None,
        before: None,
        after_seq: None,
        message: None,
    };
    print(bus, &query, false).await?;
    Ok(())
}

pub(super) async fn print(
    bus: &mut LocalBusClient,
    query: &Query,
    sync: bool,
) -> Result<(), RfError> {
    print_json(&read(bus, query, sync).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Query {
        Query {
            account: "account".to_owned(),
            conversation: "conversation".to_owned(),
            limit: None,
            before: None,
            after_seq: None,
            message: None,
        }
    }

    #[test]
    fn single_message_refuses_conflicting_cursors() {
        let mut invalid = query();
        invalid.message = Some("message".into());
        invalid.before = Some("{}".into());
        assert!(
            request_body(&invalid).is_err(),
            "single-message requests must refuse page cursors"
        );
        invalid.before = None;
        invalid.after_seq = Some(1);
        assert!(
            request_body(&invalid).is_err(),
            "single-message requests must refuse change cursors"
        );
    }

    #[test]
    fn request_selects_exactly_one_read_model_shape() -> Result<(), RfError> {
        let page = request_body(&query())?;
        assert_eq!(page["read_model"], true);
        assert!(page.get("after_sequence").is_none() && page.get("message_id").is_none());

        let mut changes = query();
        changes.after_seq = Some(0);
        changes.limit = Some(7);
        let body = request_body(&changes)?;
        assert_eq!(body["after_sequence"], 0);
        assert_eq!(body["limit"], 7);
        assert!(body.get("read_model").is_none());

        let mut single = query();
        single.message = Some("id".to_owned());
        let body = request_body(&single)?;
        assert_eq!(body["message_id"], "id");
        assert!(body.get("read_model").is_none());

        single.after_seq = Some(1);
        assert!(request_body(&single).is_err());
        changes.before = Some("{}".to_owned());
        assert!(request_body(&changes).is_err());
        Ok(())
    }
}
