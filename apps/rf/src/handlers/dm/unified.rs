// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unified message read model for `rf dm list` and `rf dm read`.
//!
//! Dormant until message schema v1 is the active storage generation. Output is the contract in
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

impl Query {
    fn has_read_model_flag(&self) -> bool {
        self.limit.is_some()
            || self.before.is_some()
            || self.after_seq.is_some()
            || self.message.is_some()
    }
}

/// True when the unified path serves this command. Read-model flags are refused while dormant.
pub(super) fn selected(query: &Query) -> Result<bool, RfError> {
    if ramflux_protocol::schema_profile::schema_v1_live() {
        return Ok(true);
    }
    if query.has_read_model_flag() {
        return Err(RfError::Message(
            "--limit, --before, --after-seq and --message require message schema v1".to_owned(),
        ));
    }
    Ok(false)
}

/// Request body of the durable reader. Exactly one of page, change batch or single message.
pub(super) fn request_body(query: &Query) -> Result<serde_json::Value, RfError> {
    let mut body = serde_json::json!({ "conversation_id": query.conversation });
    if let Some(limit) = query.limit {
        body["limit"] = serde_json::json!(limit);
    }
    if let Some(message) = query.message.as_deref() {
        if query.before.is_some() || query.after_seq.is_some() {
            return Err(RfError::Message(
                "--message excludes --before and --after-seq".to_owned(),
            ));
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
pub(super) async fn print(
    bus: &mut LocalBusClient,
    query: &Query,
    sync: bool,
) -> Result<(), RfError> {
    let body = request_body(query)?;
    if sync {
        bus.request(
            Some(query.account.clone()),
            "message",
            "message.receive",
            serde_json::json!({
                "limit": 100,
                "conversation_id": query.conversation,
                "auto_fetch_attachments": false,
            }),
        )
        .await?;
    }
    print_json(&bus.request(Some(query.account.clone()), "message", "message.read", body).await?)
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
    fn dormant_generation_keeps_the_existing_output_and_refuses_read_model_flags() {
        assert!(matches!(selected(&query()), Ok(false)));
        let mut flagged = query();
        flagged.after_seq = Some(4);
        assert!(selected(&flagged).is_err());
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
