// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Nested `group.event` values. The envelope is `kind` + `group_id`, except `read`,
//! `post_state` and `post_deleted`.

use serde::Serialize;
use serde_json::{Value, json};

use super::host::b64;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GroupEvent {
    pub kind: String,
    pub group_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_log_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_mentions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_log_seq: Option<u64>,
}

pub(crate) fn post_event(group_id: &[u8; 32], row: Value) -> GroupEvent {
    GroupEvent {
        kind: "post".to_owned(),
        group_id: b64(group_id),
        post: Some(row),
        body: None,
        read_log_seq: None,
        unread: None,
        unread_mentions: None,
        post_id: None,
        state: None,
        params: None,
        log_seq: None,
        post_log_seq: None,
    }
}

pub(crate) fn body_event(kind: &str, group_id: &[u8; 32], body: Value) -> GroupEvent {
    GroupEvent {
        kind: kind.to_owned(),
        group_id: b64(group_id),
        post: None,
        body: Some(body),
        read_log_seq: None,
        unread: None,
        unread_mentions: None,
        post_id: None,
        state: None,
        params: None,
        log_seq: None,
        post_log_seq: None,
    }
}

pub(crate) fn membership_event(
    group_id: &[u8; 32],
    changes: &Value,
    by: Option<&Value>,
) -> GroupEvent {
    body_event("membership", group_id, json!({ "changes": changes, "by": by }))
}

pub(crate) fn settings_event(
    group_id: &[u8; 32],
    name: Option<&str>,
    approval: Option<bool>,
    by: Option<&Value>,
) -> GroupEvent {
    body_event("settings", group_id, json!({ "name": name, "approval": approval, "by": by }))
}

pub(crate) fn void_event(
    group_id: &[u8; 32],
    voided_log_seq: u64,
    epoch: u64,
    by: Option<&Value>,
) -> GroupEvent {
    body_event(
        "void",
        group_id,
        json!({ "voided_log_seq": voided_log_seq, "epoch": epoch, "by": by }),
    )
}

pub(crate) fn read_event(
    group_id: &[u8; 32],
    read_log_seq: u64,
    unread: u64,
    unread_mentions: u64,
) -> GroupEvent {
    GroupEvent {
        kind: "read".to_owned(),
        group_id: b64(group_id),
        post: None,
        body: None,
        read_log_seq: Some(read_log_seq),
        unread: Some(unread),
        unread_mentions: Some(unread_mentions),
        post_id: None,
        state: None,
        params: None,
        log_seq: None,
        post_log_seq: None,
    }
}

pub(crate) fn post_state_event(
    group_id: &[u8; 32],
    post_id: &str,
    state: &str,
    params: Value,
    log_seq: Option<u64>,
) -> GroupEvent {
    GroupEvent {
        kind: "post_state".to_owned(),
        group_id: b64(group_id),
        post: None,
        body: None,
        read_log_seq: None,
        unread: None,
        unread_mentions: None,
        post_id: Some(post_id.to_owned()),
        state: Some(state.to_owned()),
        params: Some(params),
        log_seq,
        post_log_seq: None,
    }
}

pub(crate) fn post_deleted_event(
    group_id: &[u8; 32],
    post_id: &str,
    post_log_seq: u64,
    log_seq: u64,
) -> GroupEvent {
    GroupEvent {
        kind: "post_deleted".to_owned(),
        group_id: b64(group_id),
        post: None,
        body: None,
        read_log_seq: None,
        unread: None,
        unread_mentions: None,
        post_id: Some(post_id.to_owned()),
        state: None,
        params: None,
        log_seq: Some(log_seq),
        post_log_seq: Some(post_log_seq),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_post_nests_the_row() {
        let event = post_event(
            &[9; 32],
            json!({
                "kind": "text",
                "post_id": "p",
                "body": "hello",
                "log_seq": 3
            }),
        );
        let value = serde_json::to_value(&event).expect("test: a post event serializes");
        let post = value.get("post").expect("test: the post row is nested");
        assert_eq!(
            post.get("kind").and_then(Value::as_str),
            Some("text"),
            "test: nested post.kind is the row kind"
        );
        assert!(value.get("body").is_none(), "test: body is not a flat envelope field");
        assert!(value.get("text").is_none(), "test: text is not a flat envelope field");
        assert!(value.get("post_id").is_none(), "test: post_id is not a flat envelope field");
        assert_eq!(
            value.get("kind").and_then(Value::as_str),
            Some("post"),
            "test: the envelope kind stays post"
        );
    }
}
