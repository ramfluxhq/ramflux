// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded post-receipt attachment work using K12's durable fetch receipts and chunk cache.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Default, Deserialize, Serialize)]
struct Attempt {
    attempts: u32,
    next_at: i64,
}

pub(super) fn next(account: &LocalBusAccountState) -> Result<Option<String>, SdkError> {
    if std::env::var("RAMFLUX_SYNC_ATTACHMENT_PREFETCH").as_deref() == Ok("0") {
        return Ok(None);
    }
    Ok(account.client.account_db()?.pending_received_attachment_ids(now_unix_timestamp(), 1)?.pop())
}
pub(super) fn started(account: &LocalBusAccountState, id: &str) -> Result<(), SdkError> {
    let key = format!("sync/attachment/{id}");
    let mut attempt =
        account.client.account_db()?.load_actor_state::<Attempt>(&key)?.unwrap_or_default();
    attempt.attempts = attempt.attempts.saturating_add(1);
    attempt.next_at = now_unix_timestamp().saturating_add(2_i64.saturating_pow(attempt.attempts));
    Ok(account.client.account_db()?.persist_actor_state(&key, &attempt)?)
}

async fn fetch_until(
    account: &mut LocalBusAccountState,
    id: &str,
    deadline: tokio::time::Instant,
) -> Result<serde_json::Value, SdkError> {
    let operation = format!(
        "sync-fetch:{}",
        ramflux_crypto::blake3_256_base64url("ramflux.sync.attachment.v1", id.as_bytes())
    );
    let request = LocalBusFrame::request(
        "background-fetch",
        None,
        "object",
        "object.fetch",
        serde_json::json!({"object_id":id,"operation_id":operation}),
    );
    Ok(super::dispatch::deferred_attachment::dispatch_until(account, &request, Some(deadline))
        .await?
        .response_body)
}

pub(super) async fn fetch_for_page(
    account: &mut LocalBusAccountState,
    conversation: Option<&str>,
    limit: usize,
) -> Result<(), SdkError> {
    let mut ids = BTreeSet::new();
    let mut selected = 0;
    for entry in &account.pending_deliveries {
        if selected >= limit.min(64) {
            break;
        }
        let Some((thread, message)) = account.client.committed_direct_context(entry)? else {
            continue;
        };
        if conversation.is_some_and(|requested| requested != thread) {
            continue;
        }
        selected += 1;
        ids.extend(account.client.account_db()?.client_message_object_ids(&message)?);
    }
    let deadline =
        tokio::time::Instant::now() + super::runtime_limits::RuntimeTimeouts::default().fetch;
    for id in ids {
        let result = fetch_until(account, &id, deadline).await?;
        ensure_page_attachment_available(&result)?;
    }
    Ok(())
}

pub(super) fn ensure_page_attachment_available(
    receipt: &serde_json::Value,
) -> Result<(), SdkError> {
    if receipt["transfer_state"] == "available" {
        return Ok(());
    }
    if receipt["retryable"] == false && receipt["last_error"] == crate::error::ATTACHMENT_DELETED {
        return Err(SdkError::AttachmentDeleted);
    }
    Err(SdkError::LocalBus(
        receipt["last_error"]
            .as_str()
            .unwrap_or("attachment fetch failed; retry object.fetch")
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    #[test]
    fn background_selection_is_bounded_and_honors_retry_limit_and_backoff() -> Result<(), SdkError>
    {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("ramflux-attachment-scheduler-{}-{suffix}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("a", "commitment")?;
        client.unlock_account("a", b"secret")?;
        let db = client.account_db()?;
        for id in ["a", "b", "c"] {
            db.persist_actor_state(
                &format!("attachment/reference/{id}"),
                &serde_json::json!({"private":"never selected"}),
            )?;
        }
        assert_eq!(db.pending_received_attachment_ids(10, 1)?, vec!["a"]);
        db.persist_actor_state(
            "sync/attachment/a",
            &serde_json::json!({"attempts":3,"next_at":0}),
        )?;
        db.persist_actor_state(
            "sync/attachment/b",
            &serde_json::json!({"attempts":1,"next_at":20}),
        )?;
        db.persist_actor_state(
            "attachment/fetch/c",
            &serde_json::json!({"transfer_state":"available"}),
        )?;
        assert_eq!(db.pending_received_attachment_ids(10, 64)?.len(), 0);
        assert_eq!(db.pending_received_attachment_ids(20, 64)?, vec!["b"]);
        drop(client);
        Ok(())
    }
}
