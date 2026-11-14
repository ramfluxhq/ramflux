// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, expiring, content-free operation reconciliation, independent of payload erasure.
use crate::bindings::{AdapterError, GeneratedErrorCode as Code};
use crate::prelude::*;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

pub(crate) const PREFIX: &str = "conversation-operation/";
pub(crate) const LIMIT: u32 = 1024;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub fingerprint: String,
    pub identity: g::EventIdentity,
    pub accepted: BTreeSet<String>,
    pub terminal: Option<serde_json::Value>,
    pub expires_at: i64,
    #[serde(default)]
    pub completed_at: Option<i64>,
}
pub(crate) fn key(operation: &str) -> String {
    format!(
        "{PREFIX}{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.operation.v1",
            operation.as_bytes()
        )
    )
}
pub(crate) fn prune(client: &RamfluxClient, now: i64) -> Result<(), SdkError> {
    client.account_db()?.expire_actor_states(PREFIX, now)?;
    client.account_db()?.expire_actor_states("conversation-send/", now)?;
    client.account_db()?.expire_actor_states("conversation-intent/", now)?;
    Ok(())
}
pub(crate) fn capacity(client: &RamfluxClient, prefix: &str) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let count = db.actor_state_usage(prefix)?.0;
    if count < u64::from(LIMIT) {
        return Ok(());
    }
    // The namespace invariant bounds this scan. Never trim pending operations to make space.
    if count == u64::from(LIMIT) {
        let mut oldest: Option<(i64, String)> = None;
        for key in db.actor_state_key_page(prefix, LIMIT)? {
            let Some(row) = db.load_actor_state::<serde_json::Value>(&key)? else { continue };
            let terminal = row.get("terminal").is_some_and(|v| !v.is_null())
                || row.get("completed").and_then(serde_json::Value::as_bool) == Some(true);
            if terminal {
                let time = row
                    .get("completed_at")
                    .and_then(serde_json::Value::as_i64)
                    .or_else(|| row.get("expires_at").and_then(serde_json::Value::as_i64))
                    .unwrap_or(i64::MAX);
                let candidate = (time, key);
                if oldest.as_ref().is_none_or(|old| &candidate < old) {
                    oldest = Some(candidate);
                }
            }
        }
        if let Some((_, key)) = oldest {
            db.remove_actor_state(&key)?;
            if let Some(suffix) = key.strip_prefix(PREFIX) {
                db.remove_actor_state(&format!("conversation-intent/{suffix}"))?;
            }
            return Ok(());
        }
    }
    Err(AdapterError::new(Code::RateLimited, "operation retention capacity").into())
}

pub(crate) fn expiry(client: &RamfluxClient, now: i64) -> Result<i64, SdkError> {
    Ok(now.saturating_add(i64::from(client.content_ttl()?)))
}
pub(crate) fn load(client: &RamfluxClient, key: &str) -> Result<Option<Receipt>, SdkError> {
    Ok(client.account_db()?.load_actor_state(key)?)
}
pub(crate) fn save(client: &RamfluxClient, key: &str, value: &Receipt) -> Result<(), SdkError> {
    client.account_db()?.persist_actor_state(key, value)?;
    Ok(())
}
pub(crate) fn terminal(
    client: &RamfluxClient,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), SdkError> {
    let mut receipt = load(client, key)?
        .ok_or_else(|| AdapterError::new(Code::Internal, "operation receipt absent"))?;
    receipt.terminal = Some(value.clone());
    receipt.completed_at = Some(now_unix_timestamp());
    save(client, key, &receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mutation_capacity_evicts_only_oldest_terminal_and_its_private_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let account = crate::bus::runtime_tests::account(
            root.path(),
            "mutation-capacity",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let db = account.client.account_db()?;
        let now = now_unix_timestamp();
        db.write_transaction(|| {
            for n in 0..LIMIT {
                db.persist_actor_state(
                    &format!("{PREFIX}{n:04}"),
                    &json!({"expires_at":now+3600,"terminal":null}),
                )?;
            }
            Ok::<_, SdkError>(())
        })?;
        let error = capacity(&account.client, PREFIX).expect_err("test: all receipts pending");
        assert_eq!(
            AdapterError::from_sdk(&error).code,
            Code::RateLimited as i32,
            "pending mutation windows refuse admission"
        );
        for (n, age) in [(1, 2), (2, 1)] {
            db.persist_actor_state(
                &format!("{PREFIX}{n:04}"),
                &json!({"expires_at":now+3600,"terminal":{"code":0},"completed_at":now-age}),
            )?;
        }
        db.persist_actor_state("conversation-intent/0001", &json!({"expires_at":now+3600}))?;
        db.write_transaction(|| capacity(&account.client, PREFIX))?;
        assert!(!db.actor_state_exists("conversation-operation/0001")?, "oldest terminal evicted");
        assert!(
            !db.actor_state_exists("conversation-intent/0001")?,
            "orphan private intent removed"
        );
        assert!(db.actor_state_exists("conversation-operation/0002")?, "newer terminal retained");
        assert!(db.actor_state_exists("conversation-operation/0000")?, "pending receipt retained");
        assert_eq!(db.actor_state_usage(PREFIX)?.0, 1023, "exactly one admission credit restored");
        Ok(())
    }
}
