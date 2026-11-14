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
    client.account_db()?.retain_expiring_actor_states(PREFIX, now, LIMIT)?;
    client.account_db()?.retain_expiring_actor_states("conversation-send/", now, LIMIT)?;
    client.account_db()?.retain_expiring_actor_states("conversation-intent/", now, LIMIT)?;
    Ok(())
}
pub(crate) fn capacity(client: &RamfluxClient, prefix: &str) -> Result<(), SdkError> {
    if client.account_db()?.actor_state_usage(prefix)?.0 >= u64::from(LIMIT) {
        return Err(AdapterError::new(Code::RateLimited, "operation retention capacity").into());
    }
    Ok(())
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
    save(client, key, &receipt)
}
