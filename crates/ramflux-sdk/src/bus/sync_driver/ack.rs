// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inbox ACK transport follows the local commit and returns only local cursor checkpoints.

use super::{advance_cursor, retain_ack_retry};
use crate::prelude::*;

pub(crate) struct AckState {
    pub(crate) entry: GatewayInboxEntry,
    pub(crate) key: String,
    pub(crate) already_seen: bool,
    pub(crate) strip_call_ciphertext: bool,
    pub(crate) accepted: bool,
    pub(crate) received_at: i64,
}
pub(crate) struct PreparedAck {
    pub ack: ramflux_protocol::Ack,
    pub state: AckState,
    pub pair_reply: Option<ramflux_protocol::Envelope>,
}
pub(super) fn stage(
    account: &LocalBusAccountState,
    state: AckState,
) -> Result<PreparedAck, SdkError> {
    account.client.account_db()?.refuse_legacy_receive()?;
    let receiver = account.client.owned_device_identity()?;
    if account.gateway_config.source_identity.as_ref() != Some(&receiver)
        || state.entry.target_delivery_id != account.target_delivery_id
    {
        return Err(SdkError::InboundRejected("ACK mailbox identity mismatch".into()));
    }
    // Retain before yielding so an erasure during the exchange can remove the retry.
    // A late transport failure must never recreate that deleted retry row.
    if !state.already_seen || account.client.account_db()?.has_inbox_retry(&state.key)? {
        retain_ack_retry(
            &account.client,
            &state.entry,
            state.strip_call_ciphertext,
            &state.key,
            state.received_at,
        )?;
    }
    let mut ack =
        crate::dm::gateway_ack(&state.entry.envelope.envelope_id, &receiver, state.received_at);
    ack.ext.ext.insert("inbox_seq".into(), serde_json::json!(state.entry.inbox_seq));
    Ok(PreparedAck { ack, state, pair_reply: None })
}
pub(crate) fn finish(
    account: &LocalBusAccountState,
    state: &AckState,
    cursor: Result<GatewayCursor, SdkError>,
    backpressure: &mut super::super::contact_backpressure::Backpressure,
) -> Result<bool, SdkError> {
    account.client.account_db()?.refuse_legacy_receive()?;
    let db = account.client.account_db()?;
    let cursor = cursor?;
    #[cfg(test)]
    let started = std::time::Instant::now();
    db.write_transaction(|| {
        account.client.persist_gateway_cursor(&cursor.target_delivery_id, cursor.inbox_seq)?;
        backpressure.completed(&account.client, &state.entry)?;
        db.remove_inbox_retry(&state.key)?;
        db.remove_unrouted(&state.key)?;
        db.remove_unrouted(&state.entry.envelope.envelope_id)?;
        advance_cursor(&account.client, &account.target_delivery_id, state.entry.inbox_seq)
    })?;
    #[cfg(test)]
    if let Some(handle) = &account.connection {
        handle.test_record_receive("ack-checkpoint", started.elapsed());
    }
    Ok(state.accepted)
}
