// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for legacy DM/A2I (S6b P15). No production caller reaches it: the live
//! `receive_legacy_entry` / `receive_bound_legacy_a2i` paths are unchanged. The expectation
//! values come from the caller; P20 supplies them.
//!
//! Contract: W0 (`stage`) precedes the irreversible effect; ratchet, content/rejection/receipt
//! and the authenticated dedup marker run inside one generation, incarnation, cursor and
//! erase-fenced receive transaction. Cursor and ACK are not embedded (ledger WA). Attachment
//! and auth reads stay outside the transaction. Group holds remain held. Never persist
//! plaintext to make a step resumable.
#![allow(dead_code)]

#[cfg(test)]
use crate::client::a2i::LegacyControlReceipt;
#[cfg(test)]
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};

pub(crate) struct LegacyW1<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl LegacyW1<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Runs the irreversible effect and optional logical-message bind inside one receive
    /// transaction. A missing recovery input refuses before the effect.
    pub(crate) fn effect<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        message: Option<&str>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            tx.require_open_input(sequence)?;
            let result = effect();
            let failed = result.is_err();
            outcome = Some(result);
            if failed {
                return Err(StorageError::Integrity("legacy effect failed"));
            }
            if let Some(message) = message {
                match tx.bind_logical_message(sequence, message)? {
                    ReceiveBind::Bound | ReceiveBind::Erased => {}
                }
            }
            before_commit_fault()?;
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("legacy effect did not run".into())),
        }
    }
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("legacy w1 before-commit"));
    }
    Ok(())
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

/// In-transaction fault injected by tests. Production always uses `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    BeforeCommit,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: Fault, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|cell| cell.set(Fault::None));
        }
    }
    FAULT.with(|cell| cell.set(fault));
    let _reset = Reset;
    f()
}

impl RamfluxClient {
    #[cfg(test)]
    fn w1_gate<'a>(db: &'a AccountDb, target: &'a str) -> Result<LegacyW1<'a>, SdkError> {
        Ok(LegacyW1 {
            expected: ReceiveExpectation {
                target,
                incarnation: "e",
                cursor: 0,
                generation: 1,
                erasure_generation: db.privacy_erasure_generation()?,
            },
            generation: 1,
        })
    }

    /// Test-only: decrypt a bound legacy DM and commit content+ratchet+marker through W1.
    #[cfg(test)]
    pub(crate) fn apply_legacy_success_w1(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        let (_, session, decrypted) = self.decrypt_legacy_entry(conversation, entry)?;
        let db = self.account_db()?;
        let gate = Self::w1_gate(db, &entry.target_delivery_id)?;
        let sequence = entry.inbox_seq;
        let message = entry.envelope.envelope_id.clone();
        let principal =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id.clone();
        gate.effect(db, sequence, Some(&message), || {
            self.append_plaintext_projection_once(
                conversation,
                &message,
                entry,
                &decrypted.plaintext,
                None,
            )?;
            if db.client_record("conversation", conversation)?.is_none() {
                db.persist_client_record(
                    "conversation",
                    conversation,
                    &serde_json::json!({
                        "kind": "direct",
                        "title": null,
                        "group_id": null,
                        "participants": [principal, entry.envelope.source_principal_id],
                        "direct_route": null
                    }),
                )?;
            }
            self.commit_legacy_effect(conversation, entry, &session)
        })
    }

    /// Test-only: peer-rejection cut — reject row + ratchet + marker, no cursor.
    #[cfg(test)]
    pub(crate) fn apply_legacy_reject_w1(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if self.legacy_w1_committed(entry)? {
            return Ok(());
        }
        let (_, session, _) = self.decrypt_legacy_entry(conversation, entry)?;
        let reason = self
            .friend_rejection_reason(&entry.envelope.source_principal_id)?
            .ok_or_else(|| SdkError::LocalBus("legacy reject has no friend rejection".into()))?;
        let db = self.account_db()?;
        let gate = Self::w1_gate(db, &entry.target_delivery_id)?;
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || {
            db.reject_inbox_message(
                conversation,
                &entry.envelope.envelope_id,
                &entry.envelope.source_principal_id,
                &reason,
                now_unix_timestamp(),
            )?;
            self.commit_legacy_effect(conversation, entry, &session)
        })
    }

    /// Test-only: A2I ratchet + receipt + event, no ACK and no cursor.
    #[cfg(test)]
    pub(crate) fn apply_legacy_a2i_w1(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        if self.legacy_a2i_committed(entry)? {
            return Ok(());
        }
        let owned = self.owned_device_identity()?;
        let conversation =
            a2i_control_conversation_id(&entry.envelope.source_device_id, owned.device_id());
        let ciphertext_bytes = ramflux_protocol::decode_base64url(
            &entry.envelope.encrypted_payload,
        )
        .map_err(|error| SdkError::LocalBus(format!("invalid A2I encrypted payload: {error}")))?;
        let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&ciphertext_bytes)?;
        let mut session =
            self.load_or_create_recv_dm_session(&conversation, envelope.x3dh.as_ref())?;
        let body = session.decrypt(&envelope.ciphertext, dm_associated_data(&conversation))?;
        let mut event: ramflux_sync::A2iControlEvent = serde_json::from_slice(&body)?;
        let source = self.bind_received_a2i_event(&mut event, entry)?;
        let receipt_key = format!(
            "legacy/a2i/{}",
            self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?
        );
        let db = self.account_db()?;
        let gate = Self::w1_gate(db, &entry.target_delivery_id)?;
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || {
            self.append_gateway_delivery(entry)?;
            db.persist_actor_state(
                &receipt_key,
                &LegacyControlReceipt {
                    event: event.clone(),
                    payload_hash: entry.envelope.payload_hash.clone(),
                },
            )?;
            self.persist_dm_session(&conversation, &entry.envelope.envelope_id, "recv", &session)?;
            db.persist_actor_state(
                &crate::client::routed::control::a2i_key(&source, &event.event_id)?,
                &event,
            )?;
            Ok(())
        })
    }

    /// Test-only: group local apply that cannot complete stays held; no terminal marker.
    #[cfg(test)]
    pub(crate) fn apply_legacy_group_hold_w1(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let gate = Self::w1_gate(db, &entry.target_delivery_id)?;
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || {
            db.hold_unrouted(
                &entry.envelope.envelope_id,
                entry.inbox_seq,
                &serde_json::to_vec(entry)?,
                now_unix_timestamp(),
            )?;
            Ok(())
        })
    }

    #[cfg(test)]
    fn legacy_w1_committed(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        Ok(self.account_db()?.actor_state_exists(&self.legacy_committed_key(entry)?)?)
    }

    #[cfg(test)]
    fn legacy_a2i_committed(&self, entry: &GatewayInboxEntry) -> Result<bool, SdkError> {
        let key = format!(
            "legacy/a2i/{}",
            self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?
        );
        Ok(self.account_db()?.actor_state_exists(&key)?)
    }
}
