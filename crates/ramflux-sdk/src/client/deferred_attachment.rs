// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-encrypted attachment references, retry receipts and resumable chunk cache.
use super::object::DeferredObjectKeySlot;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ops::AsyncFnOnce;
use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CIPHER_BYTES: u64 = 16 * 1024 * 1024 + 16;

// Deliberately not Debug: the reference contains a grant and encrypted content-key slot.
#[derive(Serialize, Deserialize)]
struct ReceivedAttachment {
    reference: SdkDmAttachmentRef,
    #[serde(default)]
    prepared_slot: Option<PreparedSlot>,
}

#[derive(Serialize, Deserialize)]
struct PreparedSlot {
    object_key: [u8; 32],
    session: ramflux_crypto::DmSessionSnapshot,
    conversation_id: String,
    commit_label: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct FetchState {
    object_id: String,
    operation_id: String,
    transfer_state: String,
    last_error: Option<String>,
    attempts: u32,
}

impl RamfluxClient {
    /// Persist before the message's receive checkpoint, without contacting any relay.
    pub(crate) fn persist_received_attachment_reference(
        &self,
        reference: &SdkDmAttachmentRef,
        owner: &str,
        conversation: &str,
        message: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = reference_key(&reference.object_id);
        if db.load_actor_state::<ReceivedAttachment>(&key)?.is_some() {
            // Replayed receipt must not replace access material or reset a failed/complete fetch.
            return Ok(());
        }
        // Extract the content key while receive-time private prekeys are available, without
        // advancing its durable slot checkpoint. A bad slot must not block message receipt.
        let prepared_slot =
            self.decrypt_object_key_slot(&reference.key_slot).ok().map(|slot| PreparedSlot {
                object_key: slot.object_key,
                session: slot.session.snapshot(),
                conversation_id: slot.conversation_id,
                commit_label: slot.commit_label,
            });
        let metadata = json!({
            "name":null,"mime":null,"size":reference.cipher_size.checked_sub(16),
            "direction":"incoming","owner":owner,"conversation_id":conversation,
            "message_id":message,"relay_endpoint":reference.relay_endpoint,
            "manifest_hash":reference.manifest_hash,"plaintext_hash":reference.plaintext_hash,
        });
        db.persist_actor_state_batch(&[
            (key, json!(ReceivedAttachment { reference: reference.clone(), prepared_slot })),
            (format!("directory/object/{}", reference.object_id), metadata),
        ])?;
        Ok(())
    }

    /// Fetches one durably received reference. Failed attempts can reuse the same operation id;
    /// successful operations replay their compact receipt without touching the relay.
    ///
    /// # Errors
    /// Returns an error for invalid identifiers, operation reuse or unavailable account storage.
    /// Transfer errors are returned as a retryable `failed` receipt with no access material.
    pub async fn fetch_received_attachment(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        operation_id: &str,
    ) -> Result<Value, SdkError> {
        self.fetch_received_with(
            object_id,
            operation_id,
            FETCH_TIMEOUT,
            async |client, reference| {
                client
                    .import_dm_attachment_from_relay_via_gateway(engine, pool, reference, None)
                    .await?;
                Ok(())
            },
        )
        .await
    }

    pub(crate) fn received_attachment_receipt(
        &self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<Option<Value>, SdkError> {
        validate_id(object_id)?;
        validate_id(operation_id)?;
        let old: Option<FetchState> =
            self.account_db()?.load_actor_state(&format!("attachment/operation/{operation_id}"))?;
        if let Some(old) = old {
            if old.object_id != object_id {
                return Err(SdkError::LocalBus("attachment operation_id already bound".to_owned()));
            }
            if old.transfer_state == "available" {
                return Ok(Some(public_receipt(&old)));
            }
        }
        Ok(None)
    }

    pub(crate) async fn fail_received_attachment_fetch(
        &mut self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<Value, SdkError> {
        self.fetch_received_with(
            object_id,
            operation_id,
            FETCH_TIMEOUT,
            async |_client, _reference| Err(SdkError::GatewaySessionNotEstablished),
        )
        .await
    }

    async fn fetch_received_with<F>(
        &mut self,
        object_id: &str,
        operation_id: &str,
        timeout: Duration,
        fetch: F,
    ) -> Result<Value, SdkError>
    where
        F: for<'a> AsyncFnOnce(&'a mut Self, &'a SdkDmAttachmentRef) -> Result<(), SdkError>,
    {
        if let Some(receipt) = self.received_attachment_receipt(object_id, operation_id)? {
            return Ok(receipt);
        }
        let stored: ReceivedAttachment =
            self.account_db()?.load_actor_state(&reference_key(object_id))?.ok_or_else(|| {
                SdkError::LocalBus("received attachment reference not found".to_owned())
            })?;
        let previous = self.attachment_fetch_state(object_id)?;
        let attempts = previous.as_ref().map_or(1, |state| state.attempts.saturating_add(1));
        let mut state = FetchState {
            object_id: object_id.to_owned(),
            operation_id: operation_id.to_owned(),
            transfer_state: if attempts > 1 { "retrying" } else { "fetching" }.to_owned(),
            last_error: None,
            attempts,
        };
        self.persist_attachment_fetch_state(&state)?;
        let outcome = async {
            validate_reference(&stored.reference)?;
            if self.object_store_object(object_id)?.is_some_and(|object| object.tombstoned) {
                return Err(SdkError::LocalBus("attachment was deleted".to_owned()));
            }
            // Recover a crash after the import's ACK/slot checkpoint but before this receipt.
            let imported = self.recv_session_checkpoint_at(
                &stored.reference.key_slot.conversation_id,
                &format!("object-slot:{object_id}"),
            )? && self.received_attachment_is_local(&stored.reference)?;
            if !imported {
                tokio::time::timeout(timeout, fetch(self, &stored.reference)).await.map_err(
                    |_| SdkError::LocalBus("attachment fetch deadline exceeded".to_owned()),
                )??;
            }
            if !self.received_attachment_is_local(&stored.reference)? {
                return Err(SdkError::LocalBus("attachment content not verified".to_owned()));
            }
            Ok::<(), SdkError>(())
        }
        .await;
        match outcome {
            Ok(()) => "available".clone_into(&mut state.transfer_state),
            Err(error) => {
                "failed".clone_into(&mut state.transfer_state);
                // Fixed diagnostic categories never echo grants, key slots or transport bodies.
                state.last_error = Some(
                    match error {
                        SdkError::Transport(_) | SdkError::GatewaySessionNotEstablished => {
                            "attachment transport failed; retry object.fetch"
                        }
                        SdkError::LocalBus(ref text)
                            if text == "attachment fetch deadline exceeded" =>
                        {
                            "attachment fetch deadline exceeded; retry object.fetch"
                        }
                        _ => "attachment fetch failed; retry object.fetch",
                    }
                    .to_owned(),
                );
            }
        }
        self.persist_attachment_fetch_state(&state)?;
        Ok(public_receipt(&state))
    }

    fn received_attachment_is_local(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<bool, SdkError> {
        let Some(object) = self.object_store_object(&reference.object_id)? else {
            return Ok(false);
        };
        if object.tombstoned || object.manifest_hash != reference.manifest_hash {
            return Ok(false);
        }
        let plaintext = self.decrypt_object(&reference.object_id)?;
        Ok(ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext)
            == reference.plaintext_hash)
    }

    fn attachment_fetch_state(&self, id: &str) -> Result<Option<FetchState>, SdkError> {
        Ok(self.account_db()?.load_actor_state(&format!("attachment/fetch/{id}"))?)
    }

    fn persist_attachment_fetch_state(&self, state: &FetchState) -> Result<(), SdkError> {
        let value = json!(state);
        self.account_db()?.persist_actor_state_batch(&[
            (format!("attachment/fetch/{}", state.object_id), value.clone()),
            (format!("attachment/operation/{}", state.operation_id), value),
        ])?;
        Ok(())
    }

    pub(crate) fn recover_received_attachment_fetches(&self) -> Result<(), SdkError> {
        let states: Vec<FetchState> = self.account_db()?.list_actor_states("attachment/fetch/")?;
        for mut state in states {
            if matches!(state.transfer_state.as_str(), "fetching" | "retrying") {
                "failed".clone_into(&mut state.transfer_state);
                state.last_error =
                    Some("attachment fetch interrupted; retry object.fetch".to_owned());
                self.persist_attachment_fetch_state(&state)?;
            }
        }
        Ok(())
    }

    pub(crate) fn received_attachment_status(&self, id: &str) -> Result<Option<Value>, SdkError> {
        Ok(self.attachment_fetch_state(id)?.map(|state| public_receipt(&state)))
    }

    pub(super) fn received_attachment_prepared_slot(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<Option<DeferredObjectKeySlot>, SdkError> {
        let Some(db) = self.active_account_db.as_ref() else { return Ok(None) };
        let Some(stored): Option<ReceivedAttachment> =
            db.load_actor_state(&reference_key(&reference.object_id))?
        else {
            return Ok(None);
        };
        // Auto-fetch may import a different share of the same object; never reuse its slot session.
        if stored.reference.manifest_hash != reference.manifest_hash
            || serde_json::to_value(&stored.reference.key_slot)?
                != serde_json::to_value(&reference.key_slot)?
        {
            return Ok(None);
        }
        stored
            .prepared_slot
            .map(|slot| {
                Ok(DeferredObjectKeySlot {
                    object_key: slot.object_key,
                    session: ramflux_crypto::DmSession::from_snapshot(slot.session)?,
                    conversation_id: slot.conversation_id,
                    commit_label: slot.commit_label,
                })
            })
            .transpose()
    }

    pub(super) fn received_attachment_chunk(
        &self,
        reference: &SdkDmAttachmentRef,
        index: u32,
    ) -> Result<Option<ChunkPayload>, SdkError> {
        let Some(db) = self.active_account_db.as_ref() else { return Ok(None) };
        let payload: Option<ChunkPayload> = db.load_actor_state(&chunk_key(reference, index))?;
        if payload.as_ref().is_some_and(|payload| payload.chunk_index != index) {
            return Err(SdkError::LocalBus("invalid attachment chunk checkpoint".to_owned()));
        }
        Ok(payload)
    }

    pub(super) fn persist_received_attachment_chunk(
        &self,
        reference: &SdkDmAttachmentRef,
        payload: &ChunkPayload,
    ) -> Result<(), SdkError> {
        let Some(db) = self.active_account_db.as_ref() else { return Ok(()) };
        if db
            .load_actor_state::<ReceivedAttachment>(&reference_key(&reference.object_id))?
            .is_some()
        {
            db.persist_actor_state(&chunk_key(reference, payload.chunk_index), payload)?;
        }
        Ok(())
    }
}

fn reference_key(object_id: &str) -> String {
    format!("attachment/reference/{object_id}")
}
fn chunk_key(reference: &SdkDmAttachmentRef, index: u32) -> String {
    format!("attachment/chunk/{}/{}/{index}", reference.object_id, reference.manifest_hash)
}
fn validate_id(id: &str) -> Result<(), SdkError> {
    if id.is_empty() || id.len() > 256 {
        return Err(SdkError::LocalBus(
            "attachment identifier must contain 1 to 256 bytes".to_owned(),
        ));
    }
    Ok(())
}
fn validate_reference(reference: &SdkDmAttachmentRef) -> Result<(), SdkError> {
    let valid = reference.schema == "ramflux.sdk.dm_attachment_ref.v1"
        && reference.version == 1
        && reference.key_slot.object_id == reference.object_id
        && (16..=MAX_CIPHER_BYTES).contains(&reference.cipher_size)
        && (1..=512 * 1024).contains(&reference.chunk_size)
        && (1..=4096).contains(&reference.total_chunks)
        && reference.cipher_size.div_ceil(reference.chunk_size as u64)
            == u64::from(reference.total_chunks);
    if !valid {
        return Err(SdkError::LocalBus(
            "invalid or oversized received attachment reference".to_owned(),
        ));
    }
    Ok(())
}
fn public_receipt(state: &FetchState) -> Value {
    json!({"object_id":state.object_id,"operation_id":state.operation_id,
        "transfer_state":state.transfer_state,"last_error":state.last_error,
        "retryable":state.transfer_state != "available"})
}

#[cfg(test)]
mod tests;
