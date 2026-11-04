// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-encrypted attachment references, retry receipts and resumable chunk cache.
use super::object::DeferredObjectKeySlot;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ops::{AsyncFnMut, AsyncFnOnce};
use std::time::Duration;

mod cached_import;
pub(crate) mod job;

#[derive(Clone, Copy)]
pub(crate) struct ReferenceContext<'a> {
    pub owner: &'a str,
    pub conversation: &'a str,
    pub message: &'a str,
}

const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CIPHER_BYTES: u64 = 16 * 1024 * 1024 + 16;

// Deliberately not Debug: the reference contains a grant and encrypted content-key slot.
#[derive(Serialize, Deserialize)]
struct ReceivedAttachment {
    reference: SdkDmAttachmentRef,
    #[serde(default)]
    authenticated_sender: Option<String>,
    #[serde(default)]
    prepared_slot: Option<PreparedSlot>,
}

#[derive(Deserialize, Serialize)]
struct AckProgress {
    object_id: String,
    acknowledged: bool,
}

#[derive(Serialize, Deserialize)]
struct PreparedSlot {
    object_key: [u8; 32],
    conversation_id: String,
    commit_label: String,
    #[serde(default)]
    pair_slot: Option<SdkObjectKeySlot>,
}

impl Drop for PreparedSlot {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.object_key);
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct FetchState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wire_object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_hash: Option<String>,
    object_id: String,
    operation_id: String,
    transfer_state: String,
    last_error: Option<String>,
    attempts: u32,
    #[serde(default = "default_retryable")]
    retryable: bool,
}

const fn default_retryable() -> bool {
    true
}

impl RamfluxClient {
    pub(super) fn attachment_error(
        &self,
        reference: &SdkDmAttachmentRef,
        error: SdkError,
    ) -> SdkError {
        match error {
            SdkError::Sync(SyncError::ObjectTombstoned) => SdkError::AttachmentDeleted,
            SdkError::Storage(ramflux_storage::StorageError::ObjectIdentityConflict) => {
                // A zero-manifest placeholder can win between the initial check and import.
                // Preserve live identity conflicts and the stronger erasure fence.
                let deleted = (|| {
                    self.account_db()?.check_object_access(&reference.object_id)?;
                    self.discard_deleted_attachment_chunks(reference)
                })();
                match deleted {
                    Ok(true) => SdkError::AttachmentDeleted,
                    Err(SdkError::ObjectErased) => SdkError::ObjectErased,
                    _ => error,
                }
            }
            other => other,
        }
    }

    /// Persist each confirmed ACK so a bounded fetch never restarts an entire ACK pass.
    pub(super) async fn acknowledge_received_attachment_with<F>(
        &self,
        reference: &SdkDmAttachmentRef,
        total_chunks: u32,
        mut acknowledge: F,
    ) -> Result<(), SdkError>
    where
        F: AsyncFnMut(u32) -> Result<(), SdkError>,
    {
        if self.object_key_slot_committed(&reference.key_slot)?
            && self.received_attachment_is_local(reference)?
        {
            return Ok(());
        }
        // Bind progress to the exact relay, grant, manifest and key slot, not a reusable object id.
        let prefix = ack_progress_prefix(reference)?;
        let db = self.account_db()?;
        db.check_object_identity(&reference.object_id, &reference.manifest_hash)?;
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        let resumable =
            db.load_actor_state::<ReceivedAttachment>(&reference_key(&selector))?.is_some();
        for index in 0..total_chunks {
            let key = format!("{prefix}{index}");
            if resumable
                && db
                    .load_actor_state::<AckProgress>(&key)?
                    .is_some_and(|saved| saved.object_id == selector && saved.acknowledged)
            {
                continue;
            }
            let started = std::time::Instant::now();
            acknowledge(index).await?;
            let confirmed = std::time::Instant::now();
            if resumable {
                self.persist_received_attachment_ack_with_limit(reference, index, total_chunks)?;
            }
            tracing::debug!(
                target: "ramflux_sdk::attachment_timing",
                object_id = %reference.object_id,
                chunk_index = index,
                acknowledge_ms = confirmed.duration_since(started).as_secs_f64() * 1000.0,
                checkpoint_ms = confirmed.elapsed().as_secs_f64() * 1000.0,
                "attachment ACK progress durable"
            );
        }
        Ok(())
    }

    /// Persist before the message's receive checkpoint, without contacting any relay.
    pub(crate) fn persist_received_attachment_reference(
        &self,
        reference: &SdkDmAttachmentRef,
        owner: &str,
        conversation: &str,
        message: &str,
    ) -> Result<(), SdkError> {
        self.account_db()?.check_object_identity(&reference.object_id, &reference.manifest_hash)?;
        let prepared = self.decrypt_object_key_slot(&reference.key_slot).ok();
        self.persist_received_reference_prepared(reference, owner, conversation, message, prepared)
    }
    pub(crate) fn persist_received_reference_prepared(
        &self,
        reference: &SdkDmAttachmentRef,
        owner: &str,
        conversation: &str,
        message: &str,
        prepared: Option<DeferredObjectKeySlot>,
    ) -> Result<(), SdkError> {
        self.persist_received_reference_prepared_at(
            reference,
            &reference.object_id,
            ReferenceContext { owner, conversation, message },
            prepared,
        )
    }

    pub(crate) fn persist_received_reference_prepared_at(
        &self,
        reference: &SdkDmAttachmentRef,
        selector: &str,
        context: ReferenceContext<'_>,
        prepared: Option<DeferredObjectKeySlot>,
    ) -> Result<(), SdkError> {
        let ReferenceContext { owner, conversation, message } = context;
        let db = self.account_db()?;
        let key = reference_key(selector);
        let existing = db.load_actor_state::<ReceivedAttachment>(&key)?.is_some();
        // Extract the content key while receive-time private prekeys are available, without
        // advancing its durable slot checkpoint. A bad slot must not block message receipt.
        let prepared_slot = prepared.map(|mut slot| PreparedSlot {
            object_key: slot.object_key,
            conversation_id: std::mem::take(&mut slot.conversation_id),
            commit_label: std::mem::take(&mut slot.commit_label),
            pair_slot: slot.pair_slot.take(),
        });
        let metadata = json!({
            "name":null,"mime":null,"size":reference.cipher_size.checked_sub(16),
            "direction":"incoming","owner":owner,"conversation_id":conversation,
            "message_id":message,"relay_endpoint":reference.relay_endpoint,
            "manifest_hash":reference.manifest_hash,"plaintext_hash":reference.plaintext_hash,
        });
        let received = json!(ReceivedAttachment {
            reference: reference.clone(),
            prepared_slot,
            authenticated_sender: None,
        });
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.attachment.reference.v1",
            &ramflux_protocol::canonical_json_bytes(reference)?,
        );
        db.write_transaction(|| -> Result<(), SdkError> {
            db.register_object_reference(&ramflux_storage::ObjectReferenceOwner {
                reference_hash: &hash,
                wire_id: &reference.object_id,
                manifest_hash: &reference.manifest_hash,
                selector,
                message_id: message,
                reference: &received,
                metadata: &metadata,
            })?;
            if !existing {
                db.persist_actor_state_batch(&[
                    (key, received),
                    (format!("directory/object/{selector}"), metadata),
                ])?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Fetches one durably received reference. Failed attempts can reuse the same operation id;
    /// successful operations replay their compact receipt without touching the relay while the
    /// object remains accessible. Later deletion or revocation takes precedence over replay.
    ///
    /// # Errors
    /// Returns an error for invalid identifiers, operation reuse or unavailable account storage.
    /// Transfer errors are returned as a retryable `failed` receipt with no access material.
    pub async fn fetch_received_attachment(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
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
        &mut self,
        object_id: &str,
        operation_id: &str,
    ) -> Result<Option<Value>, SdkError> {
        validate_id(object_id)?;
        validate_id(operation_id)?;
        self.account_db()?.check_object_access(object_id)?;
        let old: Option<FetchState> =
            self.account_db()?.load_actor_state(&format!("attachment/operation/{operation_id}"))?;
        if old.as_ref().is_some_and(|old| old.object_id != object_id) {
            return Err(SdkError::LocalBus("attachment operation_id already bound".to_owned()));
        }
        let Some(stored) =
            self.account_db()?.load_actor_state::<ReceivedAttachment>(&reference_key(object_id))?
        else {
            return Ok(None);
        };
        if self.discard_deleted_attachment_chunks(&stored.reference)? {
            let error = SdkError::AttachmentDeleted;
            super::attachment_diagnostics::failed(object_id, "attachment_deleted", &error);
            let state = FetchState {
                wire_object_id: Some(stored.reference.object_id.clone()),
                manifest_hash: Some(stored.reference.manifest_hash.clone()),
                object_id: object_id.to_owned(),
                operation_id: operation_id.to_owned(),
                transfer_state: "failed".into(),
                last_error: Some(crate::error::ATTACHMENT_DELETED.into()),
                retryable: false,
                attempts: self
                    .attachment_fetch_state(object_id)?
                    .map_or(1, |old| old.attempts.saturating_add(1)),
            };
            self.persist_attachment_fetch_state(&state)?;
            return Ok(Some(public_receipt(&state)));
        }
        if let Some(old) = old
            && old.transfer_state == "available"
        {
            return Ok(Some(public_receipt(&old)));
        }
        if validate_reference(&stored.reference).is_ok()
            && self.try_import_cached_attachment(&stored.reference)?.is_some()
        {
            let state = FetchState {
                wire_object_id: Some(stored.reference.object_id.clone()),
                manifest_hash: Some(stored.reference.manifest_hash.clone()),
                object_id: object_id.to_owned(),
                operation_id: operation_id.to_owned(),
                transfer_state: "available".into(),
                retryable: false,
                last_error: None,
                attempts: self
                    .attachment_fetch_state(object_id)?
                    .map_or(1, |old| old.attempts.saturating_add(1)),
            };
            self.persist_attachment_fetch_state(&state)?;
            return Ok(Some(public_receipt(&state)));
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
            wire_object_id: Some(stored.reference.object_id.clone()),
            manifest_hash: Some(stored.reference.manifest_hash.clone()),
            object_id: object_id.to_owned(),
            operation_id: operation_id.to_owned(),
            transfer_state: if attempts > 1 { "retrying" } else { "fetching" }.to_owned(),
            last_error: None,
            attempts,
            retryable: true,
        };
        self.persist_attachment_fetch_state(&state)?;
        let outcome = async {
            if self.discard_deleted_attachment_chunks(&stored.reference)? {
                return super::attachment_diagnostics::checked(
                    Err(SdkError::AttachmentDeleted),
                    object_id,
                    "attachment_deleted",
                );
            }
            super::attachment_diagnostics::checked(
                validate_reference(&stored.reference),
                object_id,
                "attachment_reference",
            )?;
            // Recover a crash after the import's ACK/slot checkpoint but before this receipt.
            let imported = self.recv_session_checkpoint_at(
                &stored.reference.key_slot.conversation_id,
                &format!("object-slot:{object_id}"),
            )? && self.received_attachment_is_local(&stored.reference)?;
            if !imported {
                tokio::time::timeout(timeout, fetch(self, &stored.reference)).await.map_err(
                    |_| {
                        let error =
                            SdkError::LocalBus("attachment fetch deadline exceeded".to_owned());
                        super::attachment_diagnostics::failed(
                            object_id,
                            "attachment_fetch_deadline",
                            &error,
                        );
                        error
                    },
                )??;
            }
            if !self.received_attachment_is_local(&stored.reference)? {
                return super::attachment_diagnostics::checked(
                    Err(SdkError::LocalBus("attachment content not verified".into())),
                    object_id,
                    "attachment_content_unverified",
                );
            }
            Ok::<(), SdkError>(())
        }
        .await;
        match outcome.map_err(|error| self.attachment_error(&stored.reference, error)) {
            Ok(()) => {
                "available".clone_into(&mut state.transfer_state);
                state.retryable = false;
            }
            Err(SdkError::ObjectErased) => return Err(SdkError::ObjectErased),
            Err(error) => {
                super::attachment_diagnostics::context(object_id, "attachment_fetch", &error);
                "failed".clone_into(&mut state.transfer_state);
                // Fixed diagnostic categories never echo grants, key slots or transport bodies.
                state.retryable = !matches!(error, SdkError::AttachmentDeleted);
                state.last_error = Some(
                    match error {
                        SdkError::AttachmentDeleted => crate::error::ATTACHMENT_DELETED,
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
        if object.tombstoned
            || object.manifest_hash != reference.manifest_hash
            || u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX) != reference.cipher_size
            || ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::OBJECT_MANIFEST,
                &object.ciphertext,
            ) != reference.manifest_hash
        {
            return Ok(false);
        }
        let plaintext = zeroize::Zeroizing::new(self.decrypt_object(&reference.object_id)?);
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
            let stored: Option<ReceivedAttachment> =
                self.account_db()?.load_actor_state(&reference_key(&state.object_id))?;
            let deleted = stored
                .as_ref()
                .map(|stored| self.discard_deleted_attachment_chunks(&stored.reference))
                .transpose()?
                .unwrap_or(false);
            if deleted || self.account_db()?.object_is_tombstoned(&state.object_id)? {
                state.transfer_state = "failed".into();
                state.last_error = Some(crate::error::ATTACHMENT_DELETED.into());
                state.retryable = false;
                self.persist_attachment_fetch_state(&state)?;
                continue;
            }
            if !state.retryable {
                continue;
            }
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
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        let Some(stored): Option<ReceivedAttachment> =
            db.load_actor_state(&reference_key(&selector))?
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
            .map(|mut slot| {
                Ok(DeferredObjectKeySlot {
                    object_key: slot.object_key,
                    session: None,
                    legacy_slot: if slot.pair_slot.is_none() {
                        Some(reference.key_slot.clone())
                    } else {
                        None
                    },
                    conversation_id: std::mem::take(&mut slot.conversation_id),
                    commit_label: std::mem::take(&mut slot.commit_label),
                    pair_slot: slot.pair_slot.take(),
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
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        if db.load_actor_state::<ReceivedAttachment>(&reference_key(&selector))?.is_some() {
            db.persist_actor_state(&chunk_key(reference, payload.chunk_index), payload)?;
        }
        Ok(())
    }
}

fn reference_key(object_id: &str) -> String {
    format!("attachment/reference/{object_id}")
}
fn ack_progress_prefix(reference: &SdkDmAttachmentRef) -> Result<String, SdkError> {
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.ack.progress.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    );
    Ok(format!("attachment/ack/{hash}/"))
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
        "retryable":state.retryable && state.transfer_state != "available"})
}

#[cfg(test)]
mod tests;

impl RamfluxClient {
    pub(crate) fn persist_sender_attachment_reference(
        &self,
        reference: &SdkDmAttachmentRef,
        sender: &str,
        context: ReferenceContext<'_>,
        prepared: Option<DeferredObjectKeySlot>,
    ) -> Result<(), SdkError> {
        if reference.key_slot.ciphertext.sender_device_id_hash != dm_device_id_hash(sender) {
            return Err(SdkError::InboundRejected(
                "attachment slot source differs from authenticated sender".to_owned(),
            ));
        }
        let db = self.account_db()?;
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.received.object.sender.v2",
            &ramflux_protocol::canonical_json_bytes(&(sender, &reference.object_id))?,
        );
        let scoped_key = format!("attachment/reference-by-sender/{hash}");
        let mapped = db.load_actor_state::<String>(&scoped_key)?;
        let existing: Option<ReceivedAttachment> =
            db.load_actor_state(&reference_key(&reference.object_id))?;
        let mut selector = mapped.unwrap_or_else(|| {
            if reference.object_id.starts_with("received:")
                || existing
                    .as_ref()
                    .is_some_and(|old| old.authenticated_sender.as_deref() != Some(sender))
            {
                format!("received:{hash}")
            } else {
                reference.object_id.clone()
            }
        });
        if db
            .load_actor_state::<ReceivedAttachment>(&reference_key(&selector))?
            .is_some_and(|old| old.authenticated_sender.as_deref() != Some(sender))
        {
            selector = format!(
                "received:{hash}:{}",
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
            );
        }
        self.persist_received_reference_prepared_at(reference, &selector, context, prepared)?;
        let mut stored: ReceivedAttachment =
            db.load_actor_state(&reference_key(&selector))?.ok_or_else(|| {
                SdkError::LocalBus("attachment reference missing after commit".to_owned())
            })?;
        stored.authenticated_sender = Some(sender.to_owned());
        db.persist_actor_state(&reference_key(&selector), &stored)?;
        db.persist_actor_state(&scoped_key, &selector)?;
        let slot_key = slot_reference_key(reference)?;
        db.persist_actor_state(&slot_key, &selector)?;
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.attachment.reference.v1",
            &ramflux_protocol::canonical_json_bytes(reference)?,
        );
        db.register_object_reference_actor(&hash, &slot_key)?;
        Ok(())
    }
}
fn slot_reference_key(reference: &SdkDmAttachmentRef) -> Result<String, SdkError> {
    Ok(format!(
        "attachment/reference-by-slot/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.received.slot.selector.v2",
            &ramflux_protocol::canonical_json_bytes(&reference.key_slot)?
        )
    ))
}

impl RamfluxClient {
    pub(super) fn received_object_alias(
        &self,
        selector: &str,
    ) -> Result<Option<(String, String)>, SdkError> {
        if !selector.starts_with("received:") {
            return Ok(None);
        }
        let stored: ReceivedAttachment = self
            .account_db()?
            .load_actor_state(&reference_key(selector))?
            .ok_or_else(|| SdkError::LocalBus("received object selector not found".to_owned()))?;
        Ok(Some((stored.reference.object_id, stored.reference.manifest_hash)))
    }
}
