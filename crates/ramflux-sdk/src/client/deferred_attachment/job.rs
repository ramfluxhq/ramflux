// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Writer-owned fetch preparation, reference fences, ACK checkpoints, and compact receipts.

use super::{
    AckProgress, DeferredObjectKeySlot, FetchState, RamfluxClient, ReceivedAttachment,
    SdkDmAttachmentRef, SdkError, ack_progress_prefix, public_receipt, reference_key,
    slot_reference_key, validate_id, validate_reference,
};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone)]
pub(crate) struct FetchFence {
    pub selector: String,
    pub operation_id: String,
    pub reference: SdkDmAttachmentRef,
    pub reference_hash: String,
    pub attempts: u32,
}
pub(crate) struct FetchBinding {
    pub fence: FetchFence,
    pub slot: DeferredObjectKeySlot,
    state: FetchState,
}
pub(crate) enum FetchPreparation {
    Complete(Value),
    Ready(Box<FetchBinding>),
}

fn reference_hash(reference: &SdkDmAttachmentRef) -> Result<String, SdkError> {
    Ok(ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    ))
}

impl RamfluxClient {
    pub(crate) fn commit_prepared_attachment_slot(
        &self,
        binding: &FetchBinding,
    ) -> Result<(), SdkError> {
        self.check_fetch_fence(&binding.fence)?;
        if !self.object_key_slot_committed(&binding.fence.reference.key_slot)? {
            self.commit_received_attachment_import(&binding.fence.reference, &binding.slot)?;
        }
        Ok(())
    }

    pub(crate) fn received_attachment_is_verified_local(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<bool, SdkError> {
        self.received_attachment_is_local(reference)
    }

    pub(crate) fn lookup_received_attachment_operation(
        &self,
        selector: &str,
        operation: &str,
    ) -> Result<Option<Value>, SdkError> {
        validate_id(selector)?;
        validate_id(operation)?;
        let db = self.account_db()?;
        db.check_object_access(selector)?;
        let saved =
            db.load_actor_state::<FetchState>(&format!("attachment/operation/{operation}"))?;
        if saved.as_ref().is_some_and(|state| state.object_id != selector) {
            return Err(SdkError::LocalBus("attachment operation_id already bound".into()));
        }
        let Some(stored) = db.load_actor_state::<ReceivedAttachment>(&reference_key(selector))?
        else {
            return Ok(None);
        };
        if let Some(saved) = saved
            && saved.transfer_state == "available"
            && self.received_attachment_is_local(&stored.reference)?
        {
            return Ok(Some(public_receipt(&saved)));
        }
        Ok(None)
    }

    pub(crate) fn prepare_received_attachment_job(
        &mut self,
        selector: &str,
        operation: &str,
    ) -> Result<FetchPreparation, SdkError> {
        if let Some(receipt) = self.lookup_received_attachment_operation(selector, operation)? {
            return Ok(FetchPreparation::Complete(receipt));
        }
        let stored = self
            .account_db()?
            .load_actor_state::<ReceivedAttachment>(&reference_key(selector))?
            .ok_or_else(|| SdkError::LocalBus("received attachment reference not found".into()))?;
        let attempts = self
            .attachment_fetch_state(selector)?
            .map_or(1, |state| state.attempts.saturating_add(1));
        let state = FetchState {
            wire_object_id: Some(stored.reference.object_id.clone()),
            manifest_hash: Some(stored.reference.manifest_hash.clone()),
            object_id: selector.into(),
            operation_id: operation.into(),
            transfer_state: if attempts > 1 { "retrying" } else { "fetching" }.into(),
            last_error: None,
            retryable: true,
            attempts,
        };
        // F0 is durable before the slot may issue its first GET.
        self.persist_attachment_fetch_state(&state)?;
        let result = (|| {
            validate_reference(&stored.reference)?;
            self.account_db()?.check_object_identity(
                &stored.reference.object_id,
                &stored.reference.manifest_hash,
            )?;
            if self.discard_deleted_attachment_chunks(&stored.reference)? {
                return Err(SdkError::AttachmentDeleted);
            }
            let slot = self
                .received_attachment_prepared_slot(&stored.reference)?
                .map_or_else(|| self.decrypt_object_key_slot(&stored.reference.key_slot), Ok)?;
            let fence = FetchFence {
                selector: selector.into(),
                operation_id: operation.into(),
                reference_hash: reference_hash(&stored.reference)?,
                reference: stored.reference,
                attempts,
            };
            Ok(FetchBinding { fence, slot, state: state.clone() })
        })();
        match result {
            Ok(binding) => Ok(FetchPreparation::Ready(Box::new(binding))),
            Err(SdkError::ObjectErased) => Err(SdkError::ObjectErased),
            Err(error) => {
                let receipt = self.persist_fetch_terminal(state, Some(&error))?;
                Ok(FetchPreparation::Complete(receipt))
            }
        }
    }

    pub(crate) fn check_fetch_fence(&self, fence: &FetchFence) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.check_object_access(&fence.selector)?;
        db.check_object_identity(&fence.reference.object_id, &fence.reference.manifest_hash)?;
        let current = db
            .load_actor_state::<ReceivedAttachment>(&reference_key(&fence.selector))?
            .ok_or(SdkError::ObjectErased)?;
        if reference_hash(&current.reference)? != fence.reference_hash {
            return Err(SdkError::ObjectErased);
        }
        let state = self
            .attachment_fetch_state(&fence.selector)?
            .ok_or_else(|| SdkError::InboundPending("attachment fetch state disappeared".into()))?;
        if state.operation_id != fence.operation_id
            || state.attempts != fence.attempts
            || !matches!(state.transfer_state.as_str(), "fetching" | "retrying")
        {
            return Err(SdkError::InboundPending("attachment fetch state changed".into()));
        }
        if db.object_is_tombstoned(&fence.reference.object_id)?
            || db.object_is_tombstoned(&fence.selector)?
        {
            return Err(SdkError::AttachmentDeleted);
        }
        Ok(())
    }

    pub(crate) fn confirmed_received_attachment_indexes(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<BTreeSet<u32>, SdkError> {
        let db = self.account_db()?;
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        let prefix = ack_progress_prefix(reference)?;
        let mut confirmed = BTreeSet::new();
        for index in 0..reference.total_chunks {
            if db
                .load_actor_state::<AckProgress>(&format!("{prefix}{index}"))?
                .is_some_and(|saved| saved.object_id == selector && saved.acknowledged)
            {
                confirmed.insert(index);
            }
        }
        Ok(confirmed)
    }

    pub(crate) fn persist_received_attachment_ack(
        &self,
        reference: &SdkDmAttachmentRef,
        index: u32,
    ) -> Result<(), SdkError> {
        self.persist_received_attachment_ack_with_limit(reference, index, reference.total_chunks)
    }

    pub(super) fn persist_received_attachment_ack_with_limit(
        &self,
        reference: &SdkDmAttachmentRef,
        index: u32,
        total_chunks: u32,
    ) -> Result<(), SdkError> {
        if index >= total_chunks {
            return Err(SdkError::InboundRejected("attachment ACK index outside manifest".into()));
        }
        let db = self.account_db()?;
        let selector = db
            .load_actor_state::<String>(&slot_reference_key(reference)?)?
            .unwrap_or_else(|| reference.object_id.clone());
        let key = format!("{}{index}", ack_progress_prefix(reference)?);
        db.write_transaction(|| {
            db.check_object_identity(&reference.object_id, &reference.manifest_hash)?;
            db.persist_actor_state(&key, &AckProgress { object_id: selector, acknowledged: true })?;
            db.register_object_reference_actor(&reference_hash(reference)?, &key)?;
            Ok::<_, SdkError>(())
        })
    }

    pub(crate) fn finish_received_attachment_job(
        &self,
        binding: &FetchBinding,
        error: Option<&SdkError>,
    ) -> Result<Value, SdkError> {
        let fence_error = match self.check_fetch_fence(&binding.fence) {
            Ok(()) => None,
            Err(SdkError::AttachmentDeleted) => Some(SdkError::AttachmentDeleted),
            Err(error) => match self.attachment_error(&binding.fence.reference, error) {
                SdkError::AttachmentDeleted => Some(SdkError::AttachmentDeleted),
                error => return Err(error),
            },
        };
        let mapped = match error {
            Some(SdkError::Sync(ramflux_sync::SyncError::ObjectTombstoned)) => {
                Some(SdkError::AttachmentDeleted)
            }
            Some(SdkError::Storage(ramflux_storage::StorageError::ObjectIdentityConflict)) => {
                Some(self.attachment_error(
                    &binding.fence.reference,
                    SdkError::Storage(ramflux_storage::StorageError::ObjectIdentityConflict),
                ))
            }
            _ => None,
        };
        let error = fence_error.as_ref().or(mapped.as_ref()).or(error);
        if error.is_none() && !self.received_attachment_is_local(&binding.fence.reference)? {
            return Err(SdkError::InboundPending("attachment content not verified".into()));
        }
        self.persist_fetch_terminal(binding.state.clone(), error)
    }

    fn persist_fetch_terminal(
        &self,
        mut state: FetchState,
        error: Option<&SdkError>,
    ) -> Result<Value, SdkError> {
        if let Some(error) = error {
            if matches!(error, SdkError::ObjectErased) {
                return Err(SdkError::ObjectErased);
            }
            state.transfer_state = "failed".into();
            state.retryable = !matches!(error, SdkError::AttachmentDeleted);
            state.last_error = Some(
                match error {
                    SdkError::AttachmentDeleted => crate::error::ATTACHMENT_DELETED,
                    SdkError::Transport(_)
                    | SdkError::GatewaySessionNotEstablished
                    | SdkError::NetworkingPending
                    | SdkError::NetworkingPendingContext { .. } => {
                        "attachment transport failed; retry object.fetch"
                    }
                    SdkError::LocalBus(text) if text == "attachment fetch deadline exceeded" => {
                        "attachment fetch deadline exceeded; retry object.fetch"
                    }
                    _ => "attachment fetch failed; retry object.fetch",
                }
                .into(),
            );
        } else {
            state.transfer_state = "available".into();
            state.retryable = false;
            state.last_error = None;
        }
        self.persist_attachment_fetch_state(&state)?;
        Ok(public_receipt(&state))
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    #[test]
    fn attachment_job_persists_deleted_as_nonretryable() -> Result<(), SdkError> {
        let root = crate::bus::runtime_tests::root("attachment-job-terminal");
        let account = crate::bus::runtime_tests::account(
            &root,
            "sender",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let state = FetchState {
            wire_object_id: None,
            manifest_hash: None,
            object_id: "deleted".into(),
            operation_id: "fetch-deleted".into(),
            transfer_state: "fetching".into(),
            last_error: None,
            attempts: 1,
            retryable: true,
        };
        let receipt = account
            .client
            .persist_fetch_terminal(state.clone(), Some(&SdkError::AttachmentDeleted))?;
        assert_eq!(receipt["retryable"], false);
        assert_eq!(receipt["last_error"], crate::error::ATTACHMENT_DELETED);
        let available = account.client.persist_fetch_terminal(state, None)?;
        assert_eq!(available["retryable"], false);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
