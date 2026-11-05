// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-history pages use local authorization and import checkpoints around owned relay work.

use crate::client::object::fetch_job::{FetchCipher, FetchInput};
use crate::own_device_sync::{SdkOwnDeviceSyncEnvelope, SdkOwnDeviceSyncImportResponse};
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};
use std::sync::Arc;

pub(crate) enum HistoryPreparation {
    Complete(Option<Box<SdkOwnDeviceSyncEnvelope>>),
    Fetch(Arc<HistoryFetch>),
}
pub(crate) struct HistoryCompletion {
    receipt_key: String,
    erasure_generation: i64,
}
pub(crate) struct HistoryFetch {
    pub input: Arc<FetchInput>,
    envelope: SdkOwnDeviceSyncEnvelope,
    erasure_generation: i64,
}
impl RamfluxClient {
    pub(crate) fn prepare_own_history_receive(
        &mut self,
        envelope: SdkOwnDeviceSyncEnvelope,
        manifest: SdkDeviceManifestResponse,
        #[cfg(feature = "itest-local-mint")] http_timeout: std::time::Duration,
    ) -> Result<HistoryPreparation, SdkError> {
        self.validate_own_sync_header(&self.own_account_anchor()?, &envelope)?;
        let manifest = self.accept_fetched_device_manifest(
            manifest,
            &envelope.principal_commitment,
            "own_device_sync_import",
        )?;
        self.verify_own_sync_devices(&envelope, &manifest)?;
        let receipt = Self::own_sync_receipt_key(&envelope)?;
        if self
            .account_db()?
            .load_actor_state::<SdkOwnDeviceSyncImportResponse>(&receipt)?
            .is_some()
        {
            return Ok(HistoryPreparation::Complete(
                self.account_db()?.load_actor_state(&format!("{receipt}/next"))?,
            ));
        }
        if self
            .object_store_object(&envelope.history_ref.object_id)?
            .is_some_and(|object| object.manifest_hash == envelope.history_ref.manifest_hash)
        {
            let plaintext =
                zeroize::Zeroizing::new(self.decrypt_object(&envelope.history_ref.object_id)?);
            return Ok(HistoryPreparation::Complete(
                self.apply_own_history_plaintext(&envelope, &plaintext)?.1,
            ));
        }
        let slot = self
            .received_attachment_prepared_slot(&envelope.history_ref)?
            .map_or_else(|| self.decrypt_object_key_slot(&envelope.history_ref.key_slot), Ok)?;
        let input = self.prepare_reference_fetch_input(&envelope.history_ref, slot.object_key)?;
        #[cfg(feature = "itest-local-mint")]
        let input = {
            let mut input = input;
            input.http_timeout = http_timeout;
            input
        };
        Ok(HistoryPreparation::Fetch(Arc::new(HistoryFetch {
            input: Arc::new(input),
            envelope,
            erasure_generation: self.account_db()?.privacy_erasure_generation()?,
        })))
    }
    pub(crate) fn check_own_history_fetch(&self, fetch: &HistoryFetch) -> Result<(), SdkError> {
        let envelope = &fetch.envelope;
        self.validate_own_sync_header(&self.own_account_anchor()?, envelope)?;
        let db = self.account_db()?;
        if db.privacy_erasure_generation()? != fetch.erasure_generation {
            return Err(SdkError::ObjectErased);
        }
        db.check_object_identity(
            &envelope.history_ref.object_id,
            &envelope.history_ref.manifest_hash,
        )?;
        self.require_native_sync(
            &envelope.principal_commitment,
            &envelope.source_device_id,
            &envelope.target_device_id,
        )?;
        for device in [&envelope.source_device_id, &envelope.target_device_id] {
            self.require_cached_root_authority(
                &self.device_identity_for_root(&envelope.principal_commitment, device)?,
                crate::client::identity_authority::HeadUse::NewAuthorization,
            )?;
        }
        Ok(())
    }
    pub(crate) fn import_own_history_cipher(
        &mut self,
        fetch: &HistoryFetch,
        cipher: &FetchCipher,
    ) -> Result<(), SdkError> {
        self.check_own_history_fetch(fetch)?;
        self.persist_fetch_cipher_retained(
            &fetch.input,
            cipher,
            ramflux_storage::ObjectRetention::OwnDeviceTransport,
        )
    }
    pub(crate) fn commit_own_history_slot(&self, fetch: &HistoryFetch) -> Result<(), SdkError> {
        self.check_own_history_fetch(fetch)?;
        let reference = &fetch.envelope.history_ref;
        // Decrypt against the current receive ratchet; never install a snapshot held across I/O.
        if !self.object_key_slot_committed(&reference.key_slot)? {
            let slot = self
                .received_attachment_prepared_slot(reference)?
                .map_or_else(|| self.decrypt_object_key_slot(&reference.key_slot), Ok)?;
            if slot.object_key != *fetch.input.key {
                return Err(SdkError::InboundRejected(
                    "history object key changed before slot commit".into(),
                ));
            }
            self.commit_received_attachment_import(reference, &slot)?;
        }
        Ok(())
    }
    pub(crate) fn finish_own_history_receive(
        &self,
        fetch: &HistoryFetch,
    ) -> Result<Option<Box<SdkOwnDeviceSyncEnvelope>>, SdkError> {
        self.check_own_history_fetch(fetch)?;
        self.verify_current_own_history(&fetch.envelope)?;
        let plaintext =
            zeroize::Zeroizing::new(self.decrypt_object(&fetch.envelope.history_ref.object_id)?);
        Ok(self.apply_own_history_plaintext(&fetch.envelope, &plaintext)?.1)
    }
    fn verify_current_own_history(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
    ) -> Result<(), SdkError> {
        self.validate_own_sync_header(&self.own_account_anchor()?, envelope)?;
        self.require_native_sync(
            &envelope.principal_commitment,
            &envelope.source_device_id,
            &envelope.target_device_id,
        )?;
        let source = self.trusted_device(
            &self.device_identity_for_root(
                &envelope.principal_commitment,
                &envelope.source_device_id,
            )?,
            crate::client::identity_authority::HeadUse::NewAuthorization,
        )?;
        self.trusted_device(
            &self.device_identity_for_root(
                &envelope.principal_commitment,
                &envelope.target_device_id,
            )?,
            crate::client::identity_authority::HeadUse::NewAuthorization,
        )?;
        let key = source["signing_public_key"]
            .as_str()
            .ok_or_else(|| SdkError::InboundPending("own history signer missing".into()))?;
        if envelope.signed.signing_key_id != format!("device:{}", envelope.source_device_id) {
            return Err(SdkError::InboundRejected(
                "own-device sync signing key id mismatch".into(),
            ));
        }
        ramflux_crypto::verify_device_branch_signature(
            key,
            &crate::own_device_sync::own_device_sync_signing_body(envelope),
            &envelope.signed.signature,
        )?;
        Ok(())
    }
    pub(crate) fn own_history_completion(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
    ) -> Result<HistoryCompletion, SdkError> {
        self.verify_current_own_history(envelope)?;
        Ok(HistoryCompletion {
            receipt_key: Self::own_sync_receipt_key(envelope)?,
            erasure_generation: self.account_db()?.privacy_erasure_generation()?,
        })
    }
    pub(crate) fn confirm_prepared_own_history(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        completion: Option<&HistoryCompletion>,
    ) -> Result<(), SdkError> {
        self.verify_current_own_history(envelope)?;
        let completion = completion
            .ok_or_else(|| SdkError::InboundPending("own history pages must be prepared".into()))?;
        if completion.receipt_key != Self::own_sync_receipt_key(envelope)? {
            return Err(SdkError::InboundRejected(
                "own history completion binding mismatch".into(),
            ));
        }
        if completion.erasure_generation != self.account_db()?.privacy_erasure_generation()? {
            return Err(SdkError::ObjectErased);
        }
        Ok(())
    }
}
