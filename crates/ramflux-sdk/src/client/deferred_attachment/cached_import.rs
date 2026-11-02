// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified local attachment completion needs neither an unexpired grant nor a relay session.
use super::{
    DeferredObjectKeySlot, RamfluxClient, SdkDmAttachmentImportResult, SdkDmAttachmentRef,
    SdkError, ack_progress_prefix, validate_reference,
};

impl RamfluxClient {
    pub(in crate::client) fn try_import_cached_attachment(
        &mut self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<Option<SdkDmAttachmentImportResult>, SdkError> {
        let mut check = "verified_local_object";
        let outcome = (|| {
            if !self.received_attachment_is_local(reference)? {
                if !self.cached_attachment_bytes_complete(reference)? {
                    return Ok(None);
                }
                check = "cached_reference";
                validate_reference(reference)?;
                let slot = self
                    .received_attachment_prepared_slot(reference)?
                    .map_or_else(|| self.decrypt_object_key_slot(&reference.key_slot), Ok)?;
                self.materialize_cached_attachment(reference, slot.object_key, &mut check)?;
            }
            check = "cached_reference";
            validate_reference(reference)?;
            check = "cached_key_slot";
            if self.object_key_slot_committed(&reference.key_slot)? {
                self.account_db()?.write_transaction(|| self.sweep_attachment_acks(reference))?;
            } else {
                let slot = self
                    .received_attachment_prepared_slot(reference)?
                    .map_or_else(|| self.decrypt_object_key_slot(&reference.key_slot), Ok)?;
                let object_key = self.object_content_key(&reference.object_id)?;
                if object_key != slot.object_key {
                    return Err(SdkError::LocalBus(
                        "cached attachment key differs from key slot".into(),
                    ));
                }
                check = "key_slot_commit";
                self.commit_received_attachment_import(reference, &slot)?;
            }
            Ok(Some(SdkDmAttachmentImportResult {
                object_id: reference.object_id.clone(),
                manifest_hash: reference.manifest_hash.clone(),
                plaintext_base64: ramflux_protocol::encode_base64url(
                    &self.decrypt_object(&reference.object_id)?,
                ),
                plaintext_hash: reference.plaintext_hash.clone(),
                imported: true,
            }))
        })();
        super::super::attachment_diagnostics::checked(outcome, &reference.object_id, check)
    }

    pub(in crate::client) fn commit_received_attachment_import(
        &self,
        reference: &SdkDmAttachmentRef,
        slot: &DeferredObjectKeySlot,
    ) -> Result<(), SdkError> {
        // Nested writer phases use savepoints, so the slot and ACK removal commit together.
        self.account_db()?.write_transaction(|| {
            self.commit_object_key_slot_session(slot)?;
            self.sweep_attachment_acks(reference)
        })
    }

    fn sweep_attachment_acks(&self, reference: &SdkDmAttachmentRef) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys(&ack_progress_prefix(reference)?)? {
            db.remove_actor_state(&key)?;
        }
        Ok(())
    }
}
