// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#[cfg(test)]
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;

impl RamfluxClient {
    pub(crate) fn candidate_group_target_plan(
        &self,
        group_id: &str,
        sender_id: &str,
        logical_event_id: &str,
        kind: ramflux_protocol::message::KindId,
    ) -> Result<Option<crate::client::target_selection::SelectionPlan>, SdkError> {
        Self::candidate_target_plan(|| {
            self.group_selection_request(group_id, sender_id, logical_event_id, kind)
        })
    }

    pub fn append_gateway_delivery(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        crate::client::routed::validate_routed_ciphertext(entry)?;
        if self.routed_seen_marker(entry)?.is_some() {
            return Ok(());
        }
        let event = format!("gateway/delivery/v2/{}", self.inbox_admission_key(entry)?);
        if self.event_body(&event)?.is_some() {
            return Ok(());
        }
        let body = ramflux_protocol::canonical_json_bytes(&entry.envelope)?;
        self.append_event(&event, "gateway.deliver.opaque", &body)
    }

    /// # Errors
    /// Returns an error when the gateway delivery cannot be stored or the group payload cannot be
    /// decrypted.
    pub fn append_group_gateway_delivery(
        &self,
        conversation_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Vec<u8>, SdkError> {
        let _ = (conversation_id, message_id, entry);
        Err(SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "retired group carrier; use authenticated generated receive".into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn append_or_pending_group_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        encrypted_body: &[u8],
        envelope: &SdkGroupEncryptedEnvelope,
    ) -> Result<Vec<u8>, SdkError> {
        self.account_db()?.write_transaction(|| {
            let (sender_principal, native_sender) =
                self.verified_group_payload_sender(&envelope.group_id, &envelope.sender_id, entry)?;
            let projected_sender =
                if native_sender { sender_principal.as_str() } else { envelope.sender_id.as_str() };
            if self
                .direct_messages(conversation_id)?
                .iter()
                .any(|message| message.message_id == message_id)
            {
                self.account_db()?.remove_group_pending_undecrypted(message_id)?;
                return Ok(Vec::new());
            }
            if self.group_sender_key_counter_seen(
                envelope,
                &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            )? {
                self.account_db()?.remove_group_pending_undecrypted(message_id)?;
                return Ok(Vec::new());
            }
            match self.decrypt_group_envelope_for_identity(
                envelope,
                message_id,
                &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            ) {
                Ok(plaintext) => self.account_db()?.write_transaction(|| {
                    self.send_direct_message(
                        conversation_id,
                        message_id,
                        projected_sender,
                        encrypted_body,
                    )?;
                    self.account_db()?.store_message_content(
                        conversation_id,
                        message_id,
                        &plaintext,
                    )?;
                    self.account_db()?.remove_group_pending_undecrypted(message_id)?;
                    self.stage_delivery_receipt_for_ciphertext(
                        conversation_id,
                        message_id,
                        entry,
                        encrypted_body,
                    )?;
                    Ok(plaintext)
                }),
                Err(error) if is_missing_group_sender_key_error(&error) => {
                    self.account_db()?.upsert_group_pending_undecrypted(
                        &GroupPendingUndecryptedRecord {
                            group_id: envelope.group_id.clone(),
                            conversation_id: conversation_id.to_owned(),
                            group_key_epoch: envelope.group_key_epoch,
                            message_id: message_id.to_owned(),
                            sender_id: envelope.sender_id.clone(),
                            inbox_seq: entry.inbox_seq,
                            envelope_json: super::group_pending::encode(entry, encrypted_body)?,
                            created_at: now_unix_timestamp(),
                        },
                    )?;
                    Ok(Vec::new())
                }
                Err(error) => Err(error),
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn group_sender_key_counter_seen(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        self.account_db()?
            .group_sender_key_counter_seen(
                &envelope.group_id,
                envelope.group_key_epoch,
                source,
                &envelope.ciphertext.session_id,
                envelope.ciphertext.counter,
            )
            .map_err(SdkError::from)
    }

    pub(crate) fn record_group_sender_key_counter(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        message_id: &str,
    ) -> Result<bool, SdkError> {
        self.account_db()?
            .record_group_sender_key_counter(
                &GroupSenderKeyCounterRecord {
                    group_id: envelope.group_id.clone(),
                    group_key_epoch: envelope.group_key_epoch,
                    sender_id: envelope.sender_id.clone(),
                    session_id: envelope.ciphertext.session_id.clone(),
                    counter: envelope.ciphertext.counter,
                    message_id: message_id.to_owned(),
                    seen_at: now_unix_timestamp(),
                },
                source,
            )
            .map_err(SdkError::from)
    }
}
