// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub(crate) fn load_group_sender_key_state(
        &self,
        group_id: &str,
        sender_id: &str,
        group_key_epoch: u64,
        direction: &str,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        let checkpoint =
            group_sender_key_checkpoint_name(group_id, sender_id, group_key_epoch, direction);
        let event_id = self.projection_checkpoint(&checkpoint)?.ok_or_else(|| {
            SdkError::LocalBus(format!(
                "missing group sender key for {group_id}/{sender_id}/epoch {group_key_epoch}/{direction}"
            ))
        })?;
        let bytes = self.event_body(&event_id)?.ok_or_else(|| {
            SdkError::LocalBus(format!("missing group sender key event {event_id}"))
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(crate) fn persist_group_sender_key_state(
        &self,
        state: &SdkGroupSenderKeyState,
        direction: &str,
        event_suffix: &str,
    ) -> Result<(), SdkError> {
        let event_id = format!(
            "group.sender_key:{direction}:{}:{}:{}:{event_suffix}",
            state.group_id, state.sender_id, state.group_key_epoch
        );
        self.append_event(&event_id, "group.sender_key.state", &serde_json::to_vec(state)?)?;
        self.set_projection_checkpoint(
            &group_sender_key_checkpoint_name(
                &state.group_id,
                &state.sender_id,
                state.group_key_epoch,
                direction,
            ),
            &event_id,
        )
    }

    pub(crate) fn ensure_own_group_sender_key(
        &self,
        group_id: &str,
        sender_id: &str,
        group_key_epoch: u64,
    ) -> Result<SdkGroupSenderKeyState, SdkError> {
        if let Ok(state) =
            self.load_group_sender_key_state(group_id, sender_id, group_key_epoch, "send")
        {
            return Ok(state);
        }
        let root_seed = ramflux_crypto::random_32()?;
        let local_hash = group_sender_device_hash(group_id, sender_id, "local");
        let remote_hash = group_sender_device_hash(group_id, sender_id, "remote");
        let transcript_hash = group_sender_transcript_hash(group_id, sender_id, group_key_epoch);
        let state = SdkGroupSenderKeyState {
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch,
            session_snapshot: ramflux_crypto::DmSession::initiator(
                root_seed,
                local_hash,
                remote_hash,
                transcript_hash,
            )?
            .snapshot(),
        };
        self.persist_group_sender_key_state(&state, "send", "initial")?;
        Ok(state)
    }

    /// # Errors
    /// Returns an error when group membership, sender-key generation, or serialization fails.
    pub fn export_group_sender_key_distribution(
        &self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let group = self.group_state(group_id)?;
        if !group.members.contains(sender_id) {
            return Err(SdkError::from(StorageError::GroupPermissionDenied));
        }
        let state = self.ensure_own_group_sender_key(group_id, sender_id, group.group_epoch)?;
        let distribution = SdkGroupSenderKeyDistribution {
            schema: "ramflux.sdk.group_sender_key.distribution.v1".to_owned(),
            version: 1,
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            sender_key_seed: state.session_snapshot.root_key_bytes(),
        };
        Ok(serde_json::to_vec(&distribution)?)
    }

    /// # Errors
    /// Returns an error when the distribution is malformed or cannot be persisted.
    pub fn import_group_sender_key_distribution(
        &self,
        distribution_bytes: &[u8],
    ) -> Result<SdkGroupSenderKeyDistribution, SdkError> {
        let (distribution, _pending) =
            self.import_group_sender_key_distribution_inner(distribution_bytes, true)?;
        Ok(distribution)
    }

    pub(crate) fn import_group_sender_key_distribution_inner(
        &self,
        distribution_bytes: &[u8],
        retry_pending: bool,
    ) -> Result<(SdkGroupSenderKeyDistribution, Vec<SdkGroupPendingPlaintext>), SdkError> {
        let distribution: SdkGroupSenderKeyDistribution =
            serde_json::from_slice(distribution_bytes)?;
        if distribution.schema != "ramflux.sdk.group_sender_key.distribution.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group sender key distribution schema: {}",
                distribution.schema
            )));
        }
        let state = SdkGroupSenderKeyState {
            group_id: distribution.group_id.clone(),
            sender_id: distribution.sender_id.clone(),
            group_key_epoch: distribution.group_key_epoch,
            session_snapshot: ramflux_crypto::DmSession::recipient(
                distribution.sender_key_seed,
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "remote"),
                group_sender_device_hash(&distribution.group_id, &distribution.sender_id, "local"),
                group_sender_transcript_hash(
                    &distribution.group_id,
                    &distribution.sender_id,
                    distribution.group_key_epoch,
                ),
            )?
            .snapshot(),
        };
        self.persist_group_sender_key_state(&state, "recv", "import")?;
        let pending = if retry_pending {
            self.retry_pending_group_messages(&distribution.group_id, distribution.group_key_epoch)?
        } else {
            Vec::new()
        };
        Ok((distribution, pending))
    }

    pub(crate) fn retry_pending_group_messages(
        &self,
        group_id: &str,
        group_key_epoch: u64,
    ) -> Result<Vec<SdkGroupPendingPlaintext>, SdkError> {
        let pending = self.account_db()?.group_pending_undecrypted(group_id, group_key_epoch)?;
        let mut decrypted = Vec::new();
        for record in pending {
            if self
                .direct_messages(&record.conversation_id)?
                .iter()
                .any(|message| message.message_id == record.message_id)
            {
                self.account_db()?.remove_group_pending_undecrypted(&record.message_id)?;
                continue;
            }
            let entry: GatewayInboxEntry = serde_json::from_slice(&record.envelope_json)?;
            let encrypted_body =
                ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload).map_err(
                    |error| SdkError::LocalBus(format!("invalid pending group payload: {error}")),
                )?;
            let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&encrypted_body)?;
            if self.group_sender_key_counter_seen(&envelope)? {
                self.account_db()?.remove_group_pending_undecrypted(&record.message_id)?;
                continue;
            }
            match self.decrypt_group_envelope(&envelope, &record.message_id) {
                Ok(plaintext) => {
                    self.send_direct_message(
                        &record.conversation_id,
                        &record.message_id,
                        &envelope.sender_id,
                        &encrypted_body,
                    )?;
                    self.account_db()?.remove_group_pending_undecrypted(&record.message_id)?;
                    decrypted.push(SdkGroupPendingPlaintext {
                        group_id: record.group_id,
                        conversation_id: record.conversation_id,
                        message_id: record.message_id,
                        plaintext,
                    });
                }
                Err(error) if is_missing_group_sender_key_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(decrypted)
    }

    /// # Errors
    /// Returns an error when the sender cannot send or encryption/persistence fails.
    pub fn encrypt_group_message(
        &self,
        group_id: &str,
        sender_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let group = self.group_state(group_id)?;
        if !group.members.contains(sender_id) {
            return Err(SdkError::from(StorageError::GroupPermissionDenied));
        }
        let mut state = self.ensure_own_group_sender_key(group_id, sender_id, group.group_epoch)?;
        let associated_data = group_associated_data(group_id, sender_id, group.group_epoch);
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        let ciphertext = session.encrypt(plaintext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        self.persist_group_sender_key_state(
            &state,
            "send",
            &format!("send:{}", ciphertext.counter),
        )?;
        Ok(serde_json::to_vec(&SdkGroupEncryptedEnvelope {
            schema: "ramflux.sdk.group_sender_key.message.v1".to_owned(),
            version: 1,
            group_id: group_id.to_owned(),
            sender_id: sender_id.to_owned(),
            group_key_epoch: group.group_epoch,
            ciphertext,
        })?)
    }

    /// # Errors
    /// Returns an error when the sender key is missing, the message is malformed, or decryption
    /// fails.
    pub fn decrypt_group_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        let message = self
            .direct_messages(conversation_id)?
            .into_iter()
            .find(|message| message.message_id == message_id)
            .ok_or_else(|| SdkError::from(StorageError::MessageNotFound(message_id.to_owned())))?;
        let envelope: SdkGroupEncryptedEnvelope = serde_json::from_slice(&message.encrypted_body)?;
        self.decrypt_group_envelope(&envelope, message_id)
    }

    pub(crate) fn decrypt_group_envelope(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        message_id: &str,
    ) -> Result<Vec<u8>, SdkError> {
        if envelope.schema != "ramflux.sdk.group_sender_key.message.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group message schema: {}",
                envelope.schema
            )));
        }
        let mut state = self.load_group_sender_key_state(
            &envelope.group_id,
            &envelope.sender_id,
            envelope.group_key_epoch,
            "recv",
        )?;
        let associated_data = group_associated_data(
            &envelope.group_id,
            &envelope.sender_id,
            envelope.group_key_epoch,
        );
        let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot.clone())?;
        let plaintext = session.decrypt(&envelope.ciphertext, &associated_data)?;
        state.session_snapshot = session.snapshot();
        if !self.record_group_sender_key_counter(envelope, message_id)? {
            return Err(SdkError::LocalBus(format!(
                "replayed group sender-key counter for {}/{}/epoch {}/counter {}",
                envelope.group_id,
                envelope.sender_id,
                envelope.group_key_epoch,
                envelope.ciphertext.counter
            )));
        }
        self.persist_group_sender_key_state(
            &state,
            "recv",
            &format!("recv:{}", envelope.ciphertext.counter),
        )?;
        Ok(plaintext)
    }
}
