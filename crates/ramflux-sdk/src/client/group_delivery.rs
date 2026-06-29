// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn append_gateway_delivery(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        if self.event_body(&entry.envelope.envelope_id)?.is_some() {
            return Ok(());
        }
        let body = ramflux_protocol::canonical_json_bytes(&entry.envelope)?;
        self.append_event(&entry.envelope.envelope_id, "gateway.deliver.opaque", &body)
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
        match self.append_group_gateway_delivery_for_recipient(
            conversation_id,
            "",
            message_id,
            entry,
            "",
        )? {
            GroupGatewayDeliveryResult::Message(plaintext) => Ok(plaintext),
            GroupGatewayDeliveryResult::SenderKeyDistribution(_) => Ok(Vec::new()),
        }
    }

    pub(crate) fn append_group_gateway_delivery_for_recipient(
        &self,
        conversation_id: &str,
        group_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        recipient_device_id: &str,
    ) -> Result<GroupGatewayDeliveryResult, SdkError> {
        self.append_gateway_delivery(entry)?;
        let encrypted_body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|error| SdkError::LocalBus(format!("invalid group payload: {error}")))?;
        if let Ok(envelope) = serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&encrypted_body)
            && envelope.schema == "ramflux.sdk.group_sender_key.message.v1"
        {
            return self
                .append_or_pending_group_message(
                    conversation_id,
                    message_id,
                    entry,
                    &encrypted_body,
                    &envelope,
                )
                .map(GroupGatewayDeliveryResult::Message);
        }
        let conversation_id = group_sender_key_distribution_conversation_id(
            group_id,
            &entry.envelope.source_device_id,
            recipient_device_id,
        );
        let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&encrypted_body)?;
        let mut session =
            self.load_or_create_recv_dm_session(&conversation_id, envelope.x3dh.as_ref())?;
        let plaintext =
            session.decrypt(&envelope.ciphertext, dm_associated_data(&conversation_id))?;
        self.persist_dm_session(&conversation_id, &entry.envelope.envelope_id, "recv", &session)?;
        if self.apply_group_control_plaintext(&plaintext)?.is_some() {
            return Ok(GroupGatewayDeliveryResult::Message(Vec::new()));
        }
        let wrapper: SdkGroupSenderKeyDistributionEnvelope = serde_json::from_slice(&plaintext)?;
        if wrapper.schema != "ramflux.sdk.group_sender_key.distribution_envelope.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group sender-key distribution wrapper schema: {}",
                wrapper.schema
            )));
        }
        if wrapper.membership_event_base64.is_some() {
            return Err(SdkError::LocalBus(
                "group membership bootstrap requires verified gateway context".to_owned(),
            ));
        }
        let distribution = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
            .map_err(|error| {
                SdkError::LocalBus(format!("invalid sender key distribution payload: {error}"))
            })?;
        self.import_group_sender_key_distribution_inner(&distribution, false)
            .map(|(distribution, _pending)| distribution)
            .map(GroupGatewayDeliveryResult::SenderKeyDistribution)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn append_group_gateway_delivery_for_recipient_with_gateway(
        &self,
        gateway: &GatewaySessionConfig,
        conversation_id: &str,
        group_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        recipient_device_id: &str,
    ) -> Result<GroupGatewayDeliveryResult, SdkError> {
        self.append_gateway_delivery(entry)?;
        let encrypted_body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|error| SdkError::LocalBus(format!("invalid group payload: {error}")))?;
        if let Ok(envelope) = serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&encrypted_body)
            && envelope.schema == "ramflux.sdk.group_sender_key.message.v1"
        {
            return self
                .append_or_pending_group_message(
                    conversation_id,
                    message_id,
                    entry,
                    &encrypted_body,
                    &envelope,
                )
                .map(GroupGatewayDeliveryResult::Message);
        }
        let conversation_id = group_sender_key_distribution_conversation_id(
            group_id,
            &entry.envelope.source_device_id,
            recipient_device_id,
        );
        let envelope: SdkDmEncryptedEnvelope = serde_json::from_slice(&encrypted_body)?;
        let mut session =
            self.load_or_create_recv_dm_session(&conversation_id, envelope.x3dh.as_ref())?;
        let plaintext =
            session.decrypt(&envelope.ciphertext, dm_associated_data(&conversation_id))?;
        self.persist_dm_session(&conversation_id, &entry.envelope.envelope_id, "recv", &session)?;
        if self.apply_group_control_plaintext(&plaintext)?.is_some() {
            return Ok(GroupGatewayDeliveryResult::Message(Vec::new()));
        }
        let wrapper: SdkGroupSenderKeyDistributionEnvelope = serde_json::from_slice(&plaintext)?;
        if wrapper.schema != "ramflux.sdk.group_sender_key.distribution_envelope.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group sender-key distribution wrapper schema: {}",
                wrapper.schema
            )));
        }
        self.apply_sender_key_membership_bootstrap(gateway, entry, recipient_device_id, &wrapper)
            .await?;
        let distribution = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
            .map_err(|error| {
                SdkError::LocalBus(format!("invalid sender key distribution payload: {error}"))
            })?;
        self.import_group_sender_key_distribution_inner(&distribution, false)
            .map(|(distribution, _pending)| distribution)
            .map(GroupGatewayDeliveryResult::SenderKeyDistribution)
    }

    async fn apply_sender_key_membership_bootstrap(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        recipient_device_id: &str,
        wrapper: &SdkGroupSenderKeyDistributionEnvelope,
    ) -> Result<(), SdkError> {
        let Some(event_base64) = wrapper.membership_event_base64.as_deref() else {
            return Ok(());
        };
        let event_bytes = ramflux_protocol::decode_base64url(event_base64).map_err(|error| {
            SdkError::LocalBus(format!("invalid group membership event: {error}"))
        })?;
        let event: ramflux_protocol::GroupEvent = serde_json::from_slice(&event_bytes)?;
        let ramflux_protocol::GroupEventBody::MemberJoined {
            actor_principal_commitment,
            actor_device_signing_public_key,
            joined_identity,
            ..
        } = &event.body
        else {
            return Err(SdkError::LocalBus(
                "group sender-key membership event must be member_joined".to_owned(),
            ));
        };
        if joined_identity != recipient_device_id {
            return Err(SdkError::LocalBus(format!(
                "group membership event joined identity {joined_identity} does not match local device {recipient_device_id}"
            )));
        }
        let actor_device = self
            .assert_manifest_active_device_cached(
                gateway,
                actor_principal_commitment,
                &event.actor_device_id,
                "group.member_joined.bootstrap",
            )
            .await?;
        if actor_device.branch_public_key != *actor_device_signing_public_key {
            return Err(SdkError::LocalBus(
                "group membership event actor key does not match verified manifest".to_owned(),
            ));
        }
        self.apply_bootstrap_group_member_join_event(
            &event,
            &entry.envelope.source_device_id,
            &actor_device.branch_public_key,
        )?;
        Ok(())
    }

    pub(crate) fn append_or_pending_group_message(
        &self,
        conversation_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        encrypted_body: &[u8],
        envelope: &SdkGroupEncryptedEnvelope,
    ) -> Result<Vec<u8>, SdkError> {
        if self
            .direct_messages(conversation_id)?
            .iter()
            .any(|message| message.message_id == message_id)
        {
            self.account_db()?.remove_group_pending_undecrypted(message_id)?;
            return Ok(Vec::new());
        }
        if self.group_sender_key_counter_seen(envelope)? {
            self.account_db()?.remove_group_pending_undecrypted(message_id)?;
            return Ok(Vec::new());
        }
        match self.decrypt_group_envelope(envelope, message_id) {
            Ok(plaintext) => {
                if self.apply_group_control_plaintext(&plaintext)?.is_some() {
                    self.account_db()?.remove_group_pending_undecrypted(message_id)?;
                    return Ok(Vec::new());
                }
                self.send_direct_message(
                    conversation_id,
                    message_id,
                    &envelope.sender_id,
                    encrypted_body,
                )?;
                self.account_db()?.remove_group_pending_undecrypted(message_id)?;
                Ok(plaintext)
            }
            Err(error) if is_missing_group_sender_key_error(&error) => {
                self.account_db()?.upsert_group_pending_undecrypted(
                    &GroupPendingUndecryptedRecord {
                        group_id: envelope.group_id.clone(),
                        conversation_id: conversation_id.to_owned(),
                        group_key_epoch: envelope.group_key_epoch,
                        message_id: message_id.to_owned(),
                        sender_id: envelope.sender_id.clone(),
                        inbox_seq: entry.inbox_seq,
                        envelope_json: serde_json::to_vec(entry)?,
                        created_at: now_unix_timestamp(),
                    },
                )?;
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    fn apply_group_control_plaintext(
        &self,
        plaintext: &[u8],
    ) -> Result<Option<GroupState>, SdkError> {
        let Ok(envelope) = serde_json::from_slice::<SdkGroupControlEnvelope>(plaintext) else {
            return Ok(None);
        };
        if envelope.schema != "ramflux.sdk.group_control.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported group control schema: {}",
                envelope.schema
            )));
        }
        Ok(Some(self.apply_group_control_event(&envelope.event)?))
    }

    pub(crate) fn group_sender_key_counter_seen(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
    ) -> Result<bool, SdkError> {
        self.account_db()?
            .group_sender_key_counter_seen(
                &envelope.group_id,
                envelope.group_key_epoch,
                &envelope.sender_id,
                envelope.ciphertext.counter,
            )
            .map_err(SdkError::from)
    }

    pub(crate) fn record_group_sender_key_counter(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        message_id: &str,
    ) -> Result<bool, SdkError> {
        self.account_db()?
            .record_group_sender_key_counter(&GroupSenderKeyCounterRecord {
                group_id: envelope.group_id.clone(),
                group_key_epoch: envelope.group_key_epoch,
                sender_id: envelope.sender_id.clone(),
                counter: envelope.ciphertext.counter,
                message_id: message_id.to_owned(),
                seen_at: now_unix_timestamp(),
            })
            .map_err(SdkError::from)
    }
}
