// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#[cfg(test)]
use crate::client::identity_authority::{HeadUse, NativeOperation};
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
    pub(crate) fn append_group_gateway_delivery_for_recipient(
        &self,
        conversation_id: &str,
        group_id: &str,
        message_id: &str,
        entry: &GatewayInboxEntry,
        recipient_device_id: &str,
    ) -> Result<GroupGatewayDeliveryResult, SdkError> {
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        self.require_native_operation(
            &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            NativeOperation::Group,
        )?;
        self.append_gateway_delivery(entry)?;
        let encrypted_body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
            .map_err(|error| SdkError::LocalBus(format!("invalid group payload: {error}")))?;
        if let Ok(envelope) = serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&encrypted_body)
            && crate::group::group_message_schema(&envelope.schema)
        {
            if envelope.group_id != group_id {
                return Err(SdkError::InboundRejected(
                    "legacy group envelope differs from requested group".to_owned(),
                ));
            }
            return self
                .append_or_pending_group_message(
                    conversation_id,
                    message_id,
                    entry,
                    &encrypted_body,
                    &envelope,
                )
                .map(|_| GroupGatewayDeliveryResult::Message);
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
        validate_legacy_group_payload(&plaintext, group_id)?;
        self.persist_dm_session(&conversation_id, &entry.envelope.envelope_id, "recv", &session)?;
        if self.apply_group_control_plaintext(&plaintext)?.is_some() {
            return Ok(GroupGatewayDeliveryResult::Message);
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
        let parsed: SdkGroupSenderKeyDistribution = serde_json::from_slice(&distribution)?;
        self.require_group_payload_sender(&parsed.group_id, &parsed.sender_id, entry)?;
        self.import_group_sender_key_distribution_inner(&distribution, false)
            .map(|_| GroupGatewayDeliveryResult::SenderKeyDistribution)
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
    pub(crate) fn apply_group_control_plaintext(
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

#[cfg(test)]
fn validate_legacy_group_payload(body: &[u8], expected: &str) -> Result<(), SdkError> {
    let actual = if let Ok(control) = serde_json::from_slice::<SdkGroupControlEnvelope>(body) {
        serde_json::to_value(control.event.body)?
            .get("group_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        let wrapper: SdkGroupSenderKeyDistributionEnvelope = serde_json::from_slice(body)?;
        let bytes = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
            .map_err(|_| SdkError::InboundRejected("invalid legacy distribution".to_owned()))?;
        let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
        Some(distribution.group_id)
    };
    if actual.as_deref() != Some(expected) {
        return Err(SdkError::InboundRejected(
            "legacy group payload differs from requested group".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::client::native_test_support::{Fixture, TestResult};

    #[tokio::test]
    async fn active_group_plan_uses_verified_members_and_refuses_absent_authority() -> TestResult {
        let owner = Fixture::with_device("p05-gd-owner", "owner").await?;
        let peer = Fixture::with_device("p05-gd-peer", "peer").await?;
        owner.client.persist_fetched_identity_directory(&peer.manifest)?;
        let primary = owner
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native account")?
            .group_primary(owner.vault.as_ref())?;
        owner.client.shared_group_create_with_primary(
            "g1",
            "g1-thread",
            None,
            &owner.config.target_delivery_id,
            Some(&primary),
        )?;
        let member = peer.client.owned_group_actor(&peer.config.target_delivery_id)?;
        owner.client.shared_group_change_with_primary(
            "g1",
            &owner.config.target_delivery_id,
            ramflux_protocol::GroupStateChange::Add {
                member: member.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        let plan = owner
            .client
            .candidate_group_target_plan(
                "g1",
                "owner",
                "event-1",
                ramflux_protocol::message::KindId::KindControl,
            )?
            .ok_or("active group plan")?;
        assert!(
            plan.representations.iter().any(|row| row
                .targets
                .iter()
                .any(|target| target.device_id == peer.config.device_id)),
            "generation 1 must plan the verified group peer",
        );
        assert!(
            matches!(
                owner.client.candidate_group_target_plan(
                    "missing-group",
                    "owner",
                    "event-2",
                    ramflux_protocol::message::KindId::KindControl,
                ),
                Err(crate::SdkError::GeneratedRefused {
                    code: crate::GeneratedRefusalCode::Authority,
                    ..
                })
            ),
            "generation 1 must propagate missing group authority instead of skipping selection"
        );
        Ok(())
    }
}
