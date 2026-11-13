// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender side of peer controls 5/9/11/12: build the typed Control Inner once per logical
//! operation and capture its exact bytes durably, so a retry resends the same event identity.
//! Dormant until the schema gate selects message schema v1; nothing here sends.
use super::{a2i, content, group_key, guardian};
use crate::client::recovery::{SdkGuardianAcceptMessage, SdkGuardianInviteMessage};
use crate::{RamfluxClient, SdkError, SdkGroupSenderKeyDistribution};
use prost::Message as _;
use ramflux_protocol::message as g;
use zeroize::Zeroizing;

fn capture_key(operation_key: &str) -> String {
    format!(
        "routed/native-control-outbound/{}",
        ramflux_protocol::encode_base64url(blake3::hash(operation_key.as_bytes()).as_bytes())
    )
}

impl RamfluxClient {
    /// One logical operation, one event identity, one exact byte string. The capture row is
    /// written in the transaction that allocates the identity; a second call with the same
    /// operation key returns the captured bytes and refuses a changed payload.
    fn produce_generated_peer_control(
        &self,
        conversation: &str,
        group: Option<(&str, u64)>,
        payload: g::control::Payload,
        operation_key: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let control = crate::client::generated_control::control_from_payload(payload)?;
        crate::client::generated_control::validate_control_native(&control)?;
        let body = Zeroizing::new(control.encode_to_vec());
        let key = capture_key(operation_key);
        let own = self.owned_device_identity()?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            if let Some(cached) = db.load_actor_state::<String>(&key)? {
                let bytes = Zeroizing::new(
                    ramflux_protocol::decode_base64url(&cached)
                        .map_err(|_| SdkError::ReplayMismatch)?,
                );
                let inner =
                    g::Inner::decode(bytes.as_slice()).map_err(|_| SdkError::ReplayMismatch)?;
                let identity = inner.identity.as_ref().ok_or(SdkError::ReplayMismatch)?;
                if inner.kind != 8
                    || inner.body != *body
                    || identity.conversation_id != conversation
                    || identity.group_id.as_deref() != group.map(|(id, _)| id)
                    || g::identity::verify(identity).is_err()
                    || identity.author.as_ref().is_none_or(|author| {
                        author.account_anchor != own.root_commitment()
                            || author.device_id != own.device_id()
                    })
                {
                    return Err(SdkError::ReplayMismatch);
                }
                return Ok(bytes);
            }
            let mut identity = self.allocate_generated_identity(
                conversation,
                crate::client::generated_identity::now_ms(),
                false,
            )?;
            if let Some((group_id, epoch)) = group {
                // Same binding as the Snapshot producer: group scope and verified state epoch.
                identity.group_id = Some(group_id.to_owned());
                identity.group_epoch = Some(epoch);
            }
            let bytes = Zeroizing::new(Self::encode_generated_inner(
                identity,
                &g::Content { value: Some(g::content::Value::Control(control.clone())) },
            )?);
            db.persist_actor_state(&key, &ramflux_protocol::encode_base64url(bytes.as_slice()))?;
            Ok(bytes)
        })
    }

    /// Drop the captured bytes once the transport reports the control delivered. The capture of
    /// a guardian invite holds the recovery share, so it must not outlive delivery.
    /// # Errors
    /// Returns a storage error when the capture row cannot be removed.
    pub fn retire_generated_peer_control(&self, operation_key: &str) -> Result<(), SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        Ok(self.account_db()?.remove_actor_state(&capture_key(operation_key))?)
    }

    fn peer_scope(&self, peer_root: &str) -> Result<String, SdkError> {
        g::dm_scope::derive(&self.own_account_anchor()?, peer_root)
            .map_err(|_| content("peer control scope"))
    }

    /// `CONTROL_GROUP_KEY` for one recipient device of `conversation` (the group conversation).
    /// `group_epoch` is the verified group state epoch, as in the Snapshot producer.
    /// Additive candidate API; does not send.
    /// # Errors
    /// Refuses a distribution this device did not author or a failed native check.
    pub fn generated_group_key_inner(
        &self,
        conversation: &str,
        group_epoch: u64,
        distribution: &SdkGroupSenderKeyDistribution,
        recipient_device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        if distribution.sender_id != self.owned_device_identity()?.device_id() {
            return Err(content("group key producer must be its sender"));
        }
        let payload = g::control::Payload::GroupKeyControl(g::GroupKeyControl {
            schema: group_key::WRAPPER_SCHEMA.into(),
            version: 1,
            membership_event: None,
            actor_manifest_url: None,
            distribution: Some(group_key::generated_distribution(distribution)),
        });
        self.produce_generated_peer_control(
            conversation,
            Some((&distribution.group_id, group_epoch)),
            payload,
            &format!(
                "group-key/{}/{}/{}",
                distribution.group_id,
                distribution.group_key_epoch,
                recipient_device.storage_key()
            ),
        )
    }

    /// `CONTROL_RECOVERY` invite. Records the issued invite so a later accept can be bound.
    /// Additive candidate API; does not send.
    /// # Errors
    /// Refuses an invite this device did not author or an invite id reused with other terms.
    pub fn generated_guardian_invite_inner(
        &self,
        invite: &SdkGuardianInviteMessage,
        guardian_root: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if invite.inviter_principal_id != branch.principal_id
            || invite.inviter_device_id != branch.device_id
        {
            return Err(content("guardian invite producer must be its inviter"));
        }
        let payload = g::control::Payload::RecoveryControl(g::RecoveryControl {
            payload: Some(g::recovery_control::Payload::Invite(guardian::invite_to_generated(
                invite,
            )?)),
        });
        let db = self.account_db()?;
        db.write_transaction(|| {
            let issued = guardian::IssuedGuardianInvite {
                guardian_principal_id: invite.guardian_principal_id.clone(),
                recovery_quorum_id: invite.recovery_quorum_id.clone(),
                expires_at: invite.expires_at,
            };
            let key = guardian::issued_key(&invite.invite_id);
            match db.load_actor_state::<guardian::IssuedGuardianInvite>(&key)? {
                Some(old) if old != issued => return Err(SdkError::ReplayMismatch),
                Some(_) => {}
                None => db.persist_actor_state(&key, &issued)?,
            }
            self.produce_generated_peer_control(
                &self.peer_scope(guardian_root)?,
                None,
                payload,
                &format!("guardian-invite/{}", invite.invite_id),
            )
        })
    }

    /// `CONTROL_RECOVERY` accept, sent by the guardian after the local user accepted the invite.
    /// Additive candidate API; does not send.
    /// # Errors
    /// Refuses an accept this device did not author or a changed retry.
    pub fn generated_guardian_accept_inner(
        &self,
        accept: &SdkGuardianAcceptMessage,
        owner_root: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if accept.guardian_principal_id != branch.principal_id
            || accept.guardian_device_id != branch.device_id
        {
            return Err(content("guardian accept producer must be the guardian"));
        }
        self.produce_generated_peer_control(
            &self.peer_scope(owner_root)?,
            None,
            g::control::Payload::RecoveryControl(g::RecoveryControl {
                payload: Some(g::recovery_control::Payload::Accept(guardian::accept_to_generated(
                    accept,
                ))),
            }),
            &format!("guardian-accept/{owner_root}/{}", accept.invite_id),
        )
    }

    /// `CONTROL_A2I` from an already signed native document authored by this device.
    /// Additive candidate API; does not send.
    /// # Errors
    /// Refuses an event this device did not author or one that fails the typed round trip.
    pub fn generated_a2i_inner(
        &self,
        event: &ramflux_protocol::A2iControlEvent,
        target_root: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        Self::require_a2i_binding_authority()?;
        if event.source_device_id != self.owned_device_identity()?.device_id() {
            return Err(content("a2i producer must be its source device"));
        }
        self.produce_generated_peer_control(
            &self.peer_scope(target_root)?,
            None,
            g::control::Payload::A2i(a2i::to_generated(event)?),
            &format!("a2i/{}/{}", event.target_device_id, event.correlation_id),
        )
    }

    /// `CONTROL_OBJECT_REVOKE` for one recipient root of an object this account shared.
    /// Additive candidate API; does not send.
    /// # Errors
    /// Refuses incomplete revoke fields or a changed retry.
    pub fn generated_object_revoke_inner(
        &self,
        revoke: g::ObjectRevokeAccess,
        recipient_root: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let operation_key = format!(
            "object-revoke/{}/{}/{}",
            revoke.object_id, revoke.recipient_principal_id, revoke.link_id
        );
        self.produce_generated_peer_control(
            &self.peer_scope(recipient_root)?,
            None,
            g::control::Payload::ObjectRevoke(revoke),
            &operation_key,
        )
    }
}
