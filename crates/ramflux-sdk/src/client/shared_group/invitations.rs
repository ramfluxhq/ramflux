// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unknown groups stay outside joined projections until contact consent or explicit acceptance.
use crate::prelude::*;
use ramflux_crypto::VerifiedGroupState;
use serde::{Deserialize, Serialize};
const PREFIX: &str = "group-invitation/";
#[derive(Deserialize, Serialize)]
struct Invitation {
    snapshot: ramflux_protocol::GroupStateSnapshot,
    packet: zeroize::Zeroizing<Vec<u8>>,
    inviter: String,
    expires_at: i64,
    declined: bool,
    #[serde(default)]
    accepted: bool,
}
fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
impl RamfluxClient {
    fn group_parties_blocked(
        &self,
        snapshot: &ramflux_protocol::GroupStateSnapshot,
    ) -> Result<bool, SdkError> {
        for identity in [&snapshot.creator.identity, &snapshot.issuer.identity] {
            if self.friend_rejection_reason(&identity.root_commitment)?.as_deref()
                == Some("friend.blocked")
                || (self
                    .account_db()?
                    .client_record("identity", &identity.principal_id)?
                    .is_some_and(|row| {
                        row["contact_identity_commitment"] == identity.root_commitment
                    })
                    && self.friend_rejection_reason(&identity.principal_id)?.as_deref()
                        == Some("friend.blocked"))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(super) fn group_snapshot_requires_consent(
        &self,
        state: &VerifiedGroupState,
    ) -> Result<bool, SdkError> {
        let creator = &state.creator().identity;
        if self.group_parties_blocked(state.snapshot())? {
            return Err(super::invalid("group creator or inviter is blocked"));
        }
        self.check_group_decline_fence(&state.view().group_id)?;
        if let Some(previous) = self.account_db()?.shared_group_state(&state.view().group_id)? {
            if state.relation_to(&previous)? == ramflux_crypto::GroupStateRelation::Unrelated {
                return Err(super::invalid("group creator authority differs from joined group"));
            }
            return Ok(false);
        }
        let own = self.owned_device_identity()?;
        if state.view().effective_role(own.root_commitment(), own.device_id()).is_none() {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        if self
            .account_db()?
            .load_actor_state::<Invitation>(&key(&state.view().group_id))?
            .is_some_and(|row| {
                row.accepted
                    && row.expires_at > now_unix_timestamp()
                    && row.snapshot.genesis == *state.genesis()
            })
        {
            return Ok(false);
        }
        // A transport forwarder is never an inviter. Until a separately signed
        // invitation exists, only the creator can supply implicit contact consent.
        if self.accepted_contact_source(&creator.root_commitment, &creator.principal_id)? {
            return Ok(false);
        }
        Ok(true)
    }
    pub(crate) fn check_group_decline_fence(&self, group: &str) -> Result<(), SdkError> {
        if self
            .account_db()?
            .load_actor_state::<Invitation>(&key(group))?
            .is_some_and(|row| row.declined && row.expires_at > now_unix_timestamp())
        {
            return Err(super::invalid("group invitation was declined"));
        }
        Ok(())
    }
    pub(super) fn hold_group_invitation(
        &self,
        state: &VerifiedGroupState,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            let now = now_unix_timestamp();
            db.retain_expiring_actor_states(PREFIX, now, 128)?;
            let id = key(&state.view().group_id);
            if let Some(mut previous) = db.load_actor_state::<Invitation>(&id)? {
                if previous.declined || previous.snapshot.epoch >= state.view().epoch {
                    return Ok(());
                }
                if previous.snapshot.genesis != state.snapshot().genesis {
                    return Err(StorageError::GroupPermissionDenied.into());
                }
                previous.snapshot = state.snapshot().clone();
                previous.packet = zeroize::Zeroizing::new(body.to_vec());
                // A new snapshot never renews an unaccepted invitation's storage lifetime.
                db.persist_actor_state(&id, &previous)?;
                return Ok(());
            }
            let inviter = &state.creator().identity.root_commitment;
            let invitations = db.list_actor_states::<Invitation>(PREFIX)?;
            if invitations.len() >= 128
                || invitations.iter().filter(|row| !row.declined).count() >= 32
                || invitations.iter().filter(|row| row.inviter == *inviter && !row.declined).count()
                    >= 4
            {
                return Err(SdkError::ContactRequestCapacity(
                    "group invitation capacity exhausted".into(),
                ));
            }
            if !db.charge_contact_request(&format!("group-invite:{inviter}"), 4, 86400, now)? {
                return Err(SdkError::ContactRequestCapacity(
                    "group invitation rate exceeded".into(),
                ));
            }
            db.persist_actor_state(
                &id,
                &Invitation {
                    snapshot: state.snapshot().clone(),
                    packet: zeroize::Zeroizing::new(body.to_vec()),
                    inviter: inviter.clone(),
                    expires_at: now.saturating_add(7 * 86400),
                    declined: false,
                    accepted: false,
                },
            )?;
            Ok(())
        })
    }
    pub(crate) fn group_invitations(&self) -> Result<serde_json::Value, SdkError> {
        let now = now_unix_timestamp();
        let db = self.account_db()?;
        db.retain_expiring_actor_states(PREFIX, now, 128)?;
        let mut rows = Vec::new();
        for invitation in db.list_actor_states::<Invitation>(PREFIX)? {
            if invitation.declined || self.group_parties_blocked(&invitation.snapshot)? {
                continue;
            }
            rows.push(serde_json::json!({"group_id":invitation.snapshot.group_id,"name":invitation.snapshot.state.name,"creator":invitation.snapshot.creator.identity.root_commitment,"inviter":invitation.inviter,"expires_at":invitation.expires_at}));
        }
        Ok(serde_json::json!({"invitations":rows}))
    }
    pub(crate) fn decide_group_invitation(
        &self,
        group: &str,
        accept: bool,
        target: &str,
    ) -> Result<serde_json::Value, SdkError> {
        self.account_db()?.write_transaction(|| -> Result<serde_json::Value, SdkError> {
            let db = self.account_db()?;
            let mut invitation: Invitation =
                db.load_actor_state(&key(group))?.ok_or(StorageError::GroupPermissionDenied)?;
            if invitation.expires_at <= now_unix_timestamp() || invitation.declined {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            let state = ramflux_crypto::verify_group_state_snapshot(invitation.snapshot.clone())?;
            if accept {
                self.group_snapshot_requires_consent(&state)?;
                invitation.accepted = true;
                db.persist_actor_state(&key(group), &invitation)?;
                let prepared =
                    self.prepare_shared_group_payload(state.clone(), &invitation.packet)?;
                self.apply_prepared_shared_group(&prepared, target)?;
                crate::bus::enqueue_shared_group(self, &state, None)?;
                db.remove_actor_state(&key(group))?;
            } else {
                invitation.declined = true;
                invitation.packet.clear();
                // A declined invitation remains a small replay fence for its original window.
                invitation.snapshot.state.members.clear();
                db.persist_actor_state(&key(group), &invitation)?;
            }
            Ok(serde_json::json!({"group_id":group,"accepted":accept,"declined":!accept}))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::shared_group::tests::{person, temp_root};
    #[test]
    fn stranger_group_is_held_declined_and_blocked_without_joined_projection()
    -> Result<(), SdkError> {
        let root = temp_root("invitations")?;
        let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
        let peer = person(&root.join("peer"), "peer", "phone", 21, 22)?;
        owner.shared_group_create("group", "thread", None, "target-phone")?;
        let state = owner.shared_group_change(
            "group",
            "target-phone",
            ramflux_protocol::GroupStateChange::Add {
                member: peer.owned_group_actor("target-phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        assert!(peer.group_snapshot_requires_consent(&state)?);
        let body = super::super::bootstrap::packet_bytes(&state)?;
        peer.hold_group_invitation(&state, &body)?;
        assert!(peer.account_db()?.shared_group_state("group")?.is_none());
        assert!(peer.account_db()?.client_record("conversation", "thread")?.is_none());
        assert_eq!(peer.group_invitations()?["invitations"].as_array().map(Vec::len), Some(1));
        let before = peer
            .account_db()?
            .load_actor_state::<Invitation>(&key("group"))?
            .ok_or(StorageError::GroupPermissionDenied)?
            .expires_at;
        peer.hold_group_invitation(&state, &body)?;
        assert_eq!(
            peer.account_db()?
                .load_actor_state::<Invitation>(&key("group"))?
                .ok_or(StorageError::GroupPermissionDenied)?
                .expires_at,
            before
        );
        peer.decide_group_invitation("group", false, "target-phone")?;
        peer.hold_group_invitation(&state, &body)?;
        assert_eq!(peer.group_invitations()?["invitations"], serde_json::json!([]));
        let root_id = owner.owned_device_identity()?.root_commitment().to_owned();
        peer.establish_friend_link("blocked-inviter", "peer", &root_id)?;
        peer.block_friend_link("blocked-inviter")?;
        assert!(peer.group_snapshot_requires_consent(&state).is_err());
        drop((owner, peer));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn explicit_invitation_acceptance_and_contact_consent_adopt_only_signed_state()
    -> Result<(), SdkError> {
        let root = temp_root("invitation-accept")?;
        let owner = person(&root.join("owner"), "owner", "phone", 11, 12)?;
        let peer = person(&root.join("peer"), "peer", "phone", 21, 22)?;
        owner.shared_group_create("group", "thread", None, "target-phone")?;
        let state = owner.shared_group_change(
            "group",
            "target-phone",
            ramflux_protocol::GroupStateChange::Add {
                member: peer.owned_group_actor("target-phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        peer.hold_group_invitation(&state, &super::super::bootstrap::packet_bytes(&state)?)?;
        peer.decide_group_invitation("group", true, "target-phone")?;
        assert_eq!(
            peer.account_db()?
                .shared_group_state("group")?
                .ok_or(StorageError::GroupPermissionDenied)?
                .view(),
            state.view()
        );
        assert!(!peer.group_snapshot_requires_consent(&state)?);
        let remote = owner.owned_device_identity()?.root_commitment().to_owned();
        peer.establish_friend_link("formerly-contact", "peer", &remote)?;
        peer.remove_friend_link("formerly-contact", "me")?;
        assert!(!peer.friend_link_peer_is_accepted(&remote)?);
        assert!(
            !peer.group_snapshot_requires_consent(&state)?,
            "contact removal does not revoke joined group membership"
        );
        peer.block_friend_link("formerly-contact")?;
        assert!(
            peer.group_snapshot_requires_consent(&state).is_err(),
            "explicit blocks apply even after joining"
        );
        drop((owner, peer));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
