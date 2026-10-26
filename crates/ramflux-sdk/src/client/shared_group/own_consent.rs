// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account decisions replicate inside current-root authenticated own-device packets.
use crate::prelude::*;
use ramflux_crypto::{RootQualifiedDeviceRef, VerifiedGroupState};
use ramflux_protocol::{GroupStateActor, GroupStateSnapshot};
use serde::{Deserialize, Serialize};
const DOMAIN: &str = "ramflux.sdk.own_group_consent.v1";
const PREFIX: &[u8] = b"ramflux.own_group_consent.v1\n";
const STORED: &str = "group-account-consent/";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    schema: String,
    actor: GroupStateActor,
    snapshot: GroupStateSnapshot,
    accepted: bool,
    issued_at: i64,
    expires_at: i64,
    signature: String,
}
#[derive(Serialize, Deserialize)]
struct Decision {
    genesis_hash: String,
    accepted: bool,
    issued_at: i64,
    expires_at: i64,
}
fn key(group: &str) -> String {
    format!("{STORED}{}", ramflux_protocol::encode_base64url(group))
}
fn signing(consent: &Consent) -> Result<serde_json::Value, SdkError> {
    let mut value = serde_json::to_value(consent)?;
    value
        .as_object_mut()
        .ok_or_else(|| super::invalid("group consent object"))?
        .remove("signature");
    Ok(serde_json::json!({"domain":DOMAIN,"body":value}))
}
impl RamfluxClient {
    pub(super) fn own_group_acceptance(
        &self,
        state: &VerifiedGroupState,
    ) -> Result<bool, SdkError> {
        let genesis_hash = state.genesis_hash()?;
        Ok(self
            .account_db()?
            .load_actor_state::<Decision>(&key(&state.view().group_id))?
            .is_some_and(|decision| {
                decision.accepted
                    && decision.expires_at > now_unix_timestamp()
                    && genesis_hash == decision.genesis_hash
            }))
    }
    pub(super) fn own_group_declined(&self, group: &str) -> Result<bool, SdkError> {
        Ok(self.account_db()?.load_actor_state::<Decision>(&key(group))?.is_some_and(|decision| {
            !decision.accepted && decision.expires_at > now_unix_timestamp()
        }))
    }
    fn save_own_group_decision(
        &self,
        consent: &Consent,
        state: &VerifiedGroupState,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if let Some(old) = db.load_actor_state::<Decision>(&key(&state.view().group_id))?
            && old.expires_at > now_unix_timestamp()
        {
            if old.genesis_hash != state.genesis_hash()? {
                return Err(super::invalid("group consent genesis mismatch"));
            }
            if consent.issued_at < old.issued_at
                || (consent.issued_at == old.issued_at && (!old.accepted || consent.accepted))
            {
                return Ok(false);
            }
        }
        db.retain_expiring_actor_states(STORED, now_unix_timestamp(), 4096)?;
        let id = key(&state.view().group_id);
        if !db.actor_state_exists(&id)? && db.actor_state_usage(STORED)?.0 >= 4096 {
            return Err(SdkError::ContactRequestCapacity("group account decision capacity".into()));
        }
        db.persist_actor_state(
            &id,
            &Decision {
                genesis_hash: state.genesis_hash()?,
                accepted: consent.accepted,
                issued_at: consent.issued_at,
                expires_at: consent.expires_at,
            },
        )?;
        Ok(true)
    }
    pub(super) fn publish_own_group_decision(
        &self,
        state: &VerifiedGroupState,
        accepted: bool,
        target: &str,
    ) -> Result<(), SdkError> {
        let stored =
            self.account_db()?.load_actor_state::<Decision>(&key(&state.view().group_id))?;
        let now = now_unix_timestamp()
            .max(stored.map_or(0, |decision| decision.issued_at.saturating_add(1)));
        let mut consent = Consent {
            schema: DOMAIN.into(),
            actor: self.owned_group_actor(target)?,
            snapshot: state.snapshot().clone(),
            accepted,
            issued_at: now,
            expires_at: now.saturating_add(7 * 86400),
            signature: String::new(),
        };
        consent.signature = ramflux_crypto::sign_with_device_branch(
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &signing(&consent)?,
        )?;
        if !self.save_own_group_decision(&consent, state)? {
            return Err(super::invalid("local group decision did not supersede stored state"));
        }
        let mut body = PREFIX.to_vec();
        body.extend(serde_json::to_vec(&consent)?);
        let id = ramflux_protocol::hash_base64url(DOMAIN, &body);
        crate::bus::own_device_copy::stage(
            self,
            crate::client::own_device_copy::OwnMessageInput {
                id: &id,
                created_at: now,
                conversation: "own-group-consent",
                group: None,
                body: &body,
            },
            None,
        )
    }
    /// The containing own-device packet must authenticate a current sibling first.
    pub(crate) fn receive_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else { return Ok(false) };
        if raw.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES * 2 {
            return Err(super::invalid("group consent byte budget"));
        }
        let consent: Consent = ramflux_protocol::parse_i_json(raw)?;
        let state = self.verify_own_group_consent(source, &consent)?;
        let group = &state.view().group_id;
        if self
            .account_db()?
            .shared_group_state(group)?
            .is_some_and(|old| old.genesis() != state.genesis())
        {
            return Err(super::invalid("group consent genesis mismatch"));
        }
        if consent.accepted && self.group_parties_blocked(state.snapshot())? {
            return Ok(true);
        }
        // An undated legacy decline cannot be overridden by a delayed signed copy.
        if consent.accepted
            && self.group_invitation_declined(group)?
            && self.account_db()?.load_actor_state::<Decision>(&key(group))?.is_none()
        {
            return Ok(true);
        }
        self.account_db()?.write_transaction(|| -> Result<bool, SdkError> {
            if !self.save_own_group_decision(&consent, &state)? {
                return Ok(true);
            }
            self.apply_own_group_invitation_decision(&state, consent.accepted, consent.expires_at)?;
            Ok(true)
        })
    }
    fn verify_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        consent: &Consent,
    ) -> Result<VerifiedGroupState, SdkError> {
        let own = self.owned_device_identity()?;
        let actor = &consent.actor.identity;
        let now = now_unix_timestamp();
        self.require_cached_root_authority(source)?;
        if source.root_commitment() != own.root_commitment()
            || actor.root_commitment != source.root_commitment()
            || actor.device_id != source.device_id()
            || self.trusted_device(source)?["signing_public_key"] != actor.signing_public_key
            || consent.schema != DOMAIN
            || consent.issued_at < 0
            || consent.issued_at > now.saturating_add(300)
            || consent.expires_at <= now
            || consent.expires_at <= consent.issued_at
            || consent.expires_at > consent.issued_at.saturating_add(7 * 86400)
        {
            return Err(super::invalid("group consent authority or lifetime mismatch"));
        }
        ramflux_crypto::verify_group_state_actor(&consent.actor)?;
        ramflux_crypto::verify_device_branch_signature(
            &actor.signing_public_key,
            &signing(consent)?,
            &consent.signature,
        )?;
        let state = ramflux_crypto::verify_group_state_snapshot(consent.snapshot.clone())?;
        if consent.accepted
            && state.view().effective_role(&actor.root_commitment, &actor.device_id).is_none()
        {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r8_local_decision_advances_past_a_future_account_decision_and_matches_reply()
    -> Result<(), SdkError> {
        use crate::client::identity_authority::test_support::public_manifest;
        let path = super::super::tests::temp_root("local-consent-clock")?;
        let phone = super::super::tests::person(&path.join("phone"), "owner", "phone", 11, 12)?;
        let stranger =
            super::super::tests::person(&path.join("stranger"), "stranger", "stranger", 21, 22)?;
        phone.persist_identity_directory(&public_manifest(&phone)?)?;
        for accepted in [true, false] {
            let group = if accepted { "accept" } else { "decline" };
            stranger.shared_group_create(group, group, None, "target-stranger")?;
            let state = stranger.shared_group_change(
                group,
                "target-stranger",
                ramflux_protocol::GroupStateChange::Add {
                    member: phone.owned_group_actor("target-phone")?.identity,
                    role: ramflux_protocol::SharedGroupRole::Member,
                },
            )?;
            phone.hold_group_invitation(&state, &super::super::bootstrap::packet_bytes(&state)?)?;
            let future = now_unix_timestamp() + 120;
            phone.account_db()?.persist_actor_state(
                &key(group),
                &Decision {
                    genesis_hash: state.genesis_hash()?,
                    accepted: !accepted,
                    issued_at: future,
                    expires_at: future + 7 * 86400,
                },
            )?;
            let reply = phone.decide_group_invitation(group, accepted, "target-phone")?;
            assert_eq!(reply["accepted"], accepted);
            let saved: Decision = phone
                .account_db()?
                .load_actor_state(&key(group))?
                .ok_or(StorageError::AuthorizationRejected)?;
            assert_eq!(saved.issued_at, future + 1);
            assert_eq!(saved.accepted, accepted);
            assert_eq!(phone.local_is_group_member(group)?, accepted);
        }
        drop((phone, stranger));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
    #[test]
    fn r7_signed_account_decisions_follow_time_and_decline_wins_ties() -> Result<(), SdkError> {
        use crate::client::identity_authority::test_support::{public_manifest, sign_manifest};
        let path = super::super::tests::temp_root("ordered-consent")?;
        let phone = super::super::tests::person(&path.join("phone"), "owner", "phone", 11, 12)?;
        let laptop = super::super::tests::person(&path.join("laptop"), "owner", "laptop", 11, 32)?;
        let stranger =
            super::super::tests::person(&path.join("stranger"), "stranger", "stranger", 21, 22)?;
        let mut own = public_manifest(&phone)?;
        own.devices.extend(public_manifest(&laptop)?.devices);
        sign_manifest(
            phone.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut own,
            2,
        )?;
        for client in [&phone, &laptop] {
            client.persist_identity_directory(&own)?;
        }
        stranger.shared_group_create("group", "thread", None, "target-stranger")?;
        let state = stranger.shared_group_change(
            "group",
            "target-stranger",
            ramflux_protocol::GroupStateChange::Add {
                member: phone.owned_group_actor("target-phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        let now = now_unix_timestamp();
        let make = |client: &RamfluxClient, accepted, at| -> Result<Vec<u8>, SdkError> {
            let own = client.owned_device_identity()?;
            let mut consent = Consent {
                schema: DOMAIN.into(),
                actor: client.owned_group_actor(&format!("target-{}", own.device_id()))?,
                snapshot: state.snapshot().clone(),
                accepted,
                issued_at: at,
                expires_at: at + 7 * 86400,
                signature: String::new(),
            };
            consent.signature = ramflux_crypto::sign_with_device_branch(
                client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &signing(&consent)?,
            )?;
            let mut bytes = PREFIX.to_vec();
            bytes.extend(serde_json::to_vec(&consent)?);
            Ok(bytes)
        };
        // Two independently signed devices disagree; delivery order must not choose the winner.
        let decline = make(&phone, false, now - 20)?;
        let accept = make(&laptop, true, now - 10)?;
        for client in [&phone, &laptop] {
            client.receive_own_group_consent(&phone.owned_device_identity()?, &decline)?;
            client.receive_own_group_consent(&laptop.owned_device_identity()?, &accept)?;
            client.receive_own_group_consent(&phone.owned_device_identity()?, &decline)?;
            assert!(client.local_is_group_member("group")?);
            let tie = make(&phone, false, now - 10)?;
            client.receive_own_group_consent(&phone.owned_device_identity()?, &tie)?;
            client.receive_own_group_consent(&laptop.owned_device_identity()?, &accept)?;
            assert!(!client.local_is_group_member("group")?);
            let saved: Decision = client
                .account_db()?
                .load_actor_state(&key("group"))?
                .ok_or(StorageError::AuthorizationRejected)?;
            assert_eq!(saved.expires_at, now - 10 + 7 * 86400);
        }
        drop((phone, laptop, stranger));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}
