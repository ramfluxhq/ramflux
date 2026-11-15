// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account decisions replicate inside current-root authenticated own-device packets.
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use ramflux_crypto::{RootQualifiedDeviceRef, VerifiedGroupState};
use ramflux_protocol::{GroupStateActor, GroupStateSnapshot};
use serde::{Deserialize, Serialize};
const DOMAIN: &str = "ramflux.sdk.own_group_consent.v1";
use prost::Message as _;
use ramflux_protocol::message as g;
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
impl Consent {
    fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(crate::client::generated_control::control_from_payload(
            g::control::Payload::OwnGroupConsent(g::OwnGroupConsent {
                schema: self.schema.clone(),
                actor: Some(g::NativeGroupActor {
                    canonical: ramflux_protocol::canonical_json_bytes(&self.actor)?,
                }),
                snapshot: Some(g::NativeGroupSnapshot {
                    canonical: ramflux_protocol::canonical_json_bytes(&self.snapshot)?,
                }),
                accepted: self.accepted,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                signature: self.signature.clone(),
            }),
        )?
        .encode_to_vec())
    }
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
fn signing(consent: &Consent) -> Result<Vec<u8>, SdkError> {
    let control = g::Control::decode(consent.bytes()?.as_slice())
        .map_err(|_| super::invalid("group consent typed encoding invalid"))?;
    let Some(g::control::Payload::OwnGroupConsent(mut value)) = control.payload else {
        return Err(super::invalid("group consent typed payload missing"));
    };
    value.signature.clear();
    crate::client::task::generated::typed_transcript("OwnGroupConsent", &value.encode_to_vec())
}

fn canonical_leaf<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
) -> Result<T, SdkError> {
    if bytes.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES {
        return Err(super::invalid("group consent native leaf byte budget"));
    }
    let value: T = ramflux_protocol::parse_i_json(bytes)?;
    if ramflux_protocol::canonical_json_bytes(&value)? != bytes {
        return Err(super::invalid("group consent native leaf must be exact canonical JSON"));
    }
    Ok(value)
}

fn generated_consent(
    value: &ramflux_protocol::message::OwnGroupConsent,
) -> Result<Consent, SdkError> {
    Ok(Consent {
        schema: value.schema.clone(),
        actor: canonical_leaf(
            &value
                .actor
                .as_ref()
                .ok_or_else(|| super::invalid("group consent actor missing"))?
                .canonical,
        )?,
        snapshot: canonical_leaf(
            &value
                .snapshot
                .as_ref()
                .ok_or_else(|| super::invalid("group consent snapshot missing"))?
                .canonical,
        )?,
        accepted: value.accepted,
        issued_at: value.issued_at,
        expires_at: value.expires_at,
        signature: value.signature.clone(),
    })
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
        consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &signing(&consent)?,
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        );
        if !self.save_own_group_decision(&consent, state)? {
            return Err(super::invalid("local group decision did not supersede stored state"));
        }
        let body = consent.bytes()?;
        let id = ramflux_protocol::hash_base64url(DOMAIN, &body);
        crate::bus::own_device_copy::stage(
            self,
            crate::client::own_device_copy::OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Control,
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
    #[cfg(test)]
    pub(crate) fn receive_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        if body.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES * 2 {
            return Err(super::invalid("group consent byte budget"));
        }
        if g::validation::scan_message("Control", body, g::registry::COMPILED_LAYER).is_err() {
            return Ok(false);
        }
        let control =
            g::Control::decode(body).map_err(|_| super::invalid("invalid own Control"))?;
        crate::client::generated_control::validate_control_operation(&control)?;
        let Some(g::control::Payload::OwnGroupConsent(value)) = control.payload else {
            return Ok(false);
        };
        let consent = generated_consent(&value)?;
        self.apply_own_group_consent(source, &consent)
    }

    fn apply_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        consent: &Consent,
    ) -> Result<bool, SdkError> {
        let state = self.verify_own_group_consent(source, consent)?;
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
            if !self.save_own_group_decision(consent, &state)? {
                return Ok(true);
            }
            self.apply_own_group_invitation_decision(&state, consent.accepted, consent.expires_at)?;
            Ok(true)
        })
    }
    pub(crate) fn authorize_generated_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        value: &ramflux_protocol::message::OwnGroupConsent,
    ) -> Result<(), SdkError> {
        let consent = generated_consent(value)?;
        self.verify_own_group_consent(source, &consent)?;
        Ok(())
    }

    pub(crate) fn receive_generated_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        value: &ramflux_protocol::message::OwnGroupConsent,
    ) -> Result<bool, SdkError> {
        self.apply_own_group_consent(source, &generated_consent(value)?)
    }

    fn verify_own_group_consent(
        &self,
        source: &RootQualifiedDeviceRef,
        consent: &Consent,
    ) -> Result<VerifiedGroupState, SdkError> {
        let own = self.owned_device_identity()?;
        let actor = &consent.actor.identity;
        let now = now_unix_timestamp();
        self.require_cached_root_authority(HeadUse::NewAuthorization, source)?;
        if source.root_commitment() != own.root_commitment()
            || actor.root_commitment != source.root_commitment()
            || actor.device_id != source.device_id()
            || self.trusted_device(HeadUse::NewAuthorization, source)?["signing_public_key"]
                != actor.signing_public_key
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
        ramflux_crypto::verify_canonical_signature(
            &signing(consent)?,
            &consent.signature,
            &actor.signing_public_key,
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
        use crate::client::shared_group::tests::{
            install_native_directories, native_person, native_target,
        };
        let phone = native_person("owner", "phone")?;
        let stranger = native_person("stranger", "stranger")?;
        install_native_directories(&[&phone, &stranger])?;
        for accepted in [true, false] {
            let group = if accepted { "accept" } else { "decline" };
            stranger.client.fixture_group_create(group, group, None, "stranger")?;
            let state = stranger.client.fixture_group_change(
                group,
                "stranger",
                ramflux_protocol::GroupStateChange::Add {
                    member: phone.client.fixture_group_actor("phone")?.identity,
                    role: ramflux_protocol::SharedGroupRole::Member,
                },
            )?;
            phone.client.hold_group_invitation(
                &state,
                &stranger.client.shared_group_packet(&state, false)?,
            )?;
            let future = now_unix_timestamp() + 120;
            phone.client.account_db()?.persist_actor_state(
                &key(group),
                &Decision {
                    genesis_hash: state.genesis_hash()?,
                    accepted: !accepted,
                    issued_at: future,
                    expires_at: future + 7 * 86400,
                },
            )?;
            let reply = phone.client.decide_group_invitation(
                group,
                accepted,
                &native_target(&phone.client)?,
            )?;
            assert_eq!(reply["accepted"], accepted);
            let saved: Decision = phone
                .client
                .account_db()?
                .load_actor_state(&key(group))?
                .ok_or(StorageError::AuthorizationRejected)?;
            assert_eq!(saved.issued_at, future + 1);
            assert_eq!(saved.accepted, accepted);
            assert_eq!(phone.client.local_is_group_member(group)?, accepted);
        }
        drop((phone, stranger));
        Ok(())
    }
    #[test]
    fn r7_signed_account_decisions_follow_time_and_decline_wins_ties() -> Result<(), SdkError> {
        use crate::client::shared_group::tests::{
            install_native_directories, native_person, native_sibling,
        };
        let mut phone = native_person("owner", "phone")?;
        let laptop = native_sibling(&mut phone, "owner-laptop", "laptop")?;
        let stranger = native_person("stranger", "stranger")?;
        install_native_directories(&[&phone, &laptop])?;
        stranger.client.fixture_group_create("group", "thread", None, "stranger")?;
        let state = stranger.client.fixture_group_change(
            "group",
            "stranger",
            ramflux_protocol::GroupStateChange::Add {
                member: phone.client.fixture_group_actor("phone")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
        let now = now_unix_timestamp();
        let make = |client: &RamfluxClient, accepted, at| -> Result<Vec<u8>, SdkError> {
            let own = client.owned_device_identity()?;
            let mut consent = Consent {
                schema: DOMAIN.into(),
                actor: client.owned_group_actor(own.storage_key())?,
                snapshot: state.snapshot().clone(),
                accepted,
                issued_at: at,
                expires_at: at + 7 * 86400,
                signature: String::new(),
            };
            consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                &signing(&consent)?,
                client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            );
            let bytes = consent.bytes()?;
            Ok(bytes)
        };
        // Two independently signed devices disagree; delivery order must not choose the winner.
        let decline = make(&phone.client, false, now - 20)?;
        let accept = make(&laptop.client, true, now - 10)?;
        for client in [&phone.client, &laptop.client] {
            client.receive_own_group_consent(&phone.client.owned_device_identity()?, &decline)?;
            client.receive_own_group_consent(&laptop.client.owned_device_identity()?, &accept)?;
            client.receive_own_group_consent(&phone.client.owned_device_identity()?, &decline)?;
            assert!(client.local_is_group_member("group")?);
            let tie = make(&phone.client, false, now - 10)?;
            client.receive_own_group_consent(&phone.client.owned_device_identity()?, &tie)?;
            client.receive_own_group_consent(&laptop.client.owned_device_identity()?, &accept)?;
            assert!(!client.local_is_group_member("group")?);
            let saved: Decision = client
                .account_db()?
                .load_actor_state(&key("group"))?
                .ok_or(StorageError::AuthorizationRejected)?;
            assert_eq!(saved.expires_at, now - 10 + 7 * 86400);
        }
        drop((phone, laptop, stranger));
        Ok(())
    }

    #[tokio::test]
    async fn generated_native_group_consent_uses_exact_leaf_and_signed_authority()
    -> crate::client::native_test_support::TestResult {
        use crate::client::native_test_support::Fixture;
        use ramflux_protocol::message as g;
        let own = Box::pin(Fixture::new("generated-native-consent")).await?;
        let primary = own
            .client
            .born_v3_account
            .as_ref()
            .ok_or("account")?
            .group_primary(own.vault.as_ref())?;
        let state = own.client.shared_group_create_with_primary(
            "typed-consent-group",
            "typed-consent-thread",
            None,
            &own.config.target_delivery_id,
            Some(&primary),
        )?;
        let source = own.client.owned_device_identity()?;
        let now = now_unix_timestamp();
        let mut consent = Consent {
            schema: DOMAIN.into(),
            actor: own.client.owned_group_actor(&own.config.target_delivery_id)?,
            snapshot: state.snapshot().clone(),
            accepted: true,
            issued_at: now,
            expires_at: now + 600,
            signature: String::new(),
        };
        consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &signing(&consent)?,
            own.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        );
        let value = g::OwnGroupConsent {
            schema: consent.schema.clone(),
            actor: Some(g::NativeGroupActor {
                canonical: ramflux_protocol::canonical_json_bytes(&consent.actor)?,
            }),
            snapshot: Some(g::NativeGroupSnapshot {
                canonical: ramflux_protocol::canonical_json_bytes(&consent.snapshot)?,
            }),
            accepted: consent.accepted,
            issued_at: consent.issued_at,
            expires_at: consent.expires_at,
            signature: consent.signature.clone(),
        };
        own.client.authorize_generated_own_group_consent(&source, &value)?;
        assert!(own.client.receive_generated_own_group_consent(&source, &value)?);
        let before = own
            .client
            .account_db()?
            .load_actor_state::<serde_json::Value>(&key("typed-consent-group"))?;
        let mut invalid = value.clone();
        invalid.accepted = false;
        assert!(own.client.authorize_generated_own_group_consent(&source, &invalid).is_err());
        assert!(own.client.receive_generated_own_group_consent(&source, &invalid).is_err());
        let mut invalid = value.clone();
        invalid.actor.as_mut().ok_or("actor")?.canonical.push(b' ');
        assert!(own.client.authorize_generated_own_group_consent(&source, &invalid).is_err());
        let mut invalid = value;
        invalid.snapshot.as_mut().ok_or("snapshot")?.canonical.push(b' ');
        assert!(own.client.authorize_generated_own_group_consent(&source, &invalid).is_err());
        assert_eq!(
            own.client
                .account_db()?
                .load_actor_state::<serde_json::Value>(&key("typed-consent-group"))?,
            before
        );
        Ok(())
    }
}
