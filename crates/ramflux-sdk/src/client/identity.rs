// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

const SIGNED_PREKEY_ROTATION_SECONDS: i64 = 7 * 24 * 60 * 60;
const SIGNED_PREKEY_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;
const SIGNED_PREKEY_GRACE_SECONDS: i64 = 2 * 24 * 60 * 60;
const ONE_TIME_PREKEY_POOL_SIZE: usize = 8;
const ONE_TIME_PREKEY_REPLENISH_BELOW: usize = 2;

struct SignedPrekeyMaterial {
    id: String,
    seed: [u8; 32],
    created_at: i64,
    expires_at: i64,
    previous: Vec<crate::dm::SdkRetiringSignedPrekey>,
}

fn select_signed_prekey(
    existing: Option<&crate::dm::SdkX3dhPrivateState>,
    device_id: &str,
    now: i64,
    force_rotate: bool,
) -> Result<SignedPrekeyMaterial, SdkError> {
    let mut previous =
        existing.map(|state| state.previous_signed_prekeys.clone()).unwrap_or_default();
    previous.retain(|key| key.erase_after > now);
    let rotate = force_rotate
        || existing.is_none_or(|state| {
            state.signed_prekey_created_at == 0
                || now.saturating_sub(state.signed_prekey_created_at)
                    >= SIGNED_PREKEY_ROTATION_SECONDS
        });
    if !rotate {
        let state = existing
            .ok_or_else(|| SdkError::LocalBus("missing current signed prekey state".to_owned()))?;
        return Ok(SignedPrekeyMaterial {
            id: state.signed_prekey_id.clone(),
            seed: state.signed_prekey_seed,
            created_at: state.signed_prekey_created_at,
            expires_at: state.signed_prekey_expires_at,
            previous,
        });
    }
    if let Some(old) = existing.filter(|state| state.signed_prekey_created_at > 0) {
        previous.push(crate::dm::SdkRetiringSignedPrekey {
            id: old.signed_prekey_id.clone(),
            seed: old.signed_prekey_seed,
            erase_after: now.saturating_add(SIGNED_PREKEY_GRACE_SECONDS),
        });
        if previous.len() > 1 {
            previous.remove(0);
        }
    }
    let key = X25519KeyPair::random()?;
    Ok(SignedPrekeyMaterial {
        id: format!(
            "{device_id}:signed:{}",
            ramflux_protocol::hash_base64url("ramflux.sdk.x3dh.signed_prekey.id.v2", &key.public)
        ),
        seed: key.secret.to_bytes(),
        created_at: now,
        expires_at: now.saturating_add(SIGNED_PREKEY_VALIDITY_SECONDS),
        previous,
    })
}

impl RamfluxClient {
    pub fn create_identity_root(&mut self, principal_id: &str, seed: [u8; 32]) -> IdentityRoot {
        let root = ramflux_crypto::create_identity_root(principal_id, seed);
        self.identity_root = Some(root.clone());
        root
    }

    pub fn create_device_branch(
        &mut self,
        principal_id: &str,
        device_id: &str,
        device_epoch: u64,
        seed: [u8; 32],
    ) -> DeviceBranch {
        let branch =
            ramflux_crypto::create_device_branch(principal_id, device_id, device_epoch, seed);
        self.device_branch = Some(branch.clone());
        branch
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn authorize_current_device(
        &self,
        audience: &str,
        capability_scope: Vec<String>,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<BranchProofDocument, SdkError> {
        self.bound_current_device_proof(audience, capability_scope, issued_at, expires_at)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn x3dh_initiator(&self, input: &X3dhInitiatorInput<'_>) -> Result<X3dhOutput, SdkError> {
        Ok(ramflux_crypto::x3dh_initiator(input)?)
    }

    /// # Errors
    /// Returns an error when X3DH recipient secret derivation fails.
    pub fn x3dh_recipient(&self, input: &X3dhRecipientInput<'_>) -> Result<X3dhOutput, SdkError> {
        Ok(ramflux_crypto::x3dh_recipient(input)?)
    }

    /// # Errors
    /// Returns an error when the initiator session keys cannot be derived.
    pub fn init_dm_initiator_session(
        &self,
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        Ok(ramflux_crypto::DmSession::initiator(
            root_seed,
            local_device_id_hash,
            remote_device_id_hash,
            bootstrap_transcript_hash,
        )?)
    }

    /// # Errors
    /// Returns an error when the recipient session keys cannot be derived.
    pub fn init_dm_recipient_session(
        &self,
        root_seed: [u8; 32],
        local_device_id_hash: [u8; 32],
        remote_device_id_hash: [u8; 32],
        bootstrap_transcript_hash: [u8; 32],
    ) -> Result<ramflux_crypto::DmSession, SdkError> {
        Ok(ramflux_crypto::DmSession::recipient(
            root_seed,
            local_device_id_hash,
            remote_device_id_hash,
            bootstrap_transcript_hash,
        )?)
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published.
    pub fn initialize_and_publish_prekey_bundle(
        &self,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
        prekey_http_url: Option<&str>,
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        if let Some(url) = prekey_http_url {
            self.register_mvp1_identity_for_prekey(
                url,
                principal_commitment,
                device_id,
                target_delivery_id,
                &format!("session_for_{device_id}"),
            )?;
            let response = sdk_publish_prekey_bundle(url, device_id, &bundle)?;
            if self.directory_requests_prekey_replenishment(device_id, &response)? {
                let fresh = self.replace_one_time_prekey_pool(device_id, device_seed)?;
                let _ = sdk_publish_prekey_bundle(url, device_id, &fresh)?;
            }
            self.record_owned_proof_published(now_unix_timestamp())?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published through the
    /// authenticated production gateway session.
    pub async fn initialize_and_publish_prekey_bundle_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        self.register_owned_via_session(
            engine,
            super::identity_authority::registration::RegistrationTarget {
                commitment: principal_commitment,
                device: device_id,
                delivery: target_delivery_id,
            },
        )
        .await?;
        let response = engine.publish_prekey_bundle(device_id, &bundle).await?;
        if self.directory_requests_prekey_replenishment(device_id, &response)? {
            let fresh = self.replace_one_time_prekey_pool(device_id, device_seed)?;
            let _ = engine.publish_prekey_bundle(device_id, &fresh).await?;
        }
        self.record_owned_proof_published(now_unix_timestamp())?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when prekey material cannot be created, persisted, or published before
    /// opening the authenticated gateway session.
    pub async fn initialize_and_publish_prekey_bundle_via_gateway_request(
        &self,
        gateway: &GatewaySessionConfig,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        device_seed: [u8; 32],
    ) -> Result<(), SdkError> {
        let bundle = self.create_and_store_prekey_bundle(device_id, device_seed)?;
        self.register_owned_via_request(
            gateway,
            super::identity_authority::registration::RegistrationTarget {
                commitment: principal_commitment,
                device: device_id,
                delivery: target_delivery_id,
            },
        )
        .await?;
        let response: SdkPrekeyResponse = sdk_gateway_post_json(
            gateway,
            "/mvp1/prekey/publish",
            &SdkPrekeyPublishRequest { device_id: device_id.to_owned(), bundle },
        )
        .await?;
        if self.directory_requests_prekey_replenishment(device_id, &response)? {
            let fresh = self.replace_one_time_prekey_pool(device_id, device_seed)?;
            let _: SdkPrekeyResponse = sdk_gateway_post_json(
                gateway,
                "/mvp1/prekey/publish",
                &SdkPrekeyPublishRequest { device_id: device_id.to_owned(), bundle: fresh },
            )
            .await?;
        }
        self.record_owned_proof_published(now_unix_timestamp())?;
        Ok(())
    }

    fn create_and_store_prekey_bundle(
        &self,
        device_id: &str,
        device_seed: [u8; 32],
    ) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        self.create_and_store_prekey_bundle_at(device_id, device_seed, now_unix_timestamp())
    }

    fn directory_requests_prekey_replenishment(
        &self,
        device_id: &str,
        response: &SdkPrekeyResponse,
    ) -> Result<bool, SdkError> {
        if response.one_time_prekey_exhausted || response.available_one_time_prekeys == 0 {
            self.account_db()?.persist_actor_state(
                &format!("x3dh/directory-warning/{device_id}"),
                &serde_json::json!({
                    "type": "x3dh.one_time_prekeys.exhausted.v1",
                    "device_id": device_id,
                    "available": response.available_one_time_prekeys,
                    "observed_at": now_unix_timestamp()
                }),
            )?;
        }
        Ok(response.available_one_time_prekeys
            < u32::try_from(ONE_TIME_PREKEY_REPLENISH_BELOW).unwrap_or(u32::MAX))
    }

    fn replace_one_time_prekey_pool(
        &self,
        device_id: &str,
        device_seed: [u8; 32],
    ) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let device = self.local_device_identity(device_id)?;
        let mut state = self.load_x3dh_private_state(&device)?;
        state.one_time_prekeys.clear();
        self.persist_owned_private_prekey(&device, &state)?;
        self.account_db()?.persist_actor_state("secrets/retired", &true)?;
        self.finish_pair_retirement()?;
        self.create_and_store_prekey_bundle(device_id, device_seed)
    }

    fn create_and_store_prekey_bundle_at(
        &self,
        device_id: &str,
        device_seed: [u8; 32],
        now: i64,
    ) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let device = self.local_device_identity(device_id)?;
        let existing = self.optional_owned_private_prekey(&device)?;
        let branch_changed =
            existing.as_ref().is_some_and(|state| state.bundle.device_epoch != branch.device_epoch);
        if let Some(state) = existing.as_ref()
            && !branch_changed
            && state.signed_prekey_created_at > 0
            && now.saturating_sub(state.signed_prekey_created_at) < SIGNED_PREKEY_ROTATION_SECONDS
            && state.one_time_prekeys.len() >= ONE_TIME_PREKEY_REPLENISH_BELOW
            && state.previous_signed_prekeys.iter().all(|key| key.erase_after > now)
        {
            return Ok(state.bundle.clone());
        }
        let identity_seed = existing.as_ref().map_or_else(
            || x3dh_private_seed("ramflux.sdk.x3dh.identity.v1", &device_seed),
            |s| s.identity_seed,
        );
        let identity = X25519KeyPair::from_seed(identity_seed);
        let signed = select_signed_prekey(existing.as_ref(), device_id, now, branch_changed)?;
        let signed_prekey = X25519KeyPair::from_seed(signed.seed);
        let mut one_time_prekeys =
            existing.as_ref().map(|state| state.one_time_prekeys.clone()).unwrap_or_default();
        while one_time_prekeys.len() < ONE_TIME_PREKEY_POOL_SIZE {
            let key = X25519KeyPair::random()?;
            one_time_prekeys.push(crate::dm::SdkOneTimePrekeyPrivate {
                id: format!(
                    "{device_id}:one-time:{}",
                    ramflux_protocol::hash_base64url(
                        "ramflux.sdk.x3dh.one_time_prekey.id.v1",
                        &key.public
                    )
                ),
                seed: key.secret.to_bytes(),
            });
        }
        let public_one_time_prekeys = one_time_prekeys
            .iter()
            .map(|key| (key.id.clone(), X25519KeyPair::from_seed(key.seed).public))
            .collect::<Vec<_>>();
        let bundle_counter =
            existing.as_ref().map_or(1, |state| state.bundle_counter.saturating_add(1));
        let bundle = ramflux_crypto::create_rotating_prekey_bundle_with_lineage(
            branch,
            &branch.signing_key,
            &identity,
            &ramflux_crypto::PrekeyBundleOptions {
                signed_prekey_id: &signed.id,
                signed_prekey: &signed_prekey,
                signed_prekey_created_at: signed.created_at,
                signed_prekey_expires_at: signed.expires_at,
                one_time_prekeys: &public_one_time_prekeys,
                prekey_bundle_counter: bundle_counter,
            },
        )?;
        let state = SdkX3dhPrivateState {
            principal_commitment: Some(device.root_commitment().to_owned()),
            device_id: device_id.to_owned(),
            identity_seed,
            signed_prekey_id: signed.id,
            signed_prekey_seed: signed.seed,
            signed_prekey_created_at: signed.created_at,
            signed_prekey_expires_at: signed.expires_at,
            previous_signed_prekeys: signed.previous,
            one_time_prekeys,
            bundle_counter,
            bundle: bundle.clone(),
        };
        self.persist_owned_private_prekey(&device, &state)?;
        Ok(bundle)
    }

    pub(crate) fn register_mvp1_identity_for_prekey(
        &self,
        gateway_url: &str,
        principal_commitment: &str,
        device_id: &str,
        target_delivery_id: &str,
        session_id: &str,
    ) -> Result<(), SdkError> {
        self.register_owned_via_http(
            gateway_url,
            super::identity_authority::registration::RegistrationTarget {
                commitment: principal_commitment,
                device: device_id,
                delivery: target_delivery_id,
            },
            session_id,
        )
    }

    pub(crate) fn mvp1_identity_registration_request(
        &self,
        device_id: &str,
        target_delivery_id: &str,
        session_id: &str,
        principal_commitment: &str,
    ) -> Result<SdkIdentityRegisterRequest, SdkError> {
        self.mvp1_identity_registration_request_at(
            device_id,
            target_delivery_id,
            session_id,
            principal_commitment,
            now_unix_timestamp(),
        )
    }
    pub(crate) fn mvp1_identity_registration_request_at(
        &self,
        device_id: &str,
        target_delivery_id: &str,
        session_id: &str,
        principal_commitment: &str,
        now: i64,
    ) -> Result<SdkIdentityRegisterRequest, SdkError> {
        self.require_legacy_networking()?;
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let proof = self.authorize_current_device(
            "ramflux-node",
            vec!["device.delivery.bind".into()],
            now,
            now.saturating_add(super::identity_authority::registration::proof_lifetime_seconds()?),
        )?;
        let record = self
            .account_db()?
            .load_actor_state::<ramflux_protocol::SignedDeviceSetRecord>(
                "identity/registration_set",
            )?
            .map_or_else(|| self.prepare_owned_authority(None), Ok)?;
        self.validate_owned_registration_set(&record, &proof)?;
        Ok(SdkIdentityRegisterRequest {
            device_set: Some(record),
            root_public_key: ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            ),
            principal_commitment: principal_commitment.to_owned(),
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: target_delivery_id.to_owned(),
            gateway_id: "ramflux-gateway".to_owned(),
            session_id: session_id.to_owned(),
            push_alias_hash: Some(format!("push_alias_for_{device_id}")),
            now,
            registration_pow: None,
            source_ip_hash: None,
        })
    }
}

#[cfg(test)]
mod forward_secrecy_tests {
    use super::*;

    fn client(label: &str) -> Result<(std::path::PathBuf, RamfluxClient), SdkError> {
        let path = std::env::temp_dir().join(format!(
            "rf-dm-fs-{label}-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root("alice", [11; 32]);
        client.create_device_branch("alice", "phone", 1, [12; 32]);
        client.open_account_index(&path)?;
        client.create_account("alice", "alice")?;
        client.unlock_account("alice", b"dm-fs-test")?;
        Ok((path, client))
    }

    #[test]
    fn signed_prekeys_are_csprng_generated_and_rotation_erases_after_grace() -> Result<(), SdkError>
    {
        let (first_path, first) = client("first")?;
        let (second_path, second) = client("second")?;
        let initial = first.create_and_store_prekey_bundle_at("phone", [12; 32], 1_000)?;
        let independent = second.create_and_store_prekey_bundle_at("phone", [12; 32], 1_000)?;
        assert_ne!(initial.signed_prekey, independent.signed_prekey);
        assert_eq!(initial.one_time_prekey_ids.len(), ONE_TIME_PREKEY_POOL_SIZE);
        assert_eq!(
            initial.signed_prekey_expires_at - initial.signed_prekey_created_at,
            SIGNED_PREKEY_VALIDITY_SECONDS
        );
        let still_current = first.create_and_store_prekey_bundle_at(
            "phone",
            [12; 32],
            initial.signed_prekey_created_at.saturating_add(SIGNED_PREKEY_ROTATION_SECONDS - 1),
        )?;
        assert_eq!(initial.signed_prekey_id, still_current.signed_prekey_id);

        let rotated = first.create_and_store_prekey_bundle_at(
            "phone",
            [12; 32],
            initial.signed_prekey_created_at.saturating_add(SIGNED_PREKEY_ROTATION_SECONDS),
        )?;
        assert_ne!(initial.signed_prekey_id, rotated.signed_prekey_id);
        let device = first.owned_device_identity()?;
        let grace_state = first.load_x3dh_private_state(&device)?;
        assert_eq!(grace_state.previous_signed_prekeys.len(), 1);
        assert_eq!(grace_state.previous_signed_prekeys[0].id, initial.signed_prekey_id);
        let erase_after = grace_state.previous_signed_prekeys[0].erase_after;
        first.create_and_store_prekey_bundle_at("phone", [12; 32], erase_after)?;
        assert!(first.load_x3dh_private_state(&device)?.previous_signed_prekeys.is_empty());

        drop((first, second));
        std::fs::remove_dir_all(first_path)?;
        std::fs::remove_dir_all(second_path)?;
        Ok(())
    }

    #[test]
    fn legacy_seed_derived_bundle_is_replaced_and_its_event_payload_is_retired()
    -> Result<(), SdkError> {
        let (path, client) = client("legacy")?;
        let device = client.owned_device_identity()?;
        let identity_seed = x3dh_private_seed("ramflux.sdk.x3dh.identity.v1", &[12; 32]);
        let signed_seed = x3dh_private_seed("ramflux.sdk.x3dh.signed_prekey.v1", &[12; 32]);
        let identity = X25519KeyPair::from_seed(identity_seed);
        let signed = X25519KeyPair::from_seed(signed_seed);
        let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let legacy_bundle = ramflux_crypto::create_prekey_bundle(
            branch,
            &identity,
            "phone:signed:1",
            &signed,
            None,
            None,
        )?;
        let legacy = SdkX3dhPrivateState {
            principal_commitment: Some(device.root_commitment().to_owned()),
            device_id: "phone".to_owned(),
            identity_seed,
            signed_prekey_id: "phone:signed:1".to_owned(),
            signed_prekey_seed: signed_seed,
            signed_prekey_created_at: 0,
            signed_prekey_expires_at: 0,
            previous_signed_prekeys: Vec::new(),
            one_time_prekeys: Vec::new(),
            bundle_counter: 0,
            bundle: legacy_bundle,
        };
        client.append_event("legacy-x3dh", "x3dh.prekey.private", &serde_json::to_vec(&legacy)?)?;
        client.set_projection_checkpoint(
            &legacy_x3dh_private_checkpoint_name("phone"),
            "legacy-x3dh",
        )?;

        let migrated = client.create_and_store_prekey_bundle_at("phone", [12; 32], 1_000)?;
        assert_ne!(migrated.signed_prekey, signed.public);
        assert_eq!(migrated.prekey_bundle_counter, 1);
        assert!(client.event_body("legacy-x3dh")?.is_none());
        assert!(
            client
                .account_db()?
                .actor_state_exists(&crate::dm::x3dh_private_state_name(&device))?
        );
        drop(client);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    fn directory_drain_replaces_the_local_pool_with_fresh_ids_on_next_sync() -> Result<(), SdkError>
    {
        let (path, client) = client("directory-drain")?;
        let initial = client.create_and_store_prekey_bundle_at("phone", [12; 32], 1_000)?;
        let response = SdkPrekeyResponse {
            device_id: "phone".into(),
            bundle: Some(initial.clone()),
            principal_commitment: initial.identity_commitment.clone(),
            target_delivery_id: Some("mailbox".into()),
            one_time_prekey_exhausted: true,
            available_one_time_prekeys: 0,
        };
        assert!(client.directory_requests_prekey_replenishment("phone", &response)?);
        let refreshed = client.replace_one_time_prekey_pool("phone", [12; 32])?;
        assert!(
            refreshed
                .one_time_prekey_ids
                .iter()
                .all(|id| !initial.one_time_prekey_ids.contains(id))
        );
        assert!(refreshed.prekey_bundle_counter > initial.prekey_bundle_counter);
        let warning = client
            .account_db()?
            .load_actor_state::<serde_json::Value>("x3dh/directory-warning/phone")?
            .ok_or_else(|| SdkError::LocalBus("missing exhaustion warning".into()))?;
        assert_eq!(warning["type"], "x3dh.one_time_prekeys.exhausted.v1");
        drop(client);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}
