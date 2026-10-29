// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private prekey state is selected by the owned root, including proof-checked historical upgrades.
use super::identity_authority::invalid;
use crate::{
    RamfluxClient, SdkError,
    dm::{
        SdkX3dhPrivateState, legacy_x3dh_private_checkpoint_name, x3dh_private_checkpoint_name,
        x3dh_private_state_name,
    },
};
use ramflux_crypto::{RootQualifiedDeviceRef, X25519KeyPair};
impl RamfluxClient {
    pub(crate) fn load_x3dh_private_state(
        &self,
        device: &RootQualifiedDeviceRef,
    ) -> Result<SdkX3dhPrivateState, SdkError> {
        self.optional_owned_private_prekey(device)?
            .ok_or_else(|| invalid("missing root-qualified private prekeys"))
    }
    pub(super) fn optional_owned_private_prekey(
        &self,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<SdkX3dhPrivateState>, SdkError> {
        if *device != self.owned_device_identity()? {
            return Err(invalid("private prekeys require the owned device"));
        }
        if let Some(state) = self
            .account_db()?
            .load_actor_state::<SdkX3dhPrivateState>(&x3dh_private_state_name(device))?
        {
            self.verify_owned_private_prekey(device, &state)?;
            return Ok(Some(state));
        }
        if let Some(event) = self.projection_checkpoint(&x3dh_private_checkpoint_name(device))? {
            let bytes =
                self.event_body(&event)?.ok_or_else(|| invalid("missing private prekey event"))?;
            let state: SdkX3dhPrivateState = serde_json::from_slice(&bytes)?;
            self.verify_owned_private_prekey(device, &state)?;
            return Ok(Some(state));
        }
        self.legacy_owned_private_prekey(device)
    }
    fn legacy_owned_private_prekey(
        &self,
        device: &RootQualifiedDeviceRef,
    ) -> Result<Option<SdkX3dhPrivateState>, SdkError> {
        let old = legacy_x3dh_private_checkpoint_name(device.device_id());
        let Some(event) = self.projection_checkpoint(&old)? else { return Ok(None) };
        let bytes = self
            .event_body(&event)?
            .ok_or_else(|| invalid("missing legacy private prekey event"))?;
        let mut state: SdkX3dhPrivateState = serde_json::from_slice(&bytes)?;
        // A name or an equal branch key alone cannot prove which root owned an old row.
        // Require the retained root-signed set to bind both actual public keys to this device.
        if state.principal_commitment.is_none() {
            let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let record = self
                .observed_device_set(device.root_commitment())?
                .ok_or_else(|| invalid("legacy private prekeys need retained root authority"))?;
            let verified = RootQualifiedDeviceRef::from_signed_device_set(
                &root.signing_key.verifying_key(),
                &record,
                device.device_id(),
            )?;
            let keys = ramflux_crypto::device_key_commitments(
                &state.bundle.device_identity_ed25519_public,
                &ramflux_protocol::encode_base64url(state.bundle.identity_key),
            )?;
            if verified != *device
                || !record.devices.iter().any(|entry| {
                    entry.device_id == device.device_id()
                        && entry.signing_key_commitment == keys.0
                        && entry.agreement_key_commitment == keys.1
                })
            {
                return Err(invalid("legacy private prekeys do not match retained root authority"));
            }
            state.principal_commitment = Some(device.root_commitment().to_owned());
        }
        self.verify_owned_private_prekey(device, &state)?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.persist_owned_private_prekey(device, &state)?;
            Ok(())
        })?;
        Ok(Some(state))
    }
    fn verify_owned_private_prekey(
        &self,
        device: &RootQualifiedDeviceRef,
        state: &SdkX3dhPrivateState,
    ) -> Result<(), SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if state.principal_commitment.as_deref() != Some(device.root_commitment())
            || state.device_id != device.device_id()
            || state.bundle.device_id != device.device_id()
            || state.bundle.device_identity_ed25519_public
                != ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
            || state.bundle.identity_key != X25519KeyPair::from_seed(state.identity_seed).public
            || state.bundle.signed_prekey
                != X25519KeyPair::from_seed(state.signed_prekey_seed).public
            || state.bundle.prekey_bundle_counter != state.bundle_counter
        {
            return Err(invalid("private prekey root or key mismatch"));
        }
        for private in &state.one_time_prekeys {
            let Some(index) =
                state.bundle.one_time_prekey_ids.iter().position(|id| id == &private.id)
            else {
                return Err(invalid("private one-time prekey id is not published"));
            };
            if state.bundle.one_time_prekey_x25519_public.get(index)
                != Some(&X25519KeyPair::from_seed(private.seed).public)
            {
                return Err(invalid("private one-time prekey does not match publication"));
            }
        }
        ramflux_crypto::verify_prekey_bundle(&branch.signing_key.verifying_key(), &state.bundle)?;
        Ok(())
    }
    pub(super) fn persist_owned_private_prekey(
        &self,
        device: &RootQualifiedDeviceRef,
        state: &SdkX3dhPrivateState,
    ) -> Result<(), SdkError> {
        self.verify_owned_private_prekey(device, state)?;
        let db = self.account_db()?;
        db.persist_actor_state(&x3dh_private_state_name(device), state)?;
        db.retire_private_prekey_events()?;
        let _ = db.checkpoint_retired_secrets_if_committed()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account() -> Result<(std::path::PathBuf, RamfluxClient), SdkError> {
        account_named("account", "alice", "phone", 11, 12)
    }
    fn account_named(
        label: &str,
        principal: &str,
        device: &str,
        root_seed: u8,
        device_seed: u8,
    ) -> Result<(std::path::PathBuf, RamfluxClient), SdkError> {
        let path = std::env::temp_dir().join(format!(
            "rf-private-prekeys-{label}-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [root_seed; 32]);
        client.create_device_branch(principal, device, 1, [device_seed; 32]);
        client.open_account_index(&path)?;
        client.create_account(principal, principal)?;
        client.unlock_account(principal, b"private-prekey-test")?;
        client.initialize_and_publish_prekey_bundle(
            principal,
            device,
            "mailbox",
            [device_seed; 32],
            None,
        )?;
        Ok((path, client))
    }
    fn legacy(client: &RamfluxClient, device: &RootQualifiedDeviceRef) -> Result<(), SdkError> {
        let mut state = client.load_x3dh_private_state(device)?;
        state.principal_commitment = None;
        client.append_event("old-private", "x3dh.prekey.private", &serde_json::to_vec(&state)?)?;
        client.set_projection_checkpoint(
            &legacy_x3dh_private_checkpoint_name(device.device_id()),
            "old-private",
        )
    }
    fn leased_bundle(
        client: &RamfluxClient,
        device: &RootQualifiedDeviceRef,
    ) -> Result<(String, [u8; 32], ramflux_crypto::PrekeyBundle), SdkError> {
        let state = client.load_x3dh_private_state(device)?;
        let consumed = state.one_time_prekeys[0].id.clone();
        let consumed_seed = state.one_time_prekeys[0].seed;
        let mut leased = state.bundle.clone();
        let index = leased
            .one_time_prekey_ids
            .iter()
            .position(|id| id == &consumed)
            .ok_or_else(|| invalid("leased OPK missing"))?;
        leased.one_time_prekey_id = Some(consumed.clone());
        leased.one_time_prekey = leased.one_time_prekey_x25519_public.get(index).copied();
        leased.one_time_prekey_signature = leased.one_time_prekey_signatures.get(index).cloned();
        leased.one_time_prekey_ids.clear();
        leased.one_time_prekey_x25519_public.clear();
        leased.one_time_prekey_signatures.clear();
        Ok((consumed, consumed_seed, leased))
    }
    #[test]
    fn legacy_private_keys_need_retained_signed_root_authority_and_preserve_their_keys()
    -> Result<(), SdkError> {
        let (path, client) = account()?;
        let device = client.owned_device_identity()?;
        legacy(&client, &device)?;
        assert!(client.legacy_owned_private_prekey(&device).is_err());
        let manifest = crate::client::identity_authority::test_support::manifest(&client)?;
        client.account_db()?.persist_actor_state(
            &format!("identity/signed_set/{}", device.root_commitment()),
            &manifest.signed_device_set.ok_or_else(|| invalid("set"))?,
        )?;
        let before = client.load_x3dh_private_state(&device)?;
        let migrated =
            client.legacy_owned_private_prekey(&device)?.ok_or_else(|| invalid("migration"))?;
        assert_eq!(migrated.principal_commitment.as_deref(), Some(device.root_commitment()));
        assert_eq!(before.identity_seed, migrated.identity_seed);
        assert_eq!(before.signed_prekey_seed, migrated.signed_prekey_seed);
        assert_eq!(before.bundle, migrated.bundle);
        drop(client);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
    #[test]
    fn same_name_under_a_foreign_root_cannot_select_or_overwrite_owned_private_keys()
    -> Result<(), SdkError> {
        let (path, client) = account()?;
        let foreign = RootQualifiedDeviceRef::for_owned_account_device(
            &ramflux_crypto::create_identity_root("alice", [51; 32]),
            "phone",
        )?;
        assert!(client.load_x3dh_private_state(&foreign).is_err());
        let own = client.owned_device_identity()?;
        let mut state = client.load_x3dh_private_state(&own)?;
        state.principal_commitment = Some(foreign.root_commitment().into());
        assert!(client.persist_owned_private_prekey(&own, &state).is_err());
        assert_eq!(
            client.load_x3dh_private_state(&own)?.principal_commitment.as_deref(),
            Some(own.root_commitment())
        );
        drop(client);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    fn assert_consumption_erased(
        client: &RamfluxClient,
        device: &RootQualifiedDeviceRef,
        consumed: &str,
        checkpoints: u64,
    ) -> Result<(), SdkError> {
        assert!(client.account_db()?.retired_secret_checkpoint_count() > checkpoints);
        assert!(client.account_db()?.secure_delete_enabled()?);
        assert!(
            client
                .load_x3dh_private_state(device)?
                .one_time_prekeys
                .iter()
                .all(|key| key.id != consumed),
            "the regression must fail if authenticated consumption is disabled"
        );
        assert!(!client.account_db()?.actor_state_exists("secrets/retired")?);
        Ok(())
    }

    #[test]
    fn restart_does_not_resurrect_a_consumed_one_time_prekey() -> Result<(), SdkError> {
        let (path, client) = account_named("receiver", "bob", "bob", 11, 12)?;
        let (sender_path, sender) = account_named("sender", "alice", "alice", 21, 22)?;
        let device = client.owned_device_identity()?;
        let (consumed, _consumed_seed, leased) = leased_bundle(&client, &device)?;
        let leased_for_probe = leased.clone();
        let message = crate::GatewayDirectMessage {
            conversation_id: "restart-erasure".into(),
            message_id: "bootstrap".into(),
            envelope_id: "bootstrap".into(),
            source_principal_id: "alice".into(),
            sender_id: "alice".into(),
            recipient_device_id: Some("bob".into()),
            recipient_principal_commitment: Some(device.root_commitment().into()),
            target_delivery_id: "mailbox".into(),
            encrypted_body: Vec::new(),
            created_at: 1_000,
            ttl: 3_600,
        };
        let (mut sending, header) =
            sender.create_send_dm_session_from_bundle(&message, "bob", leased, "alice")?;
        let header = header.ok_or_else(|| invalid("bootstrap header missing"))?;
        let snapshot = serde_json::to_value(sending.snapshot())?;
        let ratchet_seed: [u8; 32] = serde_json::from_value(snapshot["dhs_private"].clone())?;
        let persisted_ratchet = X25519KeyPair::from_seed(ratchet_seed);
        assert_eq!(persisted_ratchet.public, header.initiator_ratchet_public);
        assert_ne!(persisted_ratchet.public, header.initiator_ephemeral_public);
        let sender_device = sender.owned_device_identity()?;
        let sender_state = sender.load_x3dh_private_state(&sender_device)?;
        let sender_identity = X25519KeyPair::from_seed(sender_state.identity_seed);
        let bundle_hash = crate::dm::prekey_bundle_hash(&leased_for_probe)?;
        let probe = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
            initiator_identity: &sender_identity,
            initiator_ephemeral: &persisted_ratchet,
            initiator_device_id_hash: header.initiator_device_id_hash,
            recipient_device_id_hash: header.recipient_device_id_hash,
            recipient_bundle: &leased_for_probe,
            associated_data: crate::dm::dm_associated_data("restart-erasure"),
            prekey_bundle_hash: &bundle_hash,
            initial_ratchet_public: header.initiator_ratchet_public,
        })?;
        assert_ne!(probe.bootstrap_transcript_hash, header.bootstrap_transcript_hash);
        let ciphertext =
            sending.encrypt(b"authenticated", crate::dm::dm_associated_data("restart-erasure"))?;
        let mut receiving = client.create_recv_dm_session_with_aad(
            &header,
            crate::dm::dm_associated_data("restart-erasure"),
        )?;
        assert!(
            client
                .load_x3dh_private_state(&device)?
                .one_time_prekeys
                .iter()
                .any(|key| key.id == consumed),
            "authentication alone must not erase before the ratchet transaction commits"
        );
        assert_eq!(
            receiving.decrypt(&ciphertext, crate::dm::dm_associated_data("restart-erasure"))?,
            b"authenticated"
        );
        let checkpoints = client.account_db()?.retired_secret_checkpoint_count();
        client.persist_dm_session("restart-erasure", "bootstrap", "recv", &receiving)?;
        assert_consumption_erased(&client, &device, &consumed, checkpoints)?;
        client.append_event("legacy-private-copy", "x3dh.prekey.private", b"secret")?;
        client.set_projection_checkpoint("x3dh_private:v2/legacy", "legacy-private-copy")?;
        let history = client.account_db()?.export_history_bundle("phone", "tablet")?;
        assert!(
            history
                .encrypted_event_batch
                .iter()
                .all(|event| event.event_type != "x3dh.prekey.private")
        );
        assert!(
            history
                .projection_checkpoints
                .iter()
                .all(|checkpoint| !checkpoint.projection_name.starts_with("x3dh_private:"))
        );
        client.account_db()?.retire_private_prekey_events()?;
        assert!(client.event_body("legacy-private-copy")?.is_none());
        drop(client);

        let mut reopened = RamfluxClient::new();
        reopened.create_identity_root("bob", [11; 32]);
        reopened.create_device_branch("bob", "bob", 1, [12; 32]);
        reopened.open_account_index(&path)?;
        reopened.unlock_account("bob", b"private-prekey-test")?;
        let restored = reopened.load_x3dh_private_state(&reopened.owned_device_identity()?)?;
        assert!(restored.one_time_prekeys.iter().all(|key| key.id != consumed));
        drop(reopened);
        std::fs::remove_dir_all(path)?;
        drop(sender);
        std::fs::remove_dir_all(sender_path)?;
        Ok(())
    }
}
