// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private prekey state is selected by the owned root, including proof-checked historical upgrades.
use super::identity_authority::invalid;
use crate::{
    RamfluxClient, SdkError,
    dm::{SdkX3dhPrivateState, legacy_x3dh_private_checkpoint_name, x3dh_private_checkpoint_name},
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
        {
            return Err(invalid("private prekey root or key mismatch"));
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
        let id = format!(
            "x3dh.prekey.private:v2/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.sdk.private_prekey.v2",
                &ramflux_protocol::canonical_json_bytes(&(device.storage_key(), &state.bundle))?
            )
        );
        self.append_event(&id, "x3dh.prekey.private", &serde_json::to_vec(state)?)?;
        self.set_projection_checkpoint(&x3dh_private_checkpoint_name(device), &id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account() -> Result<(std::path::PathBuf, RamfluxClient), SdkError> {
        let path = std::env::temp_dir().join(format!(
            "rf-private-prekeys-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root("alice", [11; 32]);
        client.create_device_branch("alice", "phone", 1, [12; 32]);
        client.open_account_index(&path)?;
        client.create_account("alice", "alice")?;
        client.unlock_account("alice", b"private-prekey-test")?;
        client.initialize_and_publish_prekey_bundle("alice", "phone", "mailbox", [12; 32], None)?;
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
}
