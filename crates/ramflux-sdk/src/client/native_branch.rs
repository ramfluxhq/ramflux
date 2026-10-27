// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Certified branch credentials and ordinary DM private prekeys, independent of data unlock.
use crate::{RamfluxClient, SdkError, custody::PrimaryVault, dm::SdkX3dhPrivateState};
use std::sync::Arc;
use zeroize::Zeroizing;

impl RamfluxClient {
    /// Load a certified branch for ordinary networking after data unlock.
    /// This never loads primary signing authority. Public directory reads and unlock
    /// remain available when the branch vault is unavailable.
    /// # Errors
    /// Rejects unavailable credentials, expired authority, wrong branches and storage failure.
    pub async fn initialize_born_v3_branch(
        &mut self,
        device_id: &str,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<(), SdkError> {
        let selected = self.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
        let local_id = self.account_db()?.local_account_id.clone();
        if selected.local_account_id() != local_id {
            return Err(SdkError::CustodySetupInvalid);
        }
        let root = self.account_index()?.root().to_path_buf();
        let device_id = device_id.to_owned();
        let (account, reference, credentials) = tokio::task::spawn_blocking(move || {
            let now = crate::custody::network_now()?;
            let account = crate::custody::load_account(&root, &local_id, now)?;
            let (reference, credentials) = account.credentials(vault.as_ref(), &device_id, now)?;
            account.verified().authorize(&reference, "message", now)?;
            Ok::<_, SdkError>((account, reference, credentials))
        })
        .await
        .map_err(|_| SdkError::CustodySetupInvalid)??;
        let bundle = credentials.prekey_bundle()?;
        let state = SdkX3dhPrivateState {
            principal_commitment: Some(reference.account_anchor.clone()),
            device_id: reference.device_id.clone(),
            identity_seed: *Zeroizing::new(credentials.agreement.secret.to_bytes()),
            signed_prekey_id: bundle.signed_prekey_id.clone(),
            signed_prekey_seed: *credentials.signed_prekey_seed(),
            bundle,
        };
        let identity = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
            account.verified(),
            &reference.device_id,
        )?;
        self.observe_custody_manifest(
            &ramflux_protocol::custody::CustodyManifest {
                publication: ramflux_protocol::custody::Publication {
                    record: account.record().clone(),
                    compacted_ids: None,
                },
                custodian_publication: account.custodian_publication(
                    self.account_index()?.root(),
                    crate::custody::network_now()?,
                )?,
                devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                    device_ref: reference.clone(),
                    target_delivery_id: identity.storage_key().into(),
                    prekey_bundle: serde_json::to_value(&state.bundle)?,
                }],
            },
            &reference.account_anchor,
            crate::custody::network_now()?,
        )?;
        let previous_account = self.born_v3_account.replace(Box::new(account));
        let previous = self.device_branch.replace(credentials.signing);
        if let Err(error) = self.persist_owned_private_prekey(&identity, &state) {
            self.device_branch = previous;
            self.born_v3_account = previous_account;
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::tests::{Root, TestVault, create};
    use ramflux_protocol::custody::DeviceRef;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct BranchOnly(Arc<TestVault>);
    impl PrimaryVault for BranchOnly {
        fn delete(&self, _: &str) -> Result<(), SdkError> {
            Err(SdkError::CustodyVaultUnavailable)
        }
        fn preflight(&self) -> Result<(), SdkError> {
            Err(SdkError::CustodyVaultUnavailable)
        }
        fn store_new(
            &self,
            _: &str,
            _: &ramflux_crypto::custody::SelfSigningKey,
        ) -> Result<(), SdkError> {
            Err(SdkError::CustodyVaultUnavailable)
        }
        fn load_primary(
            &self,
            _: &str,
        ) -> Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
            Err(SdkError::CustodyVaultUnavailable)
        }
        fn store_branch(&self, _: &str, _: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
            Err(SdkError::CustodyVaultUnavailable)
        }
        fn load_branch(
            &self,
            reference: &str,
            principal: &str,
            device: &DeviceRef,
        ) -> Result<crate::custody::BranchCredentials, SdkError> {
            self.0.load_branch(reference, principal, device)
        }
    }
    #[tokio::test]
    async fn ordinary_native_prekeys_match_registration_and_need_no_primary_signer() -> TestResult {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let account = create(&root.0, "native", vault.as_ref(), now)?;
        let (_, expected) = account.credentials(vault.as_ref(), "primary", now)?;
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(
            "native",
            &account.record().body.account_anchor,
            b"data-passphrase",
        )?;
        client.unlock_account("native", b"data-passphrase")?;
        let provider: Arc<dyn PrimaryVault> = Arc::new(BranchOnly(vault));
        client.initialize_born_v3_branch("primary", Arc::clone(&provider)).await?;
        let identity = client.owned_device_identity()?;
        let before = client.load_x3dh_private_state(&identity)?;
        assert_eq!(before.bundle, expected.prekey_bundle()?);
        assert_eq!(
            ramflux_crypto::X25519KeyPair::from_seed(before.identity_seed).public,
            expected.agreement.public
        );
        assert_eq!(
            before.bundle.signed_prekey,
            ramflux_crypto::X25519KeyPair::from_seed(before.signed_prekey_seed).public
        );
        assert!(client.identity_root.is_none());
        drop(client);
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.unlock_account("native", b"data-passphrase")?;
        assert!(client.device_branch.is_none());
        client.initialize_born_v3_branch("primary", provider).await?;
        let restored = client.load_x3dh_private_state(&client.owned_device_identity()?)?;
        assert_eq!(restored.bundle, before.bundle);
        assert_eq!(restored.identity_seed, before.identity_seed);
        assert_eq!(restored.signed_prekey_seed, before.signed_prekey_seed);
        assert!(client.identity_root.is_none());
        Ok(())
    }
    async fn native_client(
        root: &Root,
        id: &str,
    ) -> Result<RamfluxClient, Box<dyn std::error::Error>> {
        let vault = Arc::new(TestVault::default());
        let account = create(&root.0, id, vault.as_ref(), crate::custody::network_now()?)?;
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(
            id,
            &account.record().body.account_anchor,
            b"data-passphrase",
        )?;
        client.unlock_account(id, b"data-passphrase")?;
        client.initialize_born_v3_branch("primary", vault).await?;
        Ok(client)
    }

    #[tokio::test]
    async fn ordinary_native_dm_bootstrap_reply_ratchet_and_replay_refusal() -> TestResult {
        let alice_root = Root::new()?;
        let bob_root = Root::new()?;
        let alice = native_client(&alice_root, "alice").await?;
        let bob = native_client(&bob_root, "bob").await?;
        let bundle = bob.load_x3dh_private_state(&bob.owned_device_identity()?)?.bundle;
        let message = crate::GatewayDirectMessage {
            conversation_id: "native-dm".into(),
            message_id: "first".into(),
            envelope_id: "first".into(),
            source_principal_id: "principal-alice".into(),
            sender_id: "primary".into(),
            recipient_device_id: Some("primary".into()),
            recipient_principal_commitment: Some(bob.own_account_anchor()?),
            target_delivery_id: bob.owned_device_identity()?.storage_key().into(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 3600,
        };
        let (mut sending, header) =
            alice.create_send_dm_session_from_bundle(&message, "primary", bundle, "primary")?;
        let mut receiving = bob.load_or_create_recv_dm_session("native-dm", header.as_ref())?;
        let aad = crate::dm::dm_associated_data("native-dm");
        let first = sending.encrypt(b"native ordinary first message", aad)?;
        assert_eq!(receiving.decrypt(&first, aad)?, b"native ordinary first message");
        assert!(receiving.decrypt(&first, aad).is_err());
        let reply = receiving.encrypt(b"ordinary ratchet reply", aad)?;
        assert_eq!(sending.decrypt(&reply, aad)?, b"ordinary ratchet reply");
        assert!(sending.decrypt(&reply, aad).is_err());
        let next = sending.encrypt(b"after first reply", aad)?;
        assert_ne!(first.ratchet_public_key, next.ratchet_public_key);
        assert_eq!(receiving.decrypt(&next, aad)?, b"after first reply");
        assert!(alice.identity_root.is_none());
        assert!(bob.identity_root.is_none());
        Ok(())
    }
}
