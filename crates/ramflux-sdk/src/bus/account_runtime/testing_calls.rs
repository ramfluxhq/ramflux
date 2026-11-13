// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native account setup for transport-injected tests of the production call courier.

use super::testing::{AccountSessionHarness, FixtureCapabilities};
use crate::custody::{BranchCredentials, CreateInput, CreationCeremony, PrimaryVault};
use crate::{GatewaySessionConfig, GatewaySessionState, RamfluxClient, SdkError};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice, DeviceRef, Publication};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Default)]
struct Vault(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
impl Vault {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SdkError> {
        let mut rows = self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if rows.len() >= 4 || rows.contains_key(key) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        rows.insert(key.into(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
}
impl PrimaryVault for Vault {
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.put(reference, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        let rows = self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = rows
            .get(reference)
            .filter(|v| v.len() == 32)
            .ok_or(SdkError::CustodyVaultUnavailable)?;
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(bytes);
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        Ok(())
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.put(reference, &**seeds)
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        let rows = self.0.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = rows
            .get(reference)
            .filter(|v| v.len() == 64)
            .ok_or(SdkError::CustodyVaultUnavailable)?;
        let mut seeds = Zeroizing::new([0; 64]);
        seeds.copy_from_slice(bytes);
        BranchCredentials::from_vault_seeds(principal, device, &seeds)
    }
}

/// Phrase-created account with real native authority and private prekeys.
pub struct NativeCallAccount {
    client: RamfluxClient,
    pub config: GatewaySessionConfig,
    pub manifest: serde_json::Value,
    pub publication: Publication,
    pub identity: ramflux_crypto::RootQualifiedDeviceRef,
}
impl NativeCallAccount {
    /// # Errors
    /// Refuses invalid account setup, vault state, or native prekey construction.
    pub async fn new(root: &Path, id: &str) -> Result<Self, SdkError> {
        std::fs::create_dir_all(root)?;
        let now = crate::custody::network_now()?;
        let vault = Arc::new(Vault::default());
        let mut ceremony = CreationCeremony::begin(
            root,
            CreateInput {
                local_account_id: id.into(),
                principal_id: format!("{id}.example"),
                device_id: "primary".into(),
                display_name: "Call Fixture".into(),
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                custodian_account_id: None,
            },
            now,
        )?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let mut words = [
            Zeroizing::new(String::new()),
            Zeroizing::new(String::new()),
            Zeroizing::new(String::new()),
        ];
        for (word, position) in words.iter_mut().zip(positions) {
            *word = Zeroizing::new(
                phrase
                    .split_whitespace()
                    .nth(usize::from(position).saturating_sub(1))
                    .ok_or(SdkError::CustodyConfirmationFailed)?
                    .to_owned(),
            );
        }
        let account = ceremony.confirm(&words, vault.as_ref(), now)?;
        let publication = Publication { record: account.record().clone(), compacted_ids: None };
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        client.seal_new_account_data(id, &anchor, b"native call fixture passphrase")?;
        client.unlock_account(id, b"native call fixture passphrase")?;
        client
            .initialize_born_v3_branch("primary", Arc::clone(&vault) as Arc<dyn PrimaryVault>)
            .await?;
        let identity = client.owned_device_identity()?;
        let bundle = client.load_x3dh_private_state(&identity)?.bundle;
        let manifest = crate::SdkDeviceManifestResponse::from_native(CustodyManifest {
            publication: publication.clone(),
            custodian_publication: None,
            devices: vec![CustodyManifestDevice {
                device_ref: DeviceRef {
                    account_anchor: anchor,
                    device_id: "primary".into(),
                    device_epoch: 1,
                },
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: serde_json::to_value(bundle)?,
                message_layer: None,
            }],
        })?;
        client.persist_fetched_identity_directory(&manifest)?;
        let endpoint = crate::GatewayQuicEndpointConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            gateway_addr: ([127, 0, 0, 1], 1).into(),
            server_name: "unused.fixture".into(),
            ca_cert: root.join("unused.pem"),
            principal_id: manifest.principal_id.clone(),
            device_id: "primary".into(),
            target_delivery_id: identity.storage_key().into(),
            prekey_http_url: None,
        };
        let mut config = GatewaySessionConfig::quic(endpoint)
            .with_native_custody(crate::GatewayCustodyConfig {
                account_root: root.to_path_buf(),
                account_id: id.into(),
                node_id: "fixture-node".into(),
                node_public_key: ramflux_protocol::encode_base64url([7; 32]),
                vault,
            })
            .with_account_identity(&client)?;
        config.device_branch = Some(Arc::new(
            client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
        ));
        config.source_identity = Some(identity.clone());
        Ok(Self {
            client,
            config,
            manifest: serde_json::to_value(manifest)?,
            publication,
            identity,
        })
    }

    /// Install explicit friend consent for a native call peer before receiving ciphertext.
    /// # Errors
    /// Returns real identity validation or account-store failures.
    pub fn prepare_call_peer(&mut self, manifest: serde_json::Value) -> Result<(), SdkError> {
        let manifest: crate::SdkDeviceManifestResponse = serde_json::from_value(manifest)?;
        self.client.persist_fetched_identity_directory(&manifest)?;
        self.client.establish_friend_link(
            "calls-fixture",
            &self.client.surface_local_root_commitment()?,
            &manifest.principal_commitment,
        )?;
        for seed in [91u8, 92] {
            self.client.account_db()?.persist_client_record(
                "conversation",
                &format!("call-thread-{seed}"),
                &serde_json::json!({"kind":"direct","group_id":null,
                    "participants":[self.config.principal_id,manifest.principal_id]}),
            )?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns the production host/writer startup error.
    pub async fn attach(
        self,
        session: GatewaySessionState,
        stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    ) -> Result<AccountSessionHarness, SdkError> {
        let index = self.client.account_index()?.clone();
        self.client.first_activate_receive_ledger(&self.config.target_delivery_id, None)?;
        AccountSessionHarness::attach_initialized(
            index,
            self.client,
            self.config,
            session,
            stream,
            FixtureCapabilities { incarnation: None, ephemeral: false },
        )
        .await
    }
}
