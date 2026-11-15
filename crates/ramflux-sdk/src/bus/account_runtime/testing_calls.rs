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
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.put(reference, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.0
            .lock()
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
            .get(reference)
            .cloned()
            .ok_or(SdkError::CustodyVaultUnavailable)
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

struct Names {
    principal: String,
    device: String,
}

/// Phrase-created account with real native authority and private prekeys.
pub struct NativeCallAccount {
    pub(super) client: RamfluxClient,
    pub config: GatewaySessionConfig,
    pub manifest: serde_json::Value,
    pub publication: Publication,
    pub identity: ramflux_crypto::RootQualifiedDeviceRef,
}
impl NativeCallAccount {
    /// # Errors
    /// Refuses invalid account setup, vault state, or native prekey construction.
    pub async fn new(root: &Path, id: &str) -> Result<Self, SdkError> {
        Self::create(
            root,
            id,
            None,
            &Names { principal: format!("{id}.example"), device: "primary".into() },
        )
        .await
    }

    /// Like [`Self::new`] with explicit principal and device names, for fixtures whose gateway
    /// side already addresses the account by those strings.
    /// # Errors
    /// Refuses invalid account setup, vault state, or native prekey construction.
    pub async fn named(
        root: &Path,
        id: &str,
        principal: &str,
        device: &str,
    ) -> Result<Self, SdkError> {
        Self::create(root, id, None, &Names { principal: principal.into(), device: device.into() })
            .await
    }

    /// Create a genuinely custodian-authorized headless account for consumer tests.
    /// # Errors
    /// Returns custody, vault, or account-store failures.
    pub async fn headless(root: &Path, id: &str, custodian: &Self) -> Result<Self, SdkError> {
        Self::create(
            root,
            id,
            Some(custodian),
            &Names { principal: format!("{id}.example"), device: "primary".into() },
        )
        .await
    }

    async fn create(
        root: &Path,
        id: &str,
        custodian: Option<&Self>,
        names: &Names,
    ) -> Result<Self, SdkError> {
        std::fs::create_dir_all(root)?;
        let vault = Arc::new(Vault::default());
        let account = Self::create_authority(root, id, custodian, names, vault.as_ref())?;
        let publication = Publication { record: account.record().clone(), compacted_ids: None };
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        client.unlock_account(id, b"native call fixture passphrase")?;
        client
            .initialize_born_v3_branch(&names.device, Arc::clone(&vault) as Arc<dyn PrimaryVault>)
            .await?;
        let identity = client.owned_device_identity()?;
        let bundle = client.load_x3dh_private_state(&identity)?.bundle;
        let manifest = crate::SdkDeviceManifestResponse::from_native(CustodyManifest {
            publication: publication.clone(),
            custodian_publication: custodian.map(|account| account.publication.clone()),
            devices: vec![CustodyManifestDevice {
                device_ref: DeviceRef {
                    account_anchor: anchor,
                    device_id: names.device.clone(),
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
            device_id: names.device.clone(),
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

    fn create_authority(
        root: &Path,
        id: &str,
        custodian: Option<&Self>,
        names: &Names,
        vault: &dyn PrimaryVault,
    ) -> Result<crate::custody::BornAccount, SdkError> {
        let now = crate::custody::network_now()?;
        if let Some(custodian) = custodian {
            let id = &custodian.client.account_db()?.local_account_id;
            crate::custody::load_account(root, id, now)?.mark_live_for_test(root)?;
        }
        let mut ceremony = CreationCeremony::begin(
            root,
            CreateInput {
                local_account_id: id.into(),
                principal_id: names.principal.clone(),
                device_id: names.device.clone(),
                display_name: "Call Fixture".into(),
                principal_kind: if custodian.is_some() {
                    ramflux_protocol::PrincipalKind::HeadlessAi
                } else {
                    ramflux_protocol::PrincipalKind::Human
                },
                custodian_account_id: custodian
                    .map(|account| {
                        account.client.account_db().map(|db| db.local_account_id.clone())
                    })
                    .transpose()?,
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
        let mut account = ceremony.confirm_with_passphrase(
            &words,
            vault,
            now,
            b"native call fixture passphrase",
        )?;
        if custodian.is_some() {
            account.mark_live_for_test(root)?;
        }
        Ok(account)
    }

    /// Install an established pair session between this account and `peer`, so a durable DM
    /// needs no prekey fetch from the node.
    /// # Errors
    /// Returns identity or session-state failures.
    pub fn seed_dm_pair(&self, peer: &Self) -> Result<(), SdkError> {
        let own = self.client.owned_device_identity()?;
        let remote = peer.client.owned_device_identity()?;
        let send = ramflux_crypto::DmSession::initiator(
            [17; 32],
            crate::dm::dm_device_id_hash(own.device_id()),
            crate::dm::dm_device_id_hash(remote.device_id()),
            [3; 32],
        )?
        .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
        let recv = ramflux_crypto::DmSession::recipient(
            [17; 32],
            crate::dm::dm_device_id_hash(remote.device_id()),
            crate::dm::dm_device_id_hash(own.device_id()),
            [3; 32],
        )?
        .with_collapse_key_from_x3dh_sk(&[17; 32], &[4; 32])?;
        self.client.persist_pair(&own, &remote, &[4; 32], &send)?;
        peer.client.persist_pair(&remote, &own, &[4; 32], &recv)?;
        Ok(())
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
        let thread = ramflux_protocol::message::dm_scope::derive(
            &self.client.surface_local_root_commitment()?,
            &manifest.principal_commitment,
        )
        .map_err(|error| SdkError::InboundRejected(error.to_string()))?;
        self.client.account_db()?.persist_client_record(
            "conversation",
            &thread,
            &serde_json::json!({"kind":"direct","group_id":null,
                "participants":[self.config.principal_id,manifest.principal_id],
                "participant_roots":[self.client.surface_local_root_commitment()?,manifest.principal_commitment]}),
        )?;
        Ok(())
    }

    /// Durable journal, outbox and actor-state snapshot of a closed account, reopened the
    /// ordinary way with the fixture passphrase. Same format as `AccountSessionHarness::snapshot`.
    /// # Errors
    /// Returns open, unlock or storage failures.
    pub fn reopen_snapshot(root: &Path, id: &str) -> Result<String, SdkError> {
        let mut client = RamfluxClient::new();
        client.open_account_index(root)?;
        client.unlock_account(id, b"native call fixture passphrase")?;
        let db = client.account_db()?;
        Ok(format!(
            "{:?}|{:?}|{:?}|{:?}",
            db.journal_bounds()?,
            db.journal_after(0, 128)?,
            db.pending_outbox(256)?,
            db.list_actor_states::<serde_json::Value>("")?
        ))
    }

    /// # Errors
    /// Returns the production host/writer startup error.
    pub async fn attach(
        self,
        session: GatewaySessionState,
        incarnation: String,
        stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    ) -> Result<AccountSessionHarness, SdkError> {
        Box::pin(self.attach_negotiated(session, incarnation, false, stream)).await
    }

    /// Attach with the ephemeral capability the gateway negotiated for this session.
    /// # Errors
    /// Returns the production host/writer startup error.
    pub async fn attach_negotiated(
        self,
        session: GatewaySessionState,
        incarnation: String,
        ephemeral: bool,
        stream: Box<dyn ramflux_transport::GatewaySessionTransport + Send>,
    ) -> Result<AccountSessionHarness, SdkError> {
        let index = self.client.account_index()?.clone();
        self.client
            .first_activate_receive_ledger(&self.config.target_delivery_id, Some(&incarnation))?;
        Box::pin(AccountSessionHarness::attach_initialized(
            index,
            self.client,
            self.config,
            session,
            stream,
            FixtureCapabilities { incarnation: Some(incarnation), ephemeral },
        ))
        .await
    }
}
