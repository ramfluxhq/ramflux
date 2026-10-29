// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::PrincipalKind;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) struct Root(pub(crate) PathBuf);
impl Root {
    pub(crate) fn new() -> Result<Self> {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let root =
            base.join(format!("rf-custody-{}", ramflux_protocol::encode_base64url(*random()?)));
        std::fs::create_dir(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
pub(crate) struct TestVault {
    secrets: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    pub(crate) fail: AtomicBool,
    fail_branch: AtomicBool,
    commit_obstacle: Mutex<Option<PathBuf>>,
    cancel_commit: Mutex<Option<std::sync::Arc<CommitGate>>>,
}
impl TestVault {
    pub(crate) fn entry_count(&self) -> std::result::Result<usize, SdkError> {
        Ok(self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.len())
    }
    pub(crate) fn contains_material(&self, material: &[u8]) -> std::result::Result<bool, SdkError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
            .values()
            .any(|entry| entry.windows(material.len()).any(|part| part == material)))
    }
    pub(crate) fn primary_for_public_key(
        &self,
        public: &str,
    ) -> std::result::Result<SelfSigningKey, SdkError> {
        let entries = self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        for bytes in entries.values().filter(|bytes| bytes.len() == 32) {
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(bytes);
            let key = SelfSigningKey::from_vault_seed(&seed);
            if key.public_key() == public {
                return Ok(key);
            }
        }
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn put(&self, reference: &str, bytes: &[u8]) -> std::result::Result<(), SdkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut secrets = self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if secrets.contains_key(reference) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        secrets.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
}
impl PrimaryVault for TestVault {
    fn delete(&self, reference: &str) -> std::result::Result<(), SdkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        Ok(())
    }
    fn preflight(&self) -> std::result::Result<(), SdkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(())
    }
    fn store_new(
        &self,
        reference: &str,
        key: &SelfSigningKey,
    ) -> std::result::Result<(), SdkError> {
        self.put(reference, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> std::result::Result<SelfSigningKey, SdkError> {
        let map = self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = map.get(reference).ok_or(SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != 32 {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(bytes);
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> std::result::Result<BranchCredentials, SdkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let secrets = self.secrets.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = secrets
            .get(reference)
            .filter(|bytes| bytes.len() == 64)
            .ok_or(SdkError::CustodyVaultUnavailable)?;
        let mut seeds = Zeroizing::new([0; 64]);
        seeds.copy_from_slice(bytes);
        BranchCredentials::from_vault_seeds(principal, device, &seeds)
    }
    fn store_branch(
        &self,
        reference: &str,
        seeds: &Zeroizing<[u8; 64]>,
    ) -> std::result::Result<(), SdkError> {
        if self.fail_branch.load(Ordering::SeqCst) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        self.put(reference, &**seeds)?;
        if let Some(gate) =
            self.cancel_commit.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.take()
        {
            gate.cancel();
        }
        if let Some(path) =
            self.commit_obstacle.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.take()
        {
            std::fs::write(path, b"incomplete test reservation")?;
        }
        Ok(())
    }
}
pub(crate) fn input(id: &str) -> CreateInput {
    CreateInput {
        local_account_id: id.into(),
        principal_id: format!("principal-{id}"),
        device_id: "primary".into(),
        display_name: "Example Human".into(),
        principal_kind: PrincipalKind::Human,
        custodian_account_id: None,
    }
}
pub(crate) fn words(phrase: &str, positions: [u8; 3]) -> Result<[Zeroizing<String>; 3]> {
    let mut words = [
        Zeroizing::new(String::new()),
        Zeroizing::new(String::new()),
        Zeroizing::new(String::new()),
    ];
    for (target, index) in words.iter_mut().zip(positions) {
        *target = Zeroizing::new(
            phrase.split_whitespace().nth(usize::from(index) - 1).ok_or("position")?.into(),
        );
    }
    Ok(words)
}
pub(crate) fn create(
    root: &Path,
    id: &str,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<BornAccount> {
    create_with_device(root, id, "primary", vault, now)
}
pub(crate) fn create_with_phrase(
    root: &Path,
    id: &str,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(BornAccount, Zeroizing<String>)> {
    let mut ceremony = CreationCeremony::begin(true, root, input(id), now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let account = ceremony.confirm(&words(&phrase, positions)?, vault, now)?;
    Ok((account, phrase))
}
pub(crate) fn create_with_device(
    root: &Path,
    id: &str,
    device: &str,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<BornAccount> {
    let mut input = input(id);
    input.device_id = device.into();
    let mut ceremony = CreationCeremony::begin(true, root, input, now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    Ok(ceremony.confirm(&words(&phrase, positions)?, vault, now)?)
}
pub(crate) fn mark_live(root: &Path, id: &str, now: u64) -> Result {
    let mut account = load_account(root, id, now)?;
    account.mark_live(root)?;
    Ok(())
}
#[test]
fn custody_default_off_has_no_recovery_or_persistence_side_effects() -> Result {
    let root = Root::new()?;
    assert!(matches!(
        CreationCeremony::begin(false, &root.0, input("off"), 100),
        Err(SdkError::CustodyCreationDisabled)
    ));
    assert!(!root.0.join("custody_accounts").exists());
    assert_eq!(std::fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}
#[test]
fn custody_show_once_ordering_and_single_confirmation_attempt_are_enforced() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let mut ceremony = CreationCeremony::begin(true, &root.0, input("repeat"), 100)?;
    let phrase = ceremony.show_once()?;
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert!(ceremony.show_once().is_err());
    assert!(ceremony.hidden_challenge().is_err());
    let mut ceremony = CreationCeremony::begin(true, &root.0, input("wrong"), 100)?;
    assert!(ceremony.hidden_challenge().is_err());
    assert!(ceremony.show_once().is_err());
    let mut ceremony = CreationCeremony::begin(true, &root.0, input("failed"), 100)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    assert!(positions.iter().all(|p| (1..=24).contains(p)));
    assert_ne!(positions[0], positions[1]);
    assert_ne!(positions[0], positions[2]);
    assert_ne!(positions[1], positions[2]);
    let mut answers = words(&phrase, positions)?;
    answers[1] = Zeroizing::new("not-a-word".into());
    assert!(matches!(
        ceremony.confirm(&answers, &vault, 100),
        Err(SdkError::CustodyConfirmationFailed)
    ));
    assert!(!root.0.join("custody_accounts").exists());
    Ok(())
}
#[test]
fn custody_confirmed_authority_reloads_with_latch_and_without_phrase_or_master_on_disk() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let mut ceremony = CreationCeremony::begin(true, &root.0, input("new"), 100)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let account = ceremony.confirm(&words(&phrase, positions)?, &vault, 100)?;
    assert_eq!(account.state(), CreationState::NetworkingPending);
    assert!(matches!(account.require_networking(), Err(SdkError::NetworkingPending)));
    let loaded = load_account(&root.0, "new", 100)?;
    assert_eq!(loaded.record(), account.record());
    for version in [1, 2, 4] {
        assert!(matches!(
            loaded.require_record_version(version),
            Err(SdkError::CustodyModeDowngrade)
        ));
    }
    let path = root.0.join("custody_accounts/new/authority.json");
    let bytes = std::fs::read(&path)?;
    let text = std::str::from_utf8(&bytes)?;
    for forbidden in [
        phrase.as_str(),
        "root_seed",
        "master_seed",
        "self_signing_seed",
        "account_secret",
        "device_seed",
    ] {
        assert!(!text.contains(forbidden));
    }
    let stored: super::store::StoredAuthority = serde_json::from_slice(&bytes)?;
    assert_ne!(stored.primary_vault_ref, stored.branch_vault_ref);
    assert_eq!(
        vault.load_primary(&stored.primary_vault_ref)?.public_key(),
        loaded.record().body.master_certificate.body.self_signing_public_key
    );
    assert!(!root.0.join("local_bus_accounts").exists());
    let mut bad: serde_json::Value = serde_json::from_slice(&bytes)?;
    bad["custody_v3_observed"] = serde_json::Value::Bool(false);
    std::fs::write(&path, serde_json::to_vec(&bad)?)?;
    assert!(load_account(&root.0, "new", 100).is_err());
    assert!(account_exists(&root.0, "new")?);
    Ok(())
}
#[test]
fn custody_vault_failure_reserves_mode_and_never_creates_a_legacy_manifest() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    vault.fail.store(true, Ordering::SeqCst);
    assert!(create(&root.0, "failed", &vault, 100).is_err());
    assert!(account_exists(&root.0, "failed")?);
    assert!(load_account(&root.0, "failed", 100).is_err());
    assert!(!root.0.join("local_bus_accounts").exists());
    assert!(CreationCeremony::begin(true, &root.0, input("failed"), 100).is_err());
    Ok(())
}
#[test]
fn custody_nonhuman_genesis_requires_current_local_human_custody() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let human = create(&root.0, "human", &vault, 100)?;
    let mut input = input("service");
    input.principal_kind = PrincipalKind::HeadlessAi;
    assert!(CreationCeremony::begin(true, &root.0, input.clone(), 100).is_err());
    input.custodian_account_id = Some("human".into());
    let mut ceremony = CreationCeremony::begin(true, &root.0, input, 100)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let account = ceremony.confirm(&words(&phrase, positions)?, &vault, 100)?;
    assert_eq!(
        account.record().body.master_certificate.body.primary_device_ref.account_anchor,
        human.record().body.account_anchor
    );
    load_account(&root.0, "service", 100)?;
    Ok(())
}
#[tokio::test]
async fn custody_gateway_refuses_before_network_io_and_legacy_proof_generation() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let account = create(&root.0, "new", &vault, 100)?;
    let mut client = crate::RamfluxClient::new();
    client.load_born_v3_account(&root.0, "new", 100)?;
    assert!(matches!(
        client.observe_device_manifest_json(
            serde_json::Value::Null,
            &account.record().body.account_anchor
        ),
        Err(SdkError::CustodyModeDowngrade)
    ));
    assert!(matches!(
        client.authorize_current_device("node", vec![], 100, 200),
        Err(SdkError::NetworkingPending)
    ));
    let endpoint = crate::GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: "127.0.0.1:1".parse()?,
        server_name: "invalid.example".into(),
        ca_cert: root.0.join("nonexistent.pem"),
        principal_id: "unused".into(),
        device_id: "primary".into(),
        target_delivery_id: "unused".into(),
        prekey_http_url: None,
    };
    assert!(matches!(
        crate::GatewaySessionConfig::auto(endpoint.clone()).with_account_identity(&client),
        Err(SdkError::NetworkingPending)
    ));
    let config = crate::GatewaySessionConfig::auto(endpoint).with_born_v3_account(&account);
    let legacy = ramflux_crypto::create_identity_root("unused", [1; 32]);
    let branch = ramflux_crypto::create_device_branch("unused", "primary", 1, [2; 32]);
    assert!(matches!(
        config.clone().with_owned_device(&legacy, branch),
        Err(SdkError::NetworkingPending)
    ));
    assert!(matches!(
        crate::GatewaySessionEngine::connect(config).await,
        Err(SdkError::NetworkingPending)
    ));
    Ok(())
}

#[test]
fn custody_partial_vault_import_cannot_be_retried_as_a_legacy_account() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    vault.fail_branch.store(true, Ordering::SeqCst);
    assert!(create(&root.0, "partial", &vault, 100).is_err());
    assert!(account_exists(&root.0, "partial")?);
    assert!(!root.0.join("custody_accounts/partial/authority.json").exists());
    let mut legacy = crate::RamfluxClient::new();
    legacy.open_account_index(&root.0)?;
    assert!(matches!(
        legacy.unlock_account("partial", b"data-secret"),
        Err(SdkError::NetworkingPending)
    ));
    assert_eq!(vault.secrets.lock().map_err(|_| "vault lock")?.len(), 0);
    Ok(())
}

#[test]
fn custody_valid_sibling_authority_cannot_replace_the_indexed_local_anchor() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let first = create(&root.0, "first", &vault, 100)?;
    create(&root.0, "second", &vault, 100)?;
    let mut public: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.0.join("custody_accounts/second/authority.json"),
    )?)?;
    public["local_account_id"] = serde_json::json!("first");
    std::fs::write(
        root.0.join("custody_accounts/first/authority.json"),
        serde_json::to_vec(&public)?,
    )?;
    assert!(load_account(&root.0, "first", 100).is_err());
    assert_eq!(
        ramflux_storage::AccountIndex::open(&root.0)?.account("first")?.principal_commitment,
        first.record().body.account_anchor
    );
    Ok(())
}
#[test]
fn custody_loading_requires_a_separate_client_from_an_existing_legacy_identity() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    create(&root.0, "born", &vault, 100)?;
    let mut legacy = crate::RamfluxClient::new();
    let original = legacy.create_identity_root("legacy", [27; 32]);
    assert!(matches!(
        legacy.load_born_v3_account(&root.0, "born", 100),
        Err(SdkError::CustodySetupInvalid)
    ));
    assert_eq!(
        legacy.identity_root.as_ref().map(|root| root.principal_id.as_str()),
        Some(original.principal_id.as_str())
    );
    assert!(legacy.born_v3_account.is_none());
    Ok(())
}

#[test]
fn custody_final_publication_failure_deletes_both_new_vault_entries() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    *vault.commit_obstacle.lock().map_err(|_| "vault lock")? =
        Some(root.0.join("custody_accounts/final-failure/authority.json"));
    assert!(create(&root.0, "final-failure", &vault, 100).is_err());
    assert_eq!(vault.secrets.lock().map_err(|_| "vault lock")?.len(), 0);
    assert!(account_exists(&root.0, "final-failure")?);
    assert!(load_account(&root.0, "final-failure", 100).is_err());
    assert!(!root.0.join("local_bus_accounts/final-failure.json").exists());
    Ok(())
}

#[test]
fn custody_cancel_during_persistence_removes_new_primary_and_branch_credentials() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let mut pending = CreationCeremony::begin(true, &root.0, input("cancelled-commit"), 100)?;
    let phrase = pending.show_once()?;
    let positions = pending.hidden_challenge()?;
    let gate = std::sync::Arc::new(CommitGate::new(pending.deadline()));
    pending.guard_commit(std::sync::Arc::clone(&gate));
    *vault.cancel_commit.lock().map_err(|_| "vault lock")? = Some(gate);
    assert!(
        pending
            .confirm_with_passphrase(
                &words(&phrase, positions)?,
                &vault,
                100,
                b"discarded passphrase"
            )
            .is_err()
    );
    assert_eq!(vault.secrets.lock().map_err(|_| "vault lock")?.len(), 0);
    assert!(!root.0.join("custody_accounts/cancelled-commit/authority.json").exists());
    // The failed reservation retains its mode denial, but publishes no account authority.
    assert!(account_exists(&root.0, "cancelled-commit")?);
    let accounts = list_accounts(&root.0, 100)?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["setup_incomplete"], true);
    Ok(())
}
