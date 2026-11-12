// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real disk vault, account store and native unlock. Tests never call `set_var`.

use super::{
    StageExisting, StageNew, ordinary_networking_allowed, ordinary_session_admitted,
    stage_existing, stage_new, unadmitted_data_unlock, unlock_with_provider,
};
use crate::SdkError;
use crate::bus::native_account::unlock_from_provider;
use crate::bus::state::LocalBusDaemonState;
use crate::custody::pairing::install_store;
use crate::custody::pairing::local_credential::{
    CredentialOutcome, LocalCredentialProvider, PersistedReservation, RecipientSecrets, SecretUtf8,
    acquire_setup, acquire_unlock, cancel_credential, forget_slots, last_wiped_confirmation_bytes,
    last_wiped_pairing_bytes, load_reservation, persist_reservation, take_cancel_fences,
    take_owner_drops, take_pairing_secret_cleanups, take_pairing_secret_drops,
    take_secret_utf8_drops, take_secret_utf8_zeroed,
};
use crate::custody::{BranchCredentials, PrimaryVault, require_vault_reference};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use ramflux_protocol::custody::pairing::native::{Invitation, invitation_signing_bytes};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AdoptionRow, FileVaultSecretSource};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PHRASE: &[u8] = b"correct-passphrase";
const STAGE: &str = "acct-p08-stage";
const RESTART: &str = "acct-p08-restart";
const SHARED: &str = "acct-p08-shared";
const NODE_SEED: [u8; 32] = [8; 32];

fn b32(byte: u8) -> String {
    encode_base64url([byte; 32])
}

fn invitation(
    mode: &str,
    request: u8,
    destination: Option<DeviceRef>,
) -> TestResult<Envelope<Invitation>> {
    let anchor =
        destination.as_ref().map_or_else(|| b32(2), |device| device.account_anchor.clone());
    let primary = DeviceRef {
        account_anchor: anchor.clone(),
        device_id: "dev-primary".into(),
        device_epoch: 1,
    };
    let existing = mode == "existing";
    let body = Invitation {
        schema: "ramflux.pairing.Invitation.v2".into(),
        version: 2,
        invitation_id: b32(1),
        issuer_seq: 1,
        request_id: b32(request),
        node_key: ramflux_crypto::public_key_base64url_from_seed(NODE_SEED),
        public_origin: "https://relay.example:443".into(),
        account_anchor: anchor,
        primary_ref: primary,
        base_record_hash: b32(5),
        base_epoch: 1,
        purpose: if existing { "primary_transfer" } else { "enroll" }.into(),
        recipient_mode: mode.into(),
        destination_ref: destination,
        capabilities: vec!["message".into(), "sync".into()],
        lease_not_before: 1_700_000_000,
        lease_expires_at: 1_700_000_300,
        data_selection: Vec::new(),
        transfer_id: existing.then(|| b32(6)),
        created_at: 100,
        expires_at: 400,
    };
    let bytes = invitation_signing_bytes(&body)?;
    Ok(Envelope {
        body,
        signature: ramflux_crypto::sign_canonical_bytes_with_seed(&bytes, NODE_SEED),
    })
}

pub(crate) struct Phrase {
    passphrase: &'static [u8],
    confirmation: Option<&'static [u8]>,
    refuse: bool,
    setups: AtomicU64,
}

impl Phrase {
    pub(crate) fn setup(passphrase: &'static [u8]) -> Self {
        Self {
            passphrase,
            confirmation: Some(passphrase),
            refuse: false,
            setups: AtomicU64::new(0),
        }
    }

    fn mismatch() -> Self {
        Self {
            passphrase: b"one-pass",
            confirmation: Some(b"two-pass"),
            refuse: false,
            setups: AtomicU64::new(0),
        }
    }

    fn refuse() -> Self {
        Self { passphrase: b"x", confirmation: None, refuse: true, setups: AtomicU64::new(0) }
    }
}

impl LocalCredentialProvider for Phrase {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        if request.action == "setup" {
            self.setups.fetch_add(1, Ordering::SeqCst);
        }
        if self.refuse {
            return Ok(CredentialOutcome::Refused);
        }
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(self.passphrase)?,
            confirmation: if request.action == "setup" {
                Some(SecretUtf8::from_bytes(self.confirmation.unwrap_or(self.passphrase))?)
            } else {
                None
            },
        })
    }
}

pub(crate) struct LateCancel {
    root: PathBuf,
    account: String,
}

impl LocalCredentialProvider for LateCancel {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        cancel_credential(&self.root, &self.account);
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(PHRASE)?,
            confirmation: if request.action == "setup" {
                Some(SecretUtf8::from_bytes(PHRASE)?)
            } else {
                None
            },
        })
    }
}

pub(crate) struct DiskVault {
    dir: PathBuf,
}

impl DiskVault {
    pub(crate) fn open(dir: impl AsRef<Path>) -> Result<Self, SdkError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn slot(&self, reference: &str) -> PathBuf {
        let mut name = String::new();
        for byte in reference.as_bytes() {
            let _ = write!(name, "{byte:02x}");
        }
        self.dir.join(name)
    }

    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(self.slot(reference)) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(SdkError::CustodyVaultUnavailable)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl PrimaryVault for DiskVault {
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }

    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        require_vault_reference(reference, "")?;
        self.put(reference, key.vault_seed().as_slice())
    }

    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        require_vault_reference(reference, "")?;
        let bytes =
            fs::read(self.slot(reference)).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != 32 {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&bytes);
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }

    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        if reference.starts_with(ramflux_storage::FileVaultSecretSource::OWNER_PREFIX) {
            return Ok(());
        }
        match fs::remove_file(self.slot(reference)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        require_vault_reference(reference, "branch:")?;
        self.put(reference, seeds.as_slice())
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        require_vault_reference(reference, "branch:")?;
        let bytes =
            fs::read(self.slot(reference)).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != 64 {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seeds = Zeroizing::new([0_u8; 64]);
        seeds.copy_from_slice(&bytes);
        BranchCredentials::from_vault_seeds(principal, device, &seeds)
    }

    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        require_vault_reference(reference, "agent-provisioning:")?;
        self.put(reference, secret)
    }

    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        require_vault_reference(reference, "agent-provisioning:")?;
        Ok(Zeroizing::new(
            fs::read(self.slot(reference)).map_err(|_| SdkError::CustodyVaultUnavailable)?,
        ))
    }
}

struct FailVault;

impl PrimaryVault for FailVault {
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_new(&self, _: &str, _: &SelfSigningKey) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn load_primary(&self, _: &str) -> Result<SelfSigningKey, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    fn delete(&self, _: &str) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_branch(&self, _: &str, _: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
}

struct CountSends {
    sends: Arc<AtomicUsize>,
}

impl GatewaySessionFrameSink for CountSends {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for CountSends {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, TransportError>> + Send + '_>,
    > {
        Box::pin(async { Err(TransportError::Quic("unexpected network".into())) })
    }
}

fn daemon(root: &Path) -> LocalBusDaemonState {
    LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: crate::LocalBusConfig::new(root.join("bus.sock"), root),
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

fn bind(
    root: &Path,
    account_id: &str,
    reservation_id: &str,
    generation: u64,
    action: &str,
) -> TestResult<CredentialRequest> {
    persist_reservation(
        root,
        &PersistedReservation {
            account_id: account_id.into(),
            reservation_id: reservation_id.into(),
            frontend_generation: generation,
        },
    )?;
    Ok(CredentialRequest {
        local_account_id: account_id.into(),
        reservation_id: reservation_id.into(),
        frontend_generation: generation,
        action: action.into(),
    })
}

fn reopen_unlock(root: &Path, account_id: &str) -> TestResult<CredentialRequest> {
    let stored = load_reservation(root, account_id)?.ok_or("missing reservation")?;
    Ok(CredentialRequest {
        local_account_id: stored.account_id,
        reservation_id: stored.reservation_id,
        frontend_generation: stored.frontend_generation,
        action: "unlock".into(),
    })
}

fn assert_wiped() {
    assert!(last_wiped_pairing_bytes().iter().all(|byte| *byte == 0), "pairing secrets not zeroed");
}

fn assert_confirmation_cleared() {
    assert!(last_wiped_confirmation_bytes().iter().all(|byte| *byte == 0), "confirmation leftover");
}

fn stage_sample(
    root: &Path,
    vault: &DiskVault,
    account: &str,
) -> TestResult<super::StagedRecipient> {
    let invite = invitation("new", 3, None)?;
    Ok(stage_new(&StageNew {
        root,
        account_id: account,
        invitation: &invite,
        vault,
        provider: &Phrase::setup(PHRASE),
        frontend_generation: 1,
    })?)
}

fn closed_unlock_leg(root: &Path, account: &str) -> TestResult {
    let expected = reopen_unlock(root, account)?;
    let mut state = daemon(root);
    let Err(error) =
        unlock_from_provider(&mut state, account, &expected, &Phrase::setup(PHRASE), None)
    else {
        return Err("expected PublicationPending".into());
    };
    assert!(matches!(error, SdkError::PairingCode("PublicationPending")));
    assert!(state.accounts.is_empty());
    Ok(())
}

async fn existing_open_leg() -> TestResult {
    let dest = tempfile::tempdir()?;
    let vault = crate::custody::tests::TestVault::default();
    let now = crate::custody::network_now()?;
    let native = crate::custody::tests::create_with_device(
        dest.path(),
        "acct-open",
        "dev-open",
        &vault,
        now,
    )?;
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(dest.path())?;
    client.seal_new_account_data("acct-open", &native.record().body.account_anchor, PHRASE)?;
    drop(client);
    let data_ref = FileVaultSecretSource::owner_ref("acct-open");
    let recipient_ref = DeviceRef {
        account_anchor: native.record().body.account_anchor.clone(),
        device_id: native.local_device_id()?.into(),
        device_epoch: 1,
    };
    let invite = invitation("existing", 21, Some(recipient_ref.clone()))?;
    let staged = stage_existing(&StageExisting {
        new: StageNew {
            root: dest.path(),
            account_id: "acct-open",
            invitation: &invite,
            vault: &DiskVault::open(dest.path().join("disk-vault"))?,
            provider: &Phrase::setup(PHRASE),
            frontend_generation: 1,
        },
        recipient_ref: recipient_ref.clone(),
        branch_vault_ref: native.branch_vault_ref(),
        data_vault_ref: &data_ref,
    })?;
    closed_unlock_leg(dest.path(), "acct-open")?;
    install_store::remove_pending(dest.path(), "acct-open", &staged.install.operation_id)?;
    let hash = ramflux_protocol::custody::object_hash(native.record())?;
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(dest.path())?;
    client.unlock_account("acct-open", PHRASE)?;
    client.account_db()?.put_pairing_adoption(&AdoptionRow {
        account_id: "acct-open".into(),
        operation_id: staged.install.operation_id.clone(),
        record_hash: hash.clone(),
        local_ref: canonical_json_bytes(&recipient_ref)?,
        local_role: "secondary".into(),
        branch_vault_ref: staged.branch_vault_ref.clone(),
        data_vault_ref: staged.data_vault_ref.clone(),
        primary_vault_ref: None,
    })?;
    drop(client);
    let mut installed = staged.install;
    installed.record_hash = Some(hash);
    installed.state = "installed".into();
    installed.validate()?;
    install_store::write_installed(dest.path(), &installed)?;
    let expected = reopen_unlock(dest.path(), "acct-open")?;
    let mut state = daemon(dest.path());
    unlock_from_provider(&mut state, "acct-open", &expected, &Phrase::setup(PHRASE), None)?;
    let account = state.accounts.get_mut("acct-open").ok_or("unlocked")?;
    assert!(account.activation_pending);
    assert!(ordinary_session_admitted(&account.client, "acct-open")?);
    let sends = Arc::new(AtomicUsize::new(0));
    account.engine = Some(crate::gateway::GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(CountSends { sends: Arc::clone(&sends) }),
    ));
    account.engine.as_mut().ok_or("engine")?.stream.send_frame(b"pre-ack").await?;
    assert_eq!(sends.load(Ordering::SeqCst), 1, "pre-ACK send");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pairing_recipient_stages_own_keys_without_primary() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault_dir = root.path().join("disk-vault");
    let vault = DiskVault::open(&vault_dir)?;
    let invite = invitation("new", 3, None)?;
    let staged = stage_new(&StageNew {
        root: root.path(),
        account_id: STAGE,
        invitation: &invite,
        vault: &vault,
        provider: &Phrase::setup(PHRASE),
        frontend_generation: 1,
    })?;
    assert_eq!(staged.install.state, "vault_durable");
    assert!(staged.install.primary_vault_ref.is_none());
    assert!(staged.install.record_hash.is_none());
    assert_ne!(staged.reservation_id, invite.body.request_id);
    assert_eq!(ramflux_protocol::decode_base64url(&staged.reservation_id)?.len(), 32);
    require_vault_reference(&staged.branch_vault_ref, "branch:")?;
    assert_eq!(staged.data_vault_ref, FileVaultSecretSource::owner_ref(STAGE));
    assert_ne!(staged.data_vault_ref, staged.branch_vault_ref);
    assert!(vault.load_primary(&staged.data_vault_ref).is_err());
    assert!(vault.load_provisioning_secret(&format!("agent-provisioning:{}", b32(2))).is_err());
    drop(vault);
    let reopened = DiskVault::open(&vault_dir)?;
    let _ = reopened.load_branch(
        &staged.branch_vault_ref,
        &staged.recipient_ref.account_anchor,
        &staged.recipient_ref,
    )?;
    assert!(root.path().join("vault").join(format!("{STAGE}.key")).is_file());
    assert!(unadmitted_data_unlock(root.path(), STAGE)?);
    assert!(!ordinary_networking_allowed(root.path(), STAGE)?);
    assert!(!root.path().join("custody_accounts").join(STAGE).join("authority.json").exists());
    closed_unlock_leg(root.path(), STAGE)?;
    existing_open_leg().await
}

#[test]
fn pairing_local_data_credential_survives_restart() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault = DiskVault::open(root.path().join("disk-vault"))?;
    let staged = stage_sample(root.path(), &vault, RESTART)?;
    drop(vault);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    let expected = reopen_unlock(root.path(), RESTART)?;
    let Err(error) = unlock_with_provider(&mut client, RESTART, &expected, &Phrase::refuse())
    else {
        return Err("expected VaultUnavailable".into());
    };
    assert!(matches!(error, SdkError::PairingCode("VaultUnavailable")));
    assert!(client.account_db().is_err());
    assert!(!ordinary_networking_allowed(root.path(), RESTART)?);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    let Err(wrong) = client.unlock_account(RESTART, b"wrong-passphrase") else {
        return Err("expected wrong passphrase".into());
    };
    assert!(wrong.to_string().contains("wrong passphrase or damaged local key"));
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    let expected = reopen_unlock(root.path(), RESTART)?;
    unlock_with_provider(&mut client, RESTART, &expected, &Phrase::setup(PHRASE))?;
    let sentinel = client.account_db()?.load_actor_state::<String>("pairing/local-sentinel")?;
    assert_eq!(sentinel.as_deref(), Some("sealed"));
    drop(client);
    existing_target_leg(root.path(), &staged)
}

fn existing_target_leg(root: &Path, _staged: &super::StagedRecipient) -> TestResult {
    let dest_root = tempfile::tempdir()?;
    let vault = crate::custody::tests::TestVault::default();
    let now = crate::custody::network_now()?;
    let native = crate::custody::tests::create_with_device(
        dest_root.path(),
        "acct-exist",
        "dev-dest",
        &vault,
        now,
    )?;
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(dest_root.path())?;
    client.seal_new_account_data("acct-exist", &native.record().body.account_anchor, PHRASE)?;
    drop(client);
    let recipient_ref = DeviceRef {
        account_anchor: native.record().body.account_anchor.clone(),
        device_id: native.local_device_id()?.into(),
        device_epoch: 1,
    };
    let invite = invitation("existing", 13, Some(recipient_ref.clone()))?;
    let data_ref = FileVaultSecretSource::owner_ref("acct-exist");
    let counter = Phrase::setup(PHRASE);
    let refused = stage_existing(&StageExisting {
        new: StageNew {
            root: dest_root.path(),
            account_id: "acct-exist",
            invitation: &invite,
            vault: &DiskVault::open(dest_root.path().join("disk-vault"))?,
            provider: &Phrase::refuse(),
            frontend_generation: 1,
        },
        recipient_ref: recipient_ref.clone(),
        branch_vault_ref: native.branch_vault_ref(),
        data_vault_ref: &data_ref,
    });
    assert!(matches!(refused, Err(SdkError::PairingCode("VaultUnavailable"))));
    assert_eq!(install_store::list_pending(dest_root.path(), "acct-exist")?.len(), 0);
    assert!(
        load_reservation(dest_root.path(), "acct-exist")?.is_none(),
        "refusal removes pairing-reservation.json"
    );
    let again = stage_existing(&StageExisting {
        new: StageNew {
            root: dest_root.path(),
            account_id: "acct-exist",
            invitation: &invite,
            vault: &DiskVault::open(dest_root.path().join("disk-vault"))?,
            provider: &counter,
            frontend_generation: 2,
        },
        recipient_ref,
        branch_vault_ref: native.branch_vault_ref(),
        data_vault_ref: &data_ref,
    })?;
    assert_eq!(counter.setups.load(Ordering::SeqCst), 0, "zero-setup");
    assert_eq!(again.branch_vault_ref, native.branch_vault_ref());
    assert_eq!(again.data_vault_ref, data_ref);
    assert_eq!(again.install.recipient_mode, "existing");
    let _ = root;
    Ok(())
}

fn shared_keychain_leg() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault = DiskVault::open(root.path().join("disk-vault"))?;
    let invite = invitation("new", 3, None)?;
    let hashed =
        crate::custody::custody_vault_reference(root.path(), SHARED, &invite.body.account_anchor)?;
    let branch = format!("branch:{hashed}");
    vault.store_branch(&branch, &Zeroizing::new([9_u8; 64]))?;
    let Err(error) = stage_new(&StageNew {
        root: root.path(),
        account_id: SHARED,
        invitation: &invite,
        vault: &vault,
        provider: &Phrase::setup(PHRASE),
        frontend_generation: 1,
    }) else {
        return Err("expected collision".into());
    };
    assert!(matches!(error, SdkError::CustodyVaultUnavailable));
    let dest = DeviceRef {
        account_anchor: invite.body.account_anchor.clone(),
        device_id: "dev-keep".into(),
        device_epoch: 1,
    };
    let _ = vault.load_branch(&branch, &invite.body.account_anchor, &dest)?;
    Ok(())
}

#[test]
fn pairing_owned_secret_cleanup_all_exits() -> TestResult {
    let _ = take_pairing_secret_cleanups();
    let _ = take_pairing_secret_drops();
    let _ = take_secret_utf8_drops();
    let _ = take_cancel_fences();
    let root = tempfile::tempdir()?;
    let expected = bind(root.path(), "acct-mismatch", &b32(9), 1, "setup")?;
    let stored = load_reservation(root.path(), "acct-mismatch")?.ok_or("stored")?;
    assert!(acquire_setup(root.path(), &expected, &Phrase::mismatch(), &stored).is_err());
    assert!(take_pairing_secret_cleanups() >= 1, "mismatch");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_eq!(take_owner_drops(), (0, 0, 0));
    assert_confirmation_cleared();
    assert_wiped();
    assert_eq!(take_secret_utf8_drops(), 0);
    assert!(take_secret_utf8_zeroed() >= 1);

    let expected = bind(root.path(), "acct-refuse", &b32(10), 1, "setup")?;
    let stored = load_reservation(root.path(), "acct-refuse")?.ok_or("stored")?;
    assert!(acquire_setup(root.path(), &expected, &Phrase::refuse(), &stored).is_err());
    assert!(take_pairing_secret_cleanups() >= 1, "setup refuse");

    let expected = bind(root.path(), "acct-unlock", &b32(11), 1, "unlock")?;
    let stored = load_reservation(root.path(), "acct-unlock")?.ok_or("stored")?;
    assert!(acquire_unlock(root.path(), &expected, &Phrase::refuse(), &stored).is_err());

    let expected = bind(root.path(), "acct-cancel", &b32(12), 1, "setup")?;
    let stored = load_reservation(root.path(), "acct-cancel")?.ok_or("stored")?;
    let late = LateCancel { root: root.path().to_path_buf(), account: "acct-cancel".into() };
    assert!(acquire_setup(root.path(), &expected, &late, &stored).is_err());
    assert!(take_cancel_fences() >= 1, "cancel");
    let _ = take_pairing_secret_cleanups();
    let _ = take_pairing_secret_drops();

    drop(RecipientSecrets::new(Zeroizing::new([3_u8; 64])));
    assert_eq!(take_pairing_secret_cleanups(), 1, "drop");
    assert_eq!(take_owner_drops(), (0, 0, 1));
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    let mut owned = RecipientSecrets::new(Zeroizing::new([5_u8; 64]));
    owned.cleanup();
    assert!(owned.is_wiped());
    drop(owned);
    assert_eq!(take_pairing_secret_cleanups(), 1, "explicit cleanup");
    assert_eq!(take_pairing_secret_drops(), 0);

    let Err(error) = stage_new(&StageNew {
        root: root.path(),
        account_id: "acct-fail",
        invitation: &invitation("new", 3, None)?,
        vault: &FailVault,
        provider: &Phrase::setup(PHRASE),
        frontend_generation: 1,
    }) else {
        return Err("expected CustodyVaultUnavailable".into());
    };
    assert!(matches!(error, SdkError::CustodyVaultUnavailable));
    shared_keychain_leg()
}

#[test]
fn pairing_credential_slot_rearms_across_unlock_and_restart() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault = DiskVault::open(root.path().join("disk-vault"))?;
    let staged = stage_sample(root.path(), &vault, "acct-p08-slot")?;
    drop(vault);
    let expected = reopen_unlock(root.path(), "acct-p08-slot")?;
    let stored = load_reservation(root.path(), "acct-p08-slot")?.ok_or("stored")?;
    let late = LateCancel { root: root.path().to_path_buf(), account: "acct-p08-slot".into() };
    assert!(acquire_unlock(root.path(), &expected, &late, &stored).is_err(), "late callback");
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    unlock_with_provider(&mut client, "acct-p08-slot", &expected, &Phrase::setup(PHRASE))?;
    drop(client);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    unlock_with_provider(&mut client, "acct-p08-slot", &expected, &Phrase::setup(PHRASE))?;
    drop(client);
    forget_slots();
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    unlock_with_provider(&mut client, "acct-p08-slot", &expected, &Phrase::setup(PHRASE))?;
    assert_eq!(staged.install.state, "vault_durable");
    Ok(())
}
