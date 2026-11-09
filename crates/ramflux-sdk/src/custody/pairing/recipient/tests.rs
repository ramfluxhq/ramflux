// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real disk vault, account store and TCP probe. Tests never call `set_var`.

use super::{
    StageExisting, StageNew, ordinary_networking_allowed, stage_existing, stage_new,
    try_ordinary_network_send, unadmitted_data_unlock, unlock_with_provider,
};
use crate::SdkError;
use crate::custody::pairing::local_credential::{
    CredentialOutcome, LocalCredentialProvider, RecipientSecrets, SecretUtf8, acquire_setup,
    acquire_unlock, last_wiped_pairing_bytes, take_pairing_secret_cleanups,
    take_pairing_secret_drops,
};
use crate::custody::{BranchCredentials, PrimaryVault};
use ramflux_crypto::custody::SelfSigningKey;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::encode_base64url;
use std::cell::Cell;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PHRASE: &[u8] = b"correct-passphrase";
const ACCOUNT: &str = "acct-p08";

fn b32(byte: u8) -> String {
    encode_base64url([byte; 32])
}

fn invitation(mode: &str, request: u8) -> Envelope<Invitation> {
    let anchor = b32(2);
    let primary = DeviceRef {
        account_anchor: anchor.clone(),
        device_id: "dev-primary".into(),
        device_epoch: 1,
    };
    let existing = mode == "existing";
    Envelope {
        body: Invitation {
            schema: "ramflux.pairing.Invitation.v2".into(),
            version: 2,
            invitation_id: b32(1),
            issuer_seq: 1,
            request_id: b32(request),
            node_key: b32(4),
            public_origin: "https://relay.example:443".into(),
            account_anchor: anchor.clone(),
            primary_ref: primary,
            base_record_hash: b32(5),
            base_epoch: 1,
            purpose: if existing { "primary_transfer" } else { "enroll" }.into(),
            recipient_mode: mode.into(),
            destination_ref: existing.then(|| DeviceRef {
                account_anchor: anchor,
                device_id: "dev-dest".into(),
                device_epoch: 1,
            }),
            capabilities: vec!["message".into(), "sync".into()],
            lease_not_before: 1_700_000_000,
            lease_expires_at: 1_700_000_300,
            data_selection: Vec::new(),
            transfer_id: existing.then(|| b32(6)),
            created_at: 100,
            expires_at: 400,
        },
        signature: encode_base64url([7_u8; 64]),
    }
}

struct Phrase {
    passphrase: &'static [u8],
    confirmation: Option<&'static [u8]>,
    refuse: bool,
    setups: Cell<u64>,
}

impl Phrase {
    fn setup(passphrase: &'static [u8]) -> Self {
        Self { passphrase, confirmation: Some(passphrase), refuse: false, setups: Cell::new(0) }
    }

    fn unlock(passphrase: &'static [u8]) -> Self {
        Self { passphrase, confirmation: None, refuse: false, setups: Cell::new(0) }
    }

    fn refuse() -> Self {
        Self { passphrase: b"x", confirmation: None, refuse: true, setups: Cell::new(0) }
    }
}

impl LocalCredentialProvider for Phrase {
    fn provide(&self, request: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        if request.action == "setup" {
            self.setups.set(self.setups.get() + 1);
        }
        if self.refuse {
            return Ok(CredentialOutcome::Refused);
        }
        Ok(CredentialOutcome::Provided {
            passphrase: SecretUtf8::from_bytes(self.passphrase)?,
            confirmation: match self.confirmation {
                Some(bytes) => Some(SecretUtf8::from_bytes(bytes)?),
                None => None,
            },
        })
    }
}

struct DiskVault {
    dir: PathBuf,
}

impl DiskVault {
    fn open(dir: impl AsRef<Path>) -> Result<Self, SdkError> {
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
        self.put(reference, key.vault_seed().as_slice())
    }

    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
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
        match fs::remove_file(self.slot(reference)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.put(reference, seeds.as_slice())
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
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
        self.put(reference, secret)
    }

    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
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

struct Probe {
    origin: String,
    seen: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    addr: std::net::SocketAddr,
}

impl Probe {
    fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            loop {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let mut buf = [0_u8; 4096];
                        if let Ok(n) = stream.read(&mut buf) {
                            seen_thread
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .extend_from_slice(&buf[..n]);
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { origin: format!("http://{addr}"), seen, stop, join: Some(join), addr })
    }

    fn received(&self) -> Vec<u8> {
        self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn credential(action: &str) -> CredentialRequest {
    CredentialRequest {
        local_account_id: ACCOUNT.into(),
        reservation_id: b32(9),
        frontend_generation: 1,
        action: action.into(),
    }
}

fn assert_wiped() {
    assert!(last_wiped_pairing_bytes().iter().all(|byte| *byte == 0), "pairing secrets not zeroed");
}

#[test]
fn pairing_recipient_stages_own_keys_without_primary() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault_dir = root.path().join("disk-vault");
    let vault = DiskVault::open(&vault_dir)?;
    let invite = invitation("new", 3);
    let provider = Phrase::setup(PHRASE);
    let staged = stage_new(&StageNew {
        root: root.path(),
        account_id: ACCOUNT,
        invitation: &invite,
        vault: &vault,
        provider: &provider,
        frontend_generation: 1,
    })?;
    assert_eq!(staged.install.state, "vault_durable");
    assert!(staged.install.primary_vault_ref.is_none());
    assert!(staged.install.record_hash.is_none());
    assert!(vault.load_primary(&staged.branch_vault_ref).is_err());
    drop(vault);
    let reopened = DiskVault::open(&vault_dir)?;
    let _ = reopened.load_branch(
        &staged.branch_vault_ref,
        &staged.recipient_ref.account_anchor,
        &staged.recipient_ref,
    )?;
    let data = reopened.load_provisioning_secret(&staged.data_vault_ref)?;
    assert_eq!(data.len(), 32);
    assert!(unadmitted_data_unlock(root.path(), ACCOUNT)?);
    assert!(!ordinary_networking_allowed(root.path(), ACCOUNT)?);
    let probe = Probe::bind()?;
    let Err(error) = try_ordinary_network_send(root.path(), ACCOUNT, &probe.origin, b"{}") else {
        return Err("expected PublicationPending".into());
    };
    assert!(matches!(error, SdkError::PairingCode("PublicationPending")));
    std::thread::sleep(Duration::from_millis(40));
    assert!(probe.received().is_empty(), "pre-ACK send observed before head");
    assert!(!root.path().join("custody_accounts").join(ACCOUNT).join("authority.json").exists());
    Ok(())
}

#[test]
fn pairing_local_data_credential_survives_restart() -> TestResult {
    let root = tempfile::tempdir()?;
    let vault_dir = root.path().join("disk-vault");
    let vault = DiskVault::open(&vault_dir)?;
    let invite = invitation("new", 3);
    let provider = Phrase::setup(PHRASE);
    let staged = stage_new(&StageNew {
        root: root.path(),
        account_id: ACCOUNT,
        invitation: &invite,
        vault: &vault,
        provider: &provider,
        frontend_generation: 1,
    })?;
    drop(vault);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    let refuse = Phrase::refuse();
    let expected = credential("unlock");
    let Err(error) = unlock_with_provider(&mut client, ACCOUNT, &expected, &refuse) else {
        return Err("expected VaultUnavailable".into());
    };
    assert!(matches!(error, SdkError::PairingCode("VaultUnavailable")));
    assert!(client.account_db().is_err());
    assert!(!ordinary_networking_allowed(root.path(), ACCOUNT)?);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    let Err(wrong) = client.unlock_account(ACCOUNT, b"wrong-passphrase") else {
        return Err("expected wrong passphrase".into());
    };
    assert!(wrong.to_string().contains("wrong passphrase or damaged local key"));
    assert!(client.account_db().is_err());
    assert!(!ordinary_networking_allowed(root.path(), ACCOUNT)?);
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    unlock_with_provider(&mut client, ACCOUNT, &expected, &Phrase::unlock(PHRASE))?;
    let sentinel = client.account_db()?.load_actor_state::<String>("pairing/local-sentinel")?;
    assert_eq!(sentinel.as_deref(), Some("sealed"));
    let live = client.account_db()?.pairing_live_rows()?;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].phase, "invited");
    assert!(live[0].primary_vault_ref.is_none());
    drop(client);

    let existing_invite = invitation("existing", 13);
    let counter = Phrase::setup(PHRASE);
    let again = stage_existing(&StageExisting {
        new: StageNew {
            root: root.path(),
            account_id: ACCOUNT,
            invitation: &existing_invite,
            vault: &DiskVault::open(&vault_dir)?,
            provider: &counter,
            frontend_generation: 1,
        },
        recipient_ref: staged.recipient_ref.clone(),
        branch_vault_ref: &staged.branch_vault_ref,
        data_vault_ref: &staged.data_vault_ref,
    })?;
    assert_eq!(counter.setups.get(), 0);
    assert_eq!(again.branch_vault_ref, staged.branch_vault_ref);
    assert_eq!(again.data_vault_ref, staged.data_vault_ref);
    assert_eq!(again.install.recipient_mode, "existing");
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root.path())?;
    unlock_with_provider(&mut client, ACCOUNT, &expected, &Phrase::unlock(PHRASE))?;
    let sentinel = client.account_db()?.load_actor_state::<String>("pairing/local-sentinel")?;
    assert_eq!(sentinel.as_deref(), Some("sealed"));
    Ok(())
}

#[test]
fn pairing_owned_secret_cleanup_all_exits() -> TestResult {
    let _ = take_pairing_secret_cleanups();
    let _ = take_pairing_secret_drops();
    let mismatch = Phrase {
        passphrase: b"one-pass",
        confirmation: Some(b"two-pass"),
        refuse: false,
        setups: Cell::new(0),
    };
    assert!(acquire_setup(&credential("setup"), &mismatch).is_err());
    assert_eq!(take_pairing_secret_cleanups(), 1, "mismatch");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    assert!(acquire_setup(&credential("setup"), &Phrase::refuse()).is_err());
    assert_eq!(take_pairing_secret_cleanups(), 1, "setup refuse");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    assert!(acquire_unlock(&credential("unlock"), &Phrase::refuse()).is_err());
    assert_eq!(take_pairing_secret_cleanups(), 1, "unlock refuse");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    let mut branch = Zeroizing::new([3_u8; 64]);
    let mut data = Zeroizing::new([4_u8; 32]);
    drop(RecipientSecrets::new(branch.clone(), data.clone(), PHRASE));
    assert_eq!(take_pairing_secret_cleanups(), 1, "drop");
    assert_eq!(take_pairing_secret_drops(), 1);
    assert_wiped();
    branch.fill(0);
    data.fill(0);

    let mut owned =
        RecipientSecrets::new(Zeroizing::new([5_u8; 64]), Zeroizing::new([6_u8; 32]), PHRASE);
    owned.cleanup();
    assert!(owned.is_wiped());
    drop(owned);
    assert_eq!(take_pairing_secret_cleanups(), 1, "explicit cleanup");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    let root = tempfile::tempdir()?;
    let invite = invitation("new", 3);
    let provider = Phrase::setup(PHRASE);
    let Err(error) = stage_new(&StageNew {
        root: root.path(),
        account_id: ACCOUNT,
        invitation: &invite,
        vault: &FailVault,
        provider: &provider,
        frontend_generation: 1,
    }) else {
        return Err("expected CustodyVaultUnavailable".into());
    };
    assert!(matches!(error, SdkError::CustodyVaultUnavailable));
    assert!(take_pairing_secret_cleanups() >= 2, "error cleans credential and seeds");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();

    let ok_root = tempfile::tempdir()?;
    let vault = DiskVault::open(ok_root.path().join("disk-vault"))?;
    stage_new(&StageNew {
        root: ok_root.path(),
        account_id: "acct-ok",
        invitation: &invitation("new", 8),
        vault: &vault,
        provider: &Phrase::setup(PHRASE),
        frontend_generation: 1,
    })?;
    assert!(take_pairing_secret_cleanups() >= 2, "success cleans credential and seeds");
    assert_eq!(take_pairing_secret_drops(), 0);
    assert_wiped();
    Ok(())
}
