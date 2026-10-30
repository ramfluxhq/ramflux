// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local user-started recovery and public crash journals; no master material is serializable.
use super::{
    BornAccount, CreationState, MAX_STORED_AUTHORITY_BYTES, StoredAuthority, directory, invalid,
    load_data_account, private_directory, write_public,
};
use crate::{SdkError, custody::PrimaryVault};
use ramflux_crypto::custody::{
    MasterKey, RecoveryInput, RecoveryPhrase, SelfSigningKey, recover_primary,
};
use ramflux_protocol::custody::{CustodyAuthority, DeviceRef};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    before_hash: String,
    intent: StoredAuthority,
    previous_primary_ref: String,
    previous_branch_ref: String,
}

fn snapshot(stored: &StoredAuthority) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.local.recovery_snapshot.v1",
        &ramflux_protocol::canonical_json_bytes(stored)?,
    ))
}
fn journal(root: &Path, id: &str) -> Result<Option<Journal>, SdkError> {
    let path = directory(root, id)?.join("recovery.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    if path.metadata()?.len() > MAX_STORED_AUTHORITY_BYTES as u64 {
        return Err(invalid());
    }
    let value: Journal =
        ramflux_protocol::custody::decode(&fs::read(path)?, MAX_STORED_AUTHORITY_BYTES)?;
    if value.schema != "ramflux.local.recovery_intent.v1"
        || value.intent.local_account_id != id
        || value.intent.pending_branch
        || value.intent.state != CreationState::NetworkingPending
    {
        return Err(invalid());
    }
    Ok(Some(value))
}
pub(super) fn selected_authority(
    root: &Path,
    id: &str,
    current: StoredAuthority,
) -> Result<StoredAuthority, SdkError> {
    let Some(journal) = journal(root, id)? else {
        return Ok(current);
    };
    if snapshot(&current)? == journal.before_hash {
        return Ok(journal.intent);
    }
    let mut expected = journal.intent;
    expected.state = current.state;
    if snapshot(&expected)? != snapshot(&current)? {
        return Err(invalid());
    }
    Ok(current)
}
fn replace_public(path: &Path, value: &impl Serialize) -> Result<(), SdkError> {
    let temporary = path.with_extension(format!(
        "pending-{}",
        ramflux_protocol::encode_base64url(*crate::custody::random()?)
    ));
    let bytes = ramflux_protocol::canonical_json_bytes(value)?;
    if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
        return Err(invalid());
    }
    write_public(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    fs::File::open(path.parent().ok_or_else(invalid)?)?.sync_all()?;
    Ok(())
}
fn lock(root: &Path, id: &str) -> Result<fs::File, SdkError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory(root, id)?.join(".authority.lock"))?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

/// Public pending metadata contains no phrase, master, private branch or data-unlock secret.
pub struct RecoveryCeremony {
    root: PathBuf,
    account_id: String,
    anchor: String,
    before_hash: String,
    ceremony_id: String,
    deadline: Instant,
    commit_gate: Option<std::sync::Arc<crate::custody::CommitGate>>,
}
impl std::fmt::Debug for RecoveryCeremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCeremony(<redacted>)")
    }
}
impl RecoveryCeremony {
    /// Start only from an explicit local request after refreshing available trusted checkpoints.
    /// # Errors
    /// Rejects missing identity, unsupported kind and an unresolved earlier recovery intent.
    pub fn begin(root: &Path, id: &str, now: u64) -> Result<Self, SdkError> {
        if journal(root, id)?.is_some() {
            return Err(SdkError::NetworkingPending);
        }
        let account = load_data_account(root, id, now)?;
        if account.record().body.principal_kind != ramflux_protocol::PrincipalKind::Human {
            return Err(invalid());
        }
        Ok(Self {
            root: root.into(),
            account_id: id.into(),
            anchor: account.record().body.account_anchor.clone(),
            before_hash: snapshot(&account.stored)?,
            ceremony_id: format!(
                "recovery-{}",
                ramflux_protocol::encode_base64url(*crate::custody::random()?)
            ),
            deadline: Instant::now() + Duration::from_secs(300),
            commit_gate: None,
        })
    }
    #[must_use]
    pub fn account_anchor(&self) -> &str {
        &self.anchor
    }
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    #[must_use]
    pub fn ceremony_id(&self) -> &str {
        &self.ceremony_id
    }
    #[must_use]
    pub fn expires_in_ms(&self) -> u64 {
        u64::try_from(self.deadline.saturating_duration_since(Instant::now()).as_millis())
            .unwrap_or(0)
    }
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn guard_commit(&mut self, gate: std::sync::Arc<crate::custody::CommitGate>) {
        self.commit_gate = Some(gate);
    }
    pub(crate) fn verify_phrase(
        &self,
        phrase: &Zeroizing<String>,
        confirmed_anchor: &str,
        now: u64,
    ) -> Result<(), SdkError> {
        if Instant::now() >= self.deadline {
            return Err(SdkError::CustodyExpired);
        }
        let current = load_data_account(&self.root, &self.account_id, now)?;
        let words =
            RecoveryPhrase::parse(phrase).map_err(|_| SdkError::CustodyConfirmationFailed)?;
        let master = MasterKey::from_phrase(&words)?;
        if confirmed_anchor != self.anchor
            || snapshot(&current.stored)? != self.before_hash
            || master.public_key()
                != current.record().body.master_certificate.body.master_public_key
        {
            return Err(SdkError::CustodyConfirmationFailed);
        }
        Ok(())
    }

    /// Certify a new primary only after the user confirms the displayed immutable anchor.
    /// The master is erased before vault or journal writes. This does not grant networking.
    /// # Errors
    /// Refuses wrong phrases without persistent changes, stale intent, expiry and vault failure.
    pub fn confirm(
        self,
        phrase: &Zeroizing<String>,
        confirmed_anchor: &str,
        vault: &dyn PrimaryVault,
        now: u64,
    ) -> Result<BornAccount, SdkError> {
        if Instant::now() >= self.deadline {
            return Err(SdkError::CustodyExpired);
        }
        if confirmed_anchor != self.anchor {
            return Err(SdkError::CustodyConfirmationFailed);
        }
        let phrase =
            RecoveryPhrase::parse(phrase).map_err(|_| SdkError::CustodyConfirmationFailed)?;
        let master = MasterKey::from_phrase(&phrase)?;
        drop(phrase);
        let observed = load_data_account(&self.root, &self.account_id, now)?;
        if master.public_key() != observed.record().body.master_certificate.body.master_public_key {
            return Err(SdkError::CustodyConfirmationFailed);
        }
        let _lock = lock(&self.root, &self.account_id)?;
        let current = load_data_account(&self.root, &self.account_id, now)?;
        if snapshot(&current.stored)? != self.before_hash
            || journal(&self.root, &self.account_id)?.is_some()
        {
            return Err(invalid());
        }
        if master.public_key() != current.record().body.master_certificate.body.master_public_key {
            return Err(SdkError::CustodyConfirmationFailed);
        }
        vault.preflight()?;
        let primary = SelfSigningKey::generate()?;
        let (device, branch, agreement, seeds) = replacement_branch(&current, vault)?;
        let record = recover_primary(
            &master,
            &primary,
            &branch,
            &agreement,
            current.verified(),
            RecoveryInput {
                highest_observed_range: current
                    .stored
                    .pins
                    .maximum_observed_range(&self.anchor)
                    .ok_or_else(invalid)?,
                issued_at: now,
                master_cert_id: ramflux_protocol::encode_base64url(*crate::custody::random()?),
                branch_cert_id: ramflux_protocol::encode_base64url(*crate::custody::random()?),
            },
        )?;
        drop(master);
        persist_intent(
            Replacement {
                ceremony: &self,
                current,
                record,
                primary: &primary,
                device: &device,
                seeds: &seeds,
                now,
            },
            vault,
        )
    }
}
type ReplacementBranch =
    (String, ramflux_crypto::DeviceBranch, ramflux_crypto::X25519KeyPair, Zeroizing<[u8; 64]>);
fn replacement_branch(
    current: &BornAccount,
    vault: &dyn PrimaryVault,
) -> Result<ReplacementBranch, SdkError> {
    let device = if current.branch_pending() {
        current.local_device_id()?.to_owned()
    } else {
        format!("device-{}", ramflux_protocol::encode_base64url(*crate::custody::random()?))
    };
    let mut seeds = Zeroizing::new([0; 64]);
    if current.branch_pending() {
        let credentials = vault.load_branch(
            &current.stored.branch_vault_ref,
            &current.record().body.principal_id,
            &DeviceRef {
                account_anchor: current.record().body.account_anchor.clone(),
                device_id: device.clone(),
                device_epoch: 1,
            },
        )?;
        seeds[..32].copy_from_slice(&credentials.signing.signing_key.to_bytes());
        seeds[32..].copy_from_slice(&credentials.agreement.secret.to_bytes());
    } else {
        seeds[..32].copy_from_slice(&*crate::custody::random()?);
        seeds[32..].copy_from_slice(&*crate::custody::random()?);
    }
    let signing = Zeroizing::new(seeds[..32].try_into().map_err(|_| invalid())?);
    let agreement = Zeroizing::new(seeds[32..].try_into().map_err(|_| invalid())?);
    Ok((
        device.clone(),
        ramflux_crypto::create_device_branch(
            &current.record().body.principal_id,
            &device,
            1,
            *signing,
        ),
        ramflux_crypto::X25519KeyPair::from_seed(*agreement),
        seeds,
    ))
}

struct Replacement<'a> {
    ceremony: &'a RecoveryCeremony,
    current: BornAccount,
    record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    primary: &'a SelfSigningKey,
    device: &'a str,
    seeds: &'a Zeroizing<[u8; 64]>,
    now: u64,
}
fn persist_intent(
    value: Replacement<'_>,
    vault: &dyn PrimaryVault,
) -> Result<BornAccount, SdkError> {
    let Replacement { ceremony, mut current, record, primary, device, seeds, now } = value;
    let new_primary = format!("primary:{}", ceremony.ceremony_id);
    let new_branch = if current.branch_pending() {
        current.stored.branch_vault_ref.clone()
    } else {
        format!("branch:{}", ceremony.ceremony_id)
    };
    let verified = ramflux_crypto::custody::verify_record(
        &record,
        now,
        current.stored.compacted_ids.as_deref(),
        None,
    )?;
    current.stored.pins.observe(&verified)?;
    let old_primary = current.stored.primary_vault_ref.clone();
    let old_branch = current.stored.branch_vault_ref.clone();
    let branch_new = new_branch != old_branch;
    vault.store_new(&new_primary, primary)?;
    let mut branch_written = false;
    let mut journal_written = false;
    let result = (|| {
        if branch_new {
            vault.store_branch(&new_branch, seeds)?;
            branch_written = true;
        }
        current.stored.primary_vault_ref.clone_from(&new_primary);
        current.stored.branch_vault_ref.clone_from(&new_branch);
        current.stored.local_device_id = device.into();
        current.stored.record = record;
        current.stored.pending_branch = false;
        current.stored.state = CreationState::NetworkingPending;
        let journal = Journal {
            schema: "ramflux.local.recovery_intent.v1".into(),
            before_hash: ceremony.before_hash.clone(),
            intent: current.stored.clone(),
            previous_primary_ref: old_primary,
            previous_branch_ref: old_branch,
        };
        let dir = directory(&ceremony.root, &ceremony.account_id)?;
        if let Some(gate) = &ceremony.commit_gate {
            gate.commit()?;
        }
        replace_public(&dir.join("recovery.json"), &journal)?;
        journal_written = true;
        replace_public(&dir.join("authority.json"), &current.stored)?;
        Ok(BornAccount { stored: current.stored, verified, authority_blocked: false })
    })();
    if result.is_err() && !journal_written {
        let branch_cleanup = if branch_written { vault.delete(&new_branch) } else { Ok(()) };
        let primary_cleanup = vault.delete(&new_primary);
        branch_cleanup?;
        primary_cleanup?;
    }
    result
}

impl BornAccount {
    pub(crate) fn recovery_publication_pending(&self, root: &Path) -> Result<bool, SdkError> {
        Ok(journal(root, self.local_account_id())?.is_some_and(|intent| {
            self.stored.state == CreationState::NetworkingPending
                && intent.intent.record == *self.record()
        }))
    }
}
pub(crate) fn finish_recovery(
    root: &Path,
    id: &str,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(), SdkError> {
    let _lock = lock(root, id)?;
    let Some(intent) = journal(root, id)? else {
        return Ok(());
    };
    let current = load_data_account(root, id, now)?;
    if current.state() != CreationState::Live || current.record() != &intent.intent.record {
        return Err(SdkError::NetworkingPending);
    }
    if !intent.previous_primary_ref.is_empty()
        && intent.previous_primary_ref != current.stored.primary_vault_ref
    {
        vault.delete(&intent.previous_primary_ref)?;
    }
    if intent.previous_branch_ref != current.stored.branch_vault_ref {
        vault.delete(&intent.previous_branch_ref)?;
    }
    fs::remove_file(directory(root, id)?.join("recovery.json"))?;
    fs::File::open(directory(root, id)?)?.sync_all()?;
    Ok(())
}

pub(crate) fn pending_restore(
    root: &Path,
    id: &str,
    authority: &CustodyAuthority,
    vault: &dyn PrimaryVault,
    passphrase: &[u8],
    now: u64,
) -> Result<BornAccount, SdkError> {
    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
    if verified.envelope().body.principal_kind != ramflux_protocol::PrincipalKind::Human {
        return Err(invalid());
    }
    vault.preflight()?;
    let branch_ref = format!(
        "branch:restore:{}",
        ramflux_protocol::encode_base64url(*crate::custody::random()?)
    );
    let device =
        format!("device-{}", ramflux_protocol::encode_base64url(*crate::custody::random()?));
    let mut seeds = Zeroizing::new([0; 64]);
    seeds[..32].copy_from_slice(&*crate::custody::random()?);
    seeds[32..].copy_from_slice(&*crate::custody::random()?);
    let index = ramflux_storage::AccountIndex::open(root)?;
    index.create_account(id, &authority.publication.record.body.account_anchor)?;
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        private_directory(&parent)?;
        fs::File::open(root)?.sync_all()?;
    }
    let dir = directory(root, id)?;
    private_directory(&dir)?;
    fs::File::open(&parent)?.sync_all()?;
    let mut pins = ramflux_crypto::custody::AuthorityPins::default();
    pins.observe(&verified)?;
    let stored = StoredAuthority {
        schema: "ramflux.local.custody_account.v1".into(),
        local_account_id: id.into(),
        local_device_id: device,
        state: CreationState::NetworkingPending,
        pending_branch: true,
        custody_v3_observed: true,
        primary_vault_ref: String::new(),
        branch_vault_ref: branch_ref.clone(),
        vault_class: "software_os_credential_non_synchronizing".into(),
        record: authority.publication.record.clone(),
        compacted_ids: authority.publication.compacted_ids.clone(),
        custodian_publication: authority.custodian_publication.clone().map(Box::new),
        pins,
        custodian_account_id: None,
        agent_provisioning_vault_ref: None,
    };
    vault.store_branch(&branch_ref, &seeds)?;
    let result = (|| {
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(root)?;
        client.seal_new_account_data(id, &stored.record.body.account_anchor, passphrase)?;
        write_public(
            &dir.join("authority.json"),
            &ramflux_protocol::canonical_json_bytes(&stored)?,
        )?;
        fs::File::open(&dir)?.sync_all()?;
        Ok(BornAccount { stored, verified, authority_blocked: false })
    })();
    if result.is_err() {
        vault.delete(&branch_ref)?;
    }
    result
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
