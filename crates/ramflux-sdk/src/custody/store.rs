// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public local authority and irreversible born-v3 latch; never contains a master or phrase.
use super::{PrimaryVault, invalid, valid_id};
use crate::SdkError;
use ramflux_crypto::custody::{AuthorityPins, VerifiedRecord, verify_record};
use ramflux_protocol::custody::{DeviceSet, Envelope};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};
mod publication;
mod recovery;
pub(crate) use publication::accept_publication;
pub use recovery::RecoveryCeremony;
pub(crate) use recovery::{finish_recovery, pending_restore};
const MAX_STORED_AUTHORITY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationState {
    NetworkingPending,
    Live,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredAuthority {
    schema: String,
    local_account_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    local_device_id: String,
    state: CreationState,
    #[serde(default)]
    pending_branch: bool,
    custody_v3_observed: bool,
    pub(super) primary_vault_ref: String,
    pub(super) branch_vault_ref: String,
    vault_class: String,
    record: Envelope<DeviceSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compacted_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custodian_publication: Option<Box<ramflux_protocol::custody::Publication>>,
    pins: AuthorityPins,
    custodian_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_provisioning_vault_ref: Option<String>,
}

/// One-use headless participant material. It deliberately contains no phrase or authority key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvisioningBundle {
    pub account_id: String,
    pub data_passphrase: String,
}
impl std::fmt::Debug for AgentProvisioningBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentProvisioningBundle(<redacted>)")
    }
}
impl Drop for AgentProvisioningBundle {
    fn drop(&mut self) {
        self.data_passphrase.zeroize();
    }
}
/// An authenticated local account, with no legacy root signer or active session.
#[derive(Clone, Debug)]
pub struct BornAccount {
    stored: StoredAuthority,
    verified: VerifiedRecord,
    authority_blocked: bool,
}
impl BornAccount {
    pub(crate) fn sign_contact_card(
        &self,
        vault: &dyn PrimaryVault,
        body: ramflux_protocol::custody::ContactCardV3,
        now: u64,
    ) -> Result<Envelope<ramflux_protocol::custody::ContactCardV3>, SdkError> {
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        self.stored.pins.require_current(&self.verified)?;
        Ok(vault.load_primary(&self.stored.primary_vault_ref)?.sign_contact_card_v3(
            &self.verified,
            body,
            now,
        )?)
    }
    #[must_use]
    pub(crate) const fn branch_pending(&self) -> bool {
        self.stored.pending_branch
    }
    #[must_use]
    pub const fn state(&self) -> CreationState {
        if self.authority_blocked || self.stored.pending_branch {
            CreationState::NetworkingPending
        } else {
            self.stored.state
        }
    }
    pub(crate) const fn authority_blocked(&self) -> bool {
        self.authority_blocked
    }
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        &self.stored.local_account_id
    }
    pub(crate) fn local_device_id(&self) -> Result<&str, SdkError> {
        let id = if self.stored.local_device_id.is_empty() {
            match self.record().body.devices.as_slice() {
                [only] => only.device_id.as_str(),
                _ => return Err(invalid()),
            }
        } else {
            &self.stored.local_device_id
        };
        ramflux_protocol::validate_device_name(id)?;
        Ok(id)
    }
    #[must_use]
    pub fn record(&self) -> &Envelope<DeviceSet> {
        &self.stored.record
    }
    #[must_use]
    pub(crate) fn publication(&self) -> ramflux_protocol::custody::Publication {
        ramflux_protocol::custody::Publication {
            record: self.stored.record.clone(),
            compacted_ids: self.stored.compacted_ids.clone(),
        }
    }
    #[must_use]
    pub fn verified(&self) -> &VerifiedRecord {
        &self.verified
    }
    /// V3 is latched at creation; numeric legacy epochs cannot outrank it.
    /// # Errors
    /// Always refuses v1/v2 and unsupported future modes.
    pub fn require_record_version(&self, version: u32) -> Result<(), SdkError> {
        if version != 3 {
            return Err(SdkError::CustodyModeDowngrade);
        }
        Ok(())
    }
    /// # Errors
    /// Rejects accounts that have not completed native registration. Live is durable
    /// registration status; only a fresh `CustodyConnection` grants an active session.
    pub fn require_networking(&self) -> Result<(), SdkError> {
        if self.state() == CreationState::Live { Ok(()) } else { Err(SdkError::NetworkingPending) }
    }
    #[must_use]
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"local_account_id":self.local_account_id(),"principal_id":self.stored.record.body.principal_id,
            "account_anchor":self.stored.record.body.account_anchor,"kind":self.stored.record.body.principal_kind,"display_name":self.stored.record.body.profile.display_name,
            "state":self.state(),"authority_blocked":self.authority_blocked,"custody_v3_observed":true,"vault_class":self.stored.vault_class})
    }
}
fn directory(root: &Path, id: &str) -> Result<PathBuf, SdkError> {
    valid_id(id)?;
    Ok(root.join("custody_accounts").join(id))
}
pub(crate) fn account_exists(root: &Path, id: &str) -> Result<bool, SdkError> {
    // This query also guards legacy paths: do not impose new identifier rules on them.
    if valid_id(id).is_err() {
        return Ok(false);
    }
    Ok(directory(root, id)?.try_exists()?)
}
pub(crate) fn list_accounts(root: &Path, now: u64) -> Result<Vec<serde_json::Value>, SdkError> {
    let dir = root.join("custody_accounts");
    if !dir.try_exists()? {
        return Ok(Vec::new());
    }
    let mut accounts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let id = entry.file_name().into_string().map_err(|_| invalid())?;
            let summary=load_data_account(root,&id,now).map_or_else(
                |_|serde_json::json!({"local_account_id":id,"state":CreationState::NetworkingPending,"custody_v3_observed":true,"setup_incomplete":true}),
                |account|account.summary());
            accounts.push(summary);
        }
    }
    accounts.sort_by(|a, b| a["local_account_id"].as_str().cmp(&b["local_account_id"].as_str()));
    Ok(accounts)
}
/// Read public authority without unlocking the primary vault. Malformed or incomplete
/// custody state fails closed; it is never reinterpreted as a legacy manifest.
/// # Errors
/// Rejects missing/corrupt records, bad signatures, changed modes or missing custodian evidence.
pub fn load_account(root: &Path, id: &str, now: u64) -> Result<BornAccount, SdkError> {
    read_account(root, id, now, true)
}
/// A signed public record can name existing data while its authority is fenced. This
/// loader grants no branch permission and is used only by the data unlock/list paths.
pub(crate) fn load_data_account(root: &Path, id: &str, now: u64) -> Result<BornAccount, SdkError> {
    read_account(root, id, now, false)
}
fn read_account(
    root: &Path,
    id: &str,
    now: u64,
    require_current: bool,
) -> Result<BornAccount, SdkError> {
    let path = directory(root, id)?.join("authority.json");
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_STORED_AUTHORITY_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
        return Err(invalid());
    }
    let stored: StoredAuthority =
        ramflux_protocol::custody::decode(&bytes, MAX_STORED_AUTHORITY_BYTES)?;
    let stored = recovery::selected_authority(root, id, stored)?;
    if stored.schema != "ramflux.local.custody_account.v1"
        || stored.local_account_id != id
        || !stored.custody_v3_observed
    {
        return Err(invalid());
    }
    require_account_binding(root, id, &stored.record.body.account_anchor)?;
    let human = if let Some(publication) = &stored.custodian_publication {
        Some(verify_record(&publication.record, now, publication.compacted_ids.as_deref(), None)?)
    } else {
        stored.custodian_account_id.as_ref().map(|id| load_human(root, id, now)).transpose()?
    };
    let verified =
        verify_record(&stored.record, now, stored.compacted_ids.as_deref(), human.as_ref())?;
    let authority_blocked = stored.pins.require_current(&verified).is_err();
    if require_current {
        stored.pins.require_current(&verified)?;
    }
    Ok(BornAccount { stored, verified, authority_blocked })
}
fn load_human(root: &Path, id: &str, now: u64) -> Result<VerifiedRecord, SdkError> {
    // Decode directly and reject nonhuman evidence before following any custodian reference.
    let mut bytes = Vec::new();
    fs::File::open(directory(root, id)?.join("authority.json"))?
        .take((MAX_STORED_AUTHORITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let stored: StoredAuthority =
        ramflux_protocol::custody::decode(&bytes, MAX_STORED_AUTHORITY_BYTES)?;
    if stored.local_account_id != id
        || stored.custodian_account_id.is_some()
        || !stored.custody_v3_observed
        || stored.schema != "ramflux.local.custody_account.v1"
    {
        return Err(invalid());
    }
    require_account_binding(root, id, &stored.record.body.account_anchor)?;
    let verified = verify_record(&stored.record, now, stored.compacted_ids.as_deref(), None)?;
    if stored.record.body.principal_kind != ramflux_protocol::PrincipalKind::Human {
        return Err(invalid());
    }
    stored.pins.require_current(&verified)?;
    Ok(verified)
}
fn require_account_binding(root: &Path, id: &str, anchor: &str) -> Result<(), SdkError> {
    if !root.join(ramflux_storage::ACCOUNT_INDEX_FILE).try_exists()? {
        return Err(invalid());
    }
    let account = ramflux_storage::AccountIndex::open(root)?.account(id)?;
    if account.principal_commitment != anchor {
        return Err(invalid());
    }
    Ok(())
}
fn private_directory(path: &Path) -> Result<(), SdkError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    Ok(())
}
fn write_public(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
pub(super) struct GenesisMaterial<'a> {
    pub record: Envelope<DeviceSet>,
    pub primary: &'a ramflux_crypto::custody::SelfSigningKey,
    pub branch: &'a Zeroizing<[u8; 64]>,
    pub now: u64,
    pub data_secret: Option<&'a [u8]>,
    pub commit_gate: Option<&'a super::CommitGate>,
}
pub(super) fn persist(
    root: &Path,
    input: &super::CreateInput,
    material: GenesisMaterial<'_>,
    vault: &dyn PrimaryVault,
) -> Result<BornAccount, SdkError> {
    let GenesisMaterial { record, primary: key, branch, now, data_secret, commit_gate } = material;
    let human =
        input.custodian_account_id.as_ref().map(|id| load_human(root, id, now)).transpose()?;
    let verified = verify_record(&record, now, None, human.as_ref())?;
    let mut pins = AuthorityPins::default();
    pins.observe(&verified)?;
    // The transactional index arbitrates concurrent native creation.
    // A reservation left by a later failure remains blocked for reconciliation.
    ramflux_storage::AccountIndex::open(root)?
        .create_account(&input.local_account_id, &record.body.account_anchor)?;
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        private_directory(&parent)?;
        fs::File::open(root)?.sync_all()?;
    }
    let dir = directory(root, &input.local_account_id)?;
    private_directory(&dir)?; // Exclusive reservation is itself a fail-closed mode latch.
    fs::File::open(&parent)?.sync_all()?;
    let reference = ramflux_protocol::hash_base64url(
        "ramflux.local.custody_vault_reference.v1",
        &[
            &[0_u8][..],
            &ramflux_protocol::canonical_json_bytes(&(
                root.canonicalize()?.to_string_lossy(),
                &input.local_account_id,
                &record.body.account_anchor,
            ))?,
        ]
        .concat(),
    );
    let branch_reference = format!("branch:{reference}");
    let agent_provisioning_reference = (input.principal_kind
        == ramflux_protocol::PrincipalKind::HeadlessAi)
        .then(|| format!("agent-provisioning:{reference}"));
    // On failure retain the reservation; no caller may retry through legacy account.create.
    vault.store_new(&reference, key)?;
    let mut branch_written = false;
    let mut provisioning_written = false;
    let result = (|| {
        vault.store_branch(&branch_reference, branch)?;
        branch_written = true;
        if let Some(agent_reference) = &agent_provisioning_reference {
            let secret = data_secret.ok_or_else(invalid)?;
            vault.store_provisioning_secret(agent_reference, secret)?;
            provisioning_written = true;
        }
        if let Some(secret) = data_secret {
            let mut data = crate::RamfluxClient::new();
            data.open_account_index(root)?;
            data.seal_new_account_data(
                &input.local_account_id,
                &record.body.account_anchor,
                secret,
            )?;
        }
        let stored = StoredAuthority {
            schema: "ramflux.local.custody_account.v1".into(),
            local_account_id: input.local_account_id.clone(),
            local_device_id: input.device_id.clone(),
            state: CreationState::NetworkingPending,
            pending_branch: false,
            custody_v3_observed: true,
            primary_vault_ref: reference.clone(),
            branch_vault_ref: branch_reference.clone(),
            vault_class: "software_os_credential_non_synchronizing".into(),
            record,
            compacted_ids: None,
            custodian_publication: None,
            pins,
            custodian_account_id: input.custodian_account_id.clone(),
            agent_provisioning_vault_ref: agent_provisioning_reference.clone(),
        };
        if let Some(gate) = commit_gate {
            gate.commit()?;
        }
        write_public(
            &dir.join("authority.json"),
            &ramflux_protocol::canonical_json_bytes(&stored)?,
        )?;
        fs::File::open(&dir)?.sync_all()?;
        Ok(BornAccount { stored, verified, authority_blocked: false })
    })();
    if result.is_err() {
        // Attempt both deletions even if one provider operation fails. The reservation remains
        // latched, so a partial setup cannot fall back to another identity scheme.
        let branch_cleanup = if branch_written { vault.delete(&branch_reference) } else { Ok(()) };
        let provisioning_cleanup = if provisioning_written {
            vault.delete(agent_provisioning_reference.as_deref().ok_or_else(invalid)?)
        } else {
            Ok(())
        };
        let primary_cleanup = vault.delete(&reference);
        branch_cleanup?;
        provisioning_cleanup?;
        primary_cleanup?;
    }
    result
}

/// Export the one-use agent data credential for its live native human custodian.
/// The destination is created with owner-only permissions and is never overwritten.
/// # Errors
/// Rejects non-agent targets, the wrong custodian, non-live accounts, existing paths, and vault or
/// filesystem failures.
pub(crate) fn export_agent_credentials(
    root: &Path,
    owner_id: &str,
    account_id: &str,
    path: &Path,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(), SdkError> {
    let owner = load_account(root, owner_id, now)?;
    owner.require_networking()?;
    if owner.record().body.principal_kind != ramflux_protocol::PrincipalKind::Human {
        return Err(invalid());
    }
    let agent = load_account(root, account_id, now)?;
    agent.require_networking()?;
    if agent.record().body.principal_kind != ramflux_protocol::PrincipalKind::HeadlessAi
        || agent.stored.custodian_account_id.as_deref() != Some(owner_id)
    {
        return Err(invalid());
    }
    let reference = agent.stored.agent_provisioning_vault_ref.as_deref().ok_or_else(invalid)?;
    let secret = vault.load_provisioning_secret(reference)?;
    let passphrase = String::from_utf8(secret.to_vec()).map_err(|_| invalid())?;
    let bundle =
        AgentProvisioningBundle { account_id: account_id.to_owned(), data_passphrase: passphrase };
    let bytes = Zeroizing::new(ramflux_protocol::canonical_json_bytes(&bundle)?);
    let mut created = false;
    let result = (|| {
        let mut file =
            fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        created = true;
        file.write_all(&bytes)?;
        file.sync_all()?;
        vault.delete(reference)?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result
}

impl BornAccount {
    pub(crate) fn custodian_publication(
        &self,
        root: &Path,
        now: u64,
    ) -> Result<Option<ramflux_protocol::custody::Publication>, SdkError> {
        if let Some(publication) = &self.stored.custodian_publication {
            verify_record(&publication.record, now, publication.compacted_ids.as_deref(), None)?;
            return Ok(Some((**publication).clone()));
        }
        self.stored
            .custodian_account_id
            .as_ref()
            .map(|id| {
                let human = load_account(root, id, now)?;
                Ok(human.publication())
            })
            .transpose()
    }

    pub(crate) fn sign_contact_consent(
        &self,
        vault: &dyn PrimaryVault,
        current: &VerifiedRecord,
        body: ramflux_protocol::custody::ContactConsentV2,
        now: u64,
    ) -> Result<Envelope<ramflux_protocol::custody::ContactConsentV2>, SdkError> {
        if self.authority_blocked
            || current.envelope().body.account_anchor != self.record().body.account_anchor
        {
            return Err(invalid());
        }
        let primary = vault.load_primary(&self.stored.primary_vault_ref)?;
        if primary.public_key()
            != current.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(primary.sign_contact_consent(current, body, now)?)
    }

    pub(crate) fn credentials(
        &self,
        vault: &dyn PrimaryVault,
        device_id: &str,
        now: u64,
    ) -> Result<(ramflux_protocol::custody::DeviceRef, super::BranchCredentials), SdkError> {
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        if device_id != self.local_device_id()? {
            return Err(invalid());
        }
        self.stored.pins.require_current(&self.verified)?;
        let entry = self
            .record()
            .body
            .devices
            .iter()
            .find(|d| d.device_id == device_id)
            .ok_or_else(invalid)?;
        let reference = ramflux_protocol::custody::DeviceRef {
            account_anchor: self.record().body.account_anchor.clone(),
            device_id: device_id.into(),
            device_epoch: entry.device_epoch,
        };
        let cert = self.verified.authorize(&reference, "register", now)?;
        let credentials = vault.load_branch(
            &self.stored.branch_vault_ref,
            &self.record().body.principal_id,
            &reference,
        )?;
        if ramflux_protocol::encode_base64url(
            credentials.signing.signing_key.verifying_key().to_bytes(),
        ) != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(credentials.agreement.public)
                != cert.agreement_identity_public_key
        {
            return Err(invalid());
        }
        Ok((reference, credentials))
    }
    pub(super) fn mark_live(&mut self, root: &Path) -> Result<(), SdkError> {
        use std::os::unix::fs::OpenOptionsExt;
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        let dir = directory(root, self.local_account_id())?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(".authority.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        let mut current = load_account(root, self.local_account_id(), now)?;
        if current.record() != self.record() {
            return Err(invalid());
        }
        current.stored.state = CreationState::Live;
        let bytes = ramflux_protocol::canonical_json_bytes(&current.stored)?;
        if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
            return Err(invalid());
        }
        let temp = dir.join(format!(
            ".authority-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        write_public(&temp, &bytes)?;
        fs::rename(temp, dir.join("authority.json"))?;
        fs::File::open(&dir)?.sync_all()?;
        self.stored.state = CreationState::Live;
        Ok(())
    }
}
