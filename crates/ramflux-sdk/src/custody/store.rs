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
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
mod publication;
use publication::write_public;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationState {
    NetworkingPending,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredAuthority {
    schema: String,
    local_account_id: String,
    state: CreationState,
    custody_v3_observed: bool,
    pub(super) primary_vault_ref: String,
    pub(super) branch_vault_ref: String,
    vault_class: String,
    record: Envelope<DeviceSet>,
    pins: AuthorityPins,
    custodian_account_id: Option<String>,
}
/// An authenticated local account, with no legacy root signer or active session.
#[derive(Clone, Debug)]
pub struct BornAccount {
    stored: StoredAuthority,
    verified: VerifiedRecord,
}
impl BornAccount {
    #[must_use]
    pub const fn state(&self) -> CreationState {
        self.stored.state
    }
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        &self.stored.local_account_id
    }
    #[must_use]
    pub fn record(&self) -> &Envelope<DeviceSet> {
        &self.stored.record
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
    /// Networking is unavailable until the born-v3 registration profile is implemented.
    pub fn require_networking(&self) -> Result<(), SdkError> {
        Err(SdkError::NetworkingPending)
    }
    #[must_use]
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"local_account_id":self.local_account_id(),"principal_id":self.stored.record.body.principal_id,
            "account_anchor":self.stored.record.body.account_anchor,"kind":self.stored.record.body.principal_kind,
            "state":self.state(),"custody_v3_observed":true,"vault_class":self.stored.vault_class})
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
pub(crate) fn reconcile_incomplete_markers(root: &Path) -> Result<(), SdkError> {
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        return Ok(());
    }
    let index = ramflux_storage::AccountIndex::open(root)?;
    for entry in fs::read_dir(&parent)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(id) =
            entry.file_name().to_str().map(str::to_owned).filter(|id| valid_id(id).is_ok())
        else {
            tracing::warn!(
                reason_code = "custody_marker_invalid_name",
                "quarantined custody marker with invalid account name"
            );
            continue;
        };
        if let Err(error) = reconcile_marker(&index, &entry.path(), &id) {
            tracing::warn!(local_account_id=%id, reason_code="custody_marker_inconsistent", %error,
                "quarantined inconsistent custody account; other accounts remain available");
        }
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn reconcile_marker(
    index: &ramflux_storage::AccountIndex,
    path: &Path,
    id: &str,
) -> Result<(), SdkError> {
    match index.account(id) {
        Ok(_) => Ok(()),
        Err(ramflux_storage::StorageError::AccountNotFound(_))
            if !path.join("authority.json").try_exists()? =>
        {
            fs::remove_dir_all(path)?;
            tracing::warn!(local_account_id=%id, reason_code="custody_orphan_marker_removed",
                "removed custody marker without an account-index reservation");
            Ok(())
        }
        Err(ramflux_storage::StorageError::AccountNotFound(_)) => Err(invalid()),
        Err(error) => Err(error.into()),
    }
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
            let Some(id) =
                entry.file_name().to_str().map(str::to_owned).filter(|id| valid_id(id).is_ok())
            else {
                continue;
            };
            accounts.push(account_summary(root, &id, now).unwrap_or_else(|_| {
                serde_json::json!({
                    "local_account_id":id, "state":CreationState::NetworkingPending,
                    "custody_v3_observed":true, "setup_incomplete":true,
                    "setup_error":"CustodySetupInvalid"
                })
            }));
        }
    }
    accounts.sort_by(|a, b| a["local_account_id"].as_str().cmp(&b["local_account_id"].as_str()));
    Ok(accounts)
}
pub(crate) fn account_summary(
    root: &Path,
    id: &str,
    now: u64,
) -> Result<serde_json::Value, SdkError> {
    if directory(root, id)?.join("authority.json").try_exists()? {
        return load_account(root, id, now).map(|account| account.summary()).map_err(|_| invalid());
    }
    Ok(serde_json::json!({"local_account_id":id,"state":CreationState::NetworkingPending,
        "custody_v3_observed":true,"setup_incomplete":true}))
}
/// Read public authority without unlocking the primary vault. Malformed or incomplete
/// custody state fails closed; it is never reinterpreted as a legacy manifest.
/// # Errors
/// Rejects missing/corrupt records, bad signatures, changed modes or missing custodian evidence.
pub fn load_account(root: &Path, id: &str, now: u64) -> Result<BornAccount, SdkError> {
    let path = directory(root, id)?.join("authority.json");
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(600_001).read_to_end(&mut bytes)?;
    if bytes.len() > 600_000 {
        return Err(invalid());
    }
    let stored: StoredAuthority = ramflux_protocol::custody::decode(&bytes, 600_000)?;
    if stored.schema != "ramflux.local.custody_account.v1"
        || stored.local_account_id != id
        || !stored.custody_v3_observed
    {
        return Err(invalid());
    }
    require_account_binding(root, id, &stored.record.body.account_anchor)?;
    let human =
        stored.custodian_account_id.as_ref().map(|id| load_human(root, id, now)).transpose()?;
    let verified = verify_record(&stored.record, now, None, human.as_ref())?;
    stored.pins.require_current(&verified)?;
    Ok(BornAccount { stored, verified })
}
fn load_human(root: &Path, id: &str, now: u64) -> Result<VerifiedRecord, SdkError> {
    // Decode directly and reject nonhuman evidence before following any custodian reference.
    let mut bytes = Vec::new();
    fs::File::open(directory(root, id)?.join("authority.json"))?
        .take(600_001)
        .read_to_end(&mut bytes)?;
    let stored: StoredAuthority = ramflux_protocol::custody::decode(&bytes, 600_000)?;
    if stored.local_account_id != id
        || stored.custodian_account_id.is_some()
        || !stored.custody_v3_observed
        || stored.schema != "ramflux.local.custody_account.v1"
    {
        return Err(invalid());
    }
    require_account_binding(root, id, &stored.record.body.account_anchor)?;
    let verified = verify_record(&stored.record, now, None, None)?;
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
fn legacy_manifest_exists(root: &Path, id: &str) -> Result<bool, SdkError> {
    Ok(root.join("local_bus_accounts").join(format!("{id}.json")).try_exists()?)
}
fn remove_marker(parent: &Path, dir: &Path) {
    let _ = fs::remove_dir_all(dir);
    let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
}
pub(super) struct GenesisMaterial<'a> {
    pub record: Envelope<DeviceSet>,
    pub primary: &'a ramflux_crypto::custody::SelfSigningKey,
    pub branch: &'a Zeroizing<[u8; 64]>,
    pub now: u64,
}
pub(super) fn persist(
    root: &Path,
    input: &super::CreateInput,
    material: GenesisMaterial<'_>,
    vault: &dyn PrimaryVault,
) -> Result<BornAccount, SdkError> {
    let GenesisMaterial { record, primary: key, branch, now } = material;
    let human =
        input.custodian_account_id.as_ref().map(|id| load_human(root, id, now)).transpose()?;
    let verified = verify_record(&record, now, None, human.as_ref())?;
    let mut pins = AuthorityPins::default();
    pins.observe(&verified)?;
    pins.discard_retained_records();
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        private_directory(&parent)?;
        fs::File::open(root)?.sync_all()?;
    }
    let dir = directory(root, &input.local_account_id)?;
    private_directory(&dir)?; // Exclusive reservation is itself a fail-closed mode latch.
    fs::File::open(&parent)?.sync_all()?;
    // The directory is the custody-specific crash marker. Create it before the transactional
    // index reservation so no index-only state can be confused with an in-progress legacy birth.
    let index = ramflux_storage::AccountIndex::open(root)?;
    if legacy_manifest_exists(root, &input.local_account_id)? {
        remove_marker(&parent, &dir);
        return Err(SdkError::CustodyAccountConflict);
    }
    if let Err(error) = index.reserve_account(&input.local_account_id, &record.body.account_anchor)
    {
        remove_marker(&parent, &dir);
        return match error {
            ramflux_storage::StorageError::AccountAlreadyExists(_) => {
                Err(SdkError::CustodyAccountConflict)
            }
            error => Err(error.into()),
        };
    }
    #[cfg(test)]
    race_hooks::run(race_hooks::Stage::AfterReservation, root, &input.local_account_id)?;
    require_owned_reservation(
        root,
        &index,
        &input.local_account_id,
        &record.body.account_anchor,
        &dir,
    )?;
    #[cfg(test)]
    race_hooks::run(race_hooks::Stage::AfterManifestCheck, root, &input.local_account_id)?;
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
    // On failure retain the reservation; no caller may retry through legacy account.create.
    vault.store_new(&reference, key)?;
    vault.store_branch(&branch_reference, branch)?;
    let account_anchor = record.body.account_anchor.clone();
    let stored = StoredAuthority {
        schema: "ramflux.local.custody_account.v1".into(),
        local_account_id: input.local_account_id.clone(),
        state: CreationState::NetworkingPending,
        custody_v3_observed: true,
        primary_vault_ref: reference,
        branch_vault_ref: branch_reference,
        vault_class: "software_os_credential_non_synchronizing".into(),
        record,
        pins,
        custodian_account_id: input.custodian_account_id.clone(),
    };
    #[cfg(test)]
    race_hooks::run(race_hooks::Stage::BeforeAuthorityPublish, root, &input.local_account_id)?;
    require_owned_reservation(root, &index, &input.local_account_id, &account_anchor, &dir)?;
    write_public(&dir.join("authority.json"), &ramflux_protocol::canonical_json_bytes(&stored)?)?;
    Ok(BornAccount { stored, verified })
}

fn require_owned_reservation(
    root: &Path,
    index: &ramflux_storage::AccountIndex,
    id: &str,
    anchor: &str,
    dir: &Path,
) -> Result<(), SdkError> {
    if legacy_manifest_exists(root, id)?
        || !index.account(id).is_ok_and(|row| row.principal_commitment == anchor)
    {
        let _ = index.release_unwrapped_reservation(id, anchor);
        remove_marker(&root.join("custody_accounts"), dir);
        return Err(SdkError::CustodyAccountConflict);
    }
    Ok(())
}
#[cfg(test)]
mod race_hooks;
#[cfg(test)]
mod race_tests;
