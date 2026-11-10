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
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};
mod genesis;
mod networking;
pub(crate) mod pairing;
mod publication;
#[cfg(test)]
mod race_hooks;
mod recovery;
pub(crate) use publication::{accept_publication, pending_head_fence_blocks};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    networking_reason: Option<crate::AccountNetworkingReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    networking_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capacity_retry_at: Option<u64>,
    #[serde(default)]
    pending_branch: bool,
    custody_v3_observed: bool,
    #[serde(default)]
    pairing_adoption_required: bool,
    pub(super) primary_vault_ref: String,
    pub(super) branch_vault_ref: String,
    vault_class: String,
    record: Envelope<DeviceSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compacted_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custodian_publication: Option<Box<ramflux_protocol::custody::Publication>>,
    pins: AuthorityPins,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    message_layer_sequences: std::collections::BTreeMap<String, u64>,
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
        // The String's bytes are wiped over their whole allocation, not just their length.
        let mut bytes = std::mem::take(&mut self.data_passphrase).into_bytes();
        wipe_allocation(&mut bytes, "p07-export-passphrase");
    }
}
/// Wipes and (in tests) observes the complete owned allocation: spare capacity is initialized
/// without reallocating, the whole slice is zeroized, and only then is the length dropped.
fn wipe_allocation(buffer: &mut Vec<u8>, label: &'static str) {
    let capacity = buffer.capacity();
    buffer.resize(capacity, 0);
    buffer.as_mut_slice().zeroize();
    #[cfg(test)]
    super::observer::inspect_capacity(label, capacity, buffer);
    #[cfg(not(test))]
    let _ = label;
    buffer.clear();
}
/// Owned copy of the provisioning secret used for UTF-8 validation. It is wiped on every exit,
/// including the invalid-UTF-8 error: validation borrows from this guard (`str::from_utf8`), so no
/// unguarded `Vec`/`FromUtf8Error` buffer exists on any path.
struct ExportSource(Vec<u8>);
impl ExportSource {
    fn copy(secret: &[u8]) -> Self {
        Self(secret.to_vec())
    }
}
impl Drop for ExportSource {
    fn drop(&mut self) {
        wipe_allocation(&mut self.0, "p07-export-utf8");
    }
}
/// Canonical JSON bytes of an [`AgentProvisioningBundle`], written into a buffer that is sized
/// exactly up front (so nothing is ever reallocated and left behind) and wiped over its whole
/// allocation on every exit. The schema is closed: keys are in canonical order.
pub(super) struct BundleBytes(Vec<u8>);
impl BundleBytes {
    const ACCOUNT_KEY: &'static [u8] = br#"{"account_id":""#;
    const PASSPHRASE_KEY: &'static [u8] = br#"","data_passphrase":""#;
    const END: &'static [u8] = br#""}"#;
    pub(super) fn serialize(bundle: &AgentProvisioningBundle) -> Result<Self, SdkError> {
        Self::write(bundle, None)
    }
    /// Test seam: fail once `after` passphrase bytes have entered the buffer.
    #[cfg(test)]
    pub(super) fn serialize_failing(
        bundle: &AgentProvisioningBundle,
        after: usize,
    ) -> Result<Self, SdkError> {
        Self::write(bundle, Some(after))
    }
    /// Every error path drops `buffer`, which wipes the whole allocation. A capacity change
    /// (an escaped-length miscount that reallocated) fails closed instead of continuing.
    fn write(
        bundle: &AgentProvisioningBundle,
        fail_after: Option<usize>,
    ) -> Result<Self, SdkError> {
        let (account, passphrase) = (&bundle.account_id, &bundle.data_passphrase);
        let length = Self::ACCOUNT_KEY.len()
            + escaped_len(account)
            + Self::PASSPHRASE_KEY.len()
            + escaped_len(passphrase)
            + Self::END.len();
        let mut buffer = Self(Vec::with_capacity(length));
        let capacity = buffer.0.capacity();
        buffer.0.extend_from_slice(Self::ACCOUNT_KEY);
        escape_into(&mut buffer.0, account, None)?;
        buffer.0.extend_from_slice(Self::PASSPHRASE_KEY);
        escape_into(&mut buffer.0, passphrase, fail_after)?;
        buffer.0.extend_from_slice(Self::END);
        if buffer.0.len() != length || buffer.0.capacity() != capacity {
            return Err(invalid());
        }
        Ok(buffer)
    }
    #[cfg(test)]
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for BundleBytes {
    fn drop(&mut self) {
        wipe_allocation(&mut self.0, "p07-export-serializer");
    }
}
/// JCS (RFC 8785) string escaping: short escapes for the five named controls, `\u00xx` for the
/// rest below U+0020, backslash and quote escaped, everything else (U+007F, U+2028, non-BMP) literal.
fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|character| match character {
            '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
            '\0'..='\u{1f}' => 6,
            other => other.len_utf8(),
        })
        .sum()
}
fn escape_into(out: &mut Vec<u8>, text: &str, fail_after: Option<usize>) -> Result<(), SdkError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let start = out.len();
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\0'..='\u{1f}' => {
                let code = character as usize;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[code >> 4]);
                out.push(HEX[code & 0xf]);
            }
            other => {
                let mut utf8 = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut utf8).as_bytes());
            }
        }
        if fail_after.is_some_and(|limit| out.len() - start >= limit) {
            return Err(invalid());
        }
    }
    Ok(())
}
/// An authenticated local account, with no legacy root signer or active session.
#[derive(Clone, Debug)]
pub struct BornAccount {
    stored: StoredAuthority,
    verified: VerifiedRecord,
    authority_blocked: bool,
    networking_path: PathBuf,
}
pub(super) fn require_current_authority(
    pins: &ramflux_crypto::custody::AuthorityPins,
    record: &VerifiedRecord,
) -> Result<(), SdkError> {
    pins.require_current(record).map_err(|error| {
        let body = &record.envelope().body;
        let range = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)
            .ok()
            .map(|epoch| epoch.0);
        if range.is_some_and(|range| pins.conflict_evidence(&body.account_anchor, range).is_some())
        {
            SdkError::CustodyForkFenced
        } else {
            error.into()
        }
    })
}
impl BornAccount {
    fn require_current_snapshot(&self) -> Result<(), SdkError> {
        let root = self.networking_path.parent().and_then(Path::parent).ok_or_else(invalid)?;
        let current = load_data_account(root, self.local_account_id(), super::network_now()?)?;
        require_current_authority(&current.stored.pins, &current.verified)?;
        pairing::require_installed_marker(root, &current)?;
        if ramflux_protocol::custody::object_hash(current.record())?
            != ramflux_protocol::custody::object_hash(self.record())?
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        Ok(())
    }
    /// Build, but do not transmit, a branch-signed layer declaration endorsed by a new native head.
    /// The caller may publish the returned candidate only through an explicit later action.
    /// # Errors
    /// Rejects a mismatched primary/branch credential, invalid validity bounds, exhausted native
    /// revision, or any candidate that fails native authority verification.
    pub fn candidate_message_layer_publication(
        &self,
        root: &Path,
        branch: &super::BranchCredentials,
        primary: &ramflux_crypto::custody::SelfSigningKey,
        max_layer: u32,
        validity: super::DeclarationValidity,
    ) -> Result<ramflux_protocol::custody::Publication, SdkError> {
        use ramflux_protocol::custody::{decode_epoch, encode_epoch};
        let now = validity.issued_at;
        let expires_at = validity.expires_at;
        if self.branch_pending() || self.authority_blocked {
            return Err(SdkError::NetworkingPending);
        }
        require_current_authority(&self.stored.pins, &self.verified)?;
        let current = self.record();
        let body = &current.body;
        if primary.public_key() != body.master_certificate.body.self_signing_public_key {
            return Err(invalid());
        }
        if now <= body.issued_at || now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
            return Err(invalid());
        }
        let device_id = self.local_device_id()?;
        let device =
            body.devices.iter().find(|device| device.device_id == device_id).ok_or_else(invalid)?;
        let certificate = device.branch_certificate.as_ref().ok_or_else(invalid)?;
        let device_ref = ramflux_protocol::custody::DeviceRef {
            account_anchor: body.account_anchor.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        };
        if branch.signing.signing_key.verifying_key()
            != ramflux_crypto::verifying_key_from_base64url(
                &certificate.body.branch_signing_public_key,
            )?
        {
            return Err(invalid());
        }
        let previous_sequence = self
            .stored
            .message_layer_sequences
            .get(&ramflux_protocol::qualified_device_id(&body.account_anchor, device_id)?)
            .copied()
            .into_iter()
            .chain(device.message_layer.iter().map(|value| value.declaration.declaration_sequence))
            .max()
            .unwrap_or_default();
        let sequence = previous_sequence.checked_add(1).ok_or_else(invalid)?;
        let signed = super::layer_declaration::candidate(
            &branch.signing,
            device_ref.clone(),
            max_layer,
            sequence,
            now,
            expires_at,
        )?;
        if now < certificate.body.not_before || expires_at > certificate.body.expires_at {
            return Err(invalid());
        }
        let body_bytes = ramflux_protocol::custody::signing_bytes(
            ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
            &signed.declaration,
        )?;
        ramflux_crypto::verify_canonical_signature(
            &body_bytes,
            &signed.branch_signature,
            &certificate.body.branch_signing_public_key,
        )?;

        let mut next = body.clone();
        let old_head = ramflux_protocol::custody::object_hash(current)?;
        let (range, revision) = decode_epoch(body.device_set_epoch)?;
        next.device_set_epoch = encode_epoch(range, revision.checked_add(1).ok_or_else(invalid)?)?;
        next.previous_record_hash = Some(old_head);
        next.issued_at = now;
        let updated = next
            .devices
            .iter_mut()
            .find(|entry| entry.device_id == device_id)
            .ok_or_else(invalid)?;
        updated.message_layer = Some(signed);
        let record = primary.sign_record(next)?;
        let custodian = match self.stored.custodian_publication.as_ref() {
            Some(publication) => Some(ramflux_crypto::custody::verify_record(
                &publication.record,
                now,
                publication.compacted_ids.as_deref(),
                None,
            )?),
            None => self
                .stored
                .custodian_account_id
                .as_deref()
                .map(|id| load_human(root, id, now))
                .transpose()?,
        };
        let verified =
            verify_record(&record, now, self.stored.compacted_ids.as_deref(), custodian.as_ref())?;
        let mut pins = self.stored.pins.clone();
        if pins.observe_with_previous(&verified, Some(current))?
            != ramflux_crypto::custody::PinOutcome::Advanced
        {
            return Err(invalid());
        }
        Ok(ramflux_protocol::custody::Publication {
            record,
            compacted_ids: self.stored.compacted_ids.clone(),
        })
    }

    pub(crate) fn group_primary(
        &self,
        vault: &dyn PrimaryVault,
    ) -> Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
        self.require_current_snapshot()?;
        if self.branch_pending() || self.authority_blocked {
            return Err(SdkError::NetworkingPending);
        }
        require_current_authority(&self.stored.pins, &self.verified)?;
        if self.stored.primary_vault_ref.is_empty()
            || self.record().body.master_certificate.body.primary_device_ref.device_id
                != self.local_device_id()?
        {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        let primary = vault.load_primary(&self.stored.primary_vault_ref)?;
        if primary.public_key()
            != self.record().body.master_certificate.body.self_signing_public_key
        {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        Ok(primary)
    }
    pub(crate) fn sign_contact_card(
        &self,
        vault: &dyn PrimaryVault,
        body: ramflux_protocol::custody::ContactCardV3,
        now: u64,
    ) -> Result<Envelope<ramflux_protocol::custody::ContactCardV3>, SdkError> {
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        require_current_authority(&self.stored.pins, &self.verified)?;
        Ok(self.group_primary(vault)?.sign_contact_card_v3(&self.verified, body, now)?)
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
    /// The persisted cause; account status derives its remaining delay at display time.
    #[must_use]
    pub fn networking_reason(&self) -> Option<&crate::AccountNetworkingReason> {
        (self.state() == CreationState::NetworkingPending)
            .then_some(self.stored.networking_reason.as_ref())
            .flatten()
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
    pub(crate) fn branch_vault_ref(&self) -> &str {
        &self.stored.branch_vault_ref
    }
    #[must_use]
    pub(crate) fn primary_vault_ref(&self) -> &str {
        &self.stored.primary_vault_ref
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
    pub(crate) fn sign_migration_authorization(
        &self,
        vault: &dyn PrimaryVault,
        body: &ramflux_protocol::home_migration::Authorization,
        digest: &str,
        now: u64,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        vault.home_authorization_preflight()?;
        let (actor, credentials) = self.credentials(vault, &body.actor.device_id, now)?;
        if actor != body.actor {
            return Err(invalid());
        }
        let request = super::HomeAuthorizationRequest::new(
            super::home_authorization::HomeAuthorizationInput {
                local_account_id: self.local_account_id(),
                reference: &self.stored.primary_vault_ref,
                body,
                branch: &credentials.signing,
                authority: self.verified(),
                digest,
                now,
            },
        )?;
        vault.sign_home_authorization(request)
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
        self.summary_at(super::capacity_hint::unix_now())
    }
    pub(crate) fn summary_at(&self, now: u64) -> serde_json::Value {
        serde_json::json!({"local_account_id":self.local_account_id(),"principal_id":self.stored.record.body.principal_id,
            "account_anchor":self.stored.record.body.account_anchor,"kind":self.stored.record.body.principal_kind,"display_name":self.stored.record.body.profile.display_name,
            "state":self.state(),"networking_reason":self.networking_view(now),"authority_blocked":self.authority_blocked,"custody_v3_observed":true,"vault_class":self.stored.vault_class,"custodian_account_id":self.stored.custodian_account_id})
    }
}
fn directory(root: &Path, id: &str) -> Result<PathBuf, SdkError> {
    valid_id(id)?;
    Ok(root.join("custody_accounts").join(id))
}
pub(crate) fn reserve_pairing_account(
    root: &Path,
    id: &str,
    anchor: &str,
) -> Result<PathBuf, SdkError> {
    genesis::reserve_account(root, id, anchor)
}

/// Production vault-ref allocator (`custody_vault_reference.v1`). Same bytes as genesis.
///
/// # Errors
/// Canonical encoding or path canonicalize failures.
pub(crate) fn custody_vault_reference(
    root: &Path,
    account_id: &str,
    anchor: &str,
) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.local.custody_vault_reference.v1",
        &[
            &[0_u8][..],
            &ramflux_protocol::canonical_json_bytes(&(
                root.canonicalize()?.to_string_lossy(),
                account_id,
                anchor,
            ))?,
        ]
        .concat(),
    ))
}

pub(crate) fn account_exists(root: &Path, id: &str) -> Result<bool, SdkError> {
    // This query also guards legacy paths: do not impose new identifier rules on them.
    if valid_id(id).is_err() {
        return Ok(false);
    }
    Ok(directory(root, id)?.try_exists()?)
}
pub(crate) fn reconcile_incomplete_markers(
    root: &Path,
    _lease: &crate::bus::data_root_lock::DataRootLock,
) -> Result<(), SdkError> {
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
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".authority-") && name.ends_with(".tmp") && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    fs::File::open(path)?.sync_all()?;
    match index.account(id) {
        Ok(_) => Ok(()),
        Err(ramflux_storage::StorageError::AccountNotFound(_))
            if !path.join("authority.json").try_exists()? =>
        {
            fs::remove_dir(path)?;
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
            let summary = if let Ok(account) = load_data_account(root, &id, now) {
                account.summary_at(now)
            } else {
                let failed = failed_setup(root, &id)?;
                serde_json::json!({"local_account_id":id,"state":CreationState::NetworkingPending,
                    "custody_v3_observed":true,"setup_incomplete":true,"setup_failed":failed.is_some(),
                    "reason":failed.unwrap_or("authority_unreadable"),"setup_error":"CustodySetupInvalid"})
            };
            accounts.push(summary);
        }
    }
    accounts.sort_by(|a, b| a["local_account_id"].as_str().cmp(&b["local_account_id"].as_str()));
    Ok(accounts)
}
/// A reservation whose creation failed before its authority was written stays latched and can
/// never be unlocked. Returns the reason code for such an entry.
/// # Errors
/// Rejects invalid identifiers and filesystem failures.
pub(crate) fn failed_setup(root: &Path, id: &str) -> Result<Option<&'static str>, SdkError> {
    let dir = directory(root, id)?;
    Ok((dir.try_exists()? && !dir.join("authority.json").try_exists()?)
        .then_some("setup_failed_before_authority"))
}
/// Typed refusal for unlocking a failed setup, instead of a misleading networking state.
pub(crate) fn failed_setup_error(id: &str, reason: &str) -> SdkError {
    SdkError::LocalBusRefused {
        code: "CustodySetupFailed".into(),
        message: format!(
            "account {id} did not finish setup; its reservation is latched and cannot be \
             unlocked, so create a new account"
        ),
        body: Box::new(serde_json::json!({"reason_code": reason, "local_account_id": id})),
    }
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
        require_current_authority(&stored.pins, &verified)?;
    }
    let account =
        BornAccount { stored, verified, authority_blocked, networking_path: directory(root, id)? };
    if require_current {
        pairing::require_installed_marker(root, &account)?;
    }
    let _ = account.networking_view(now);
    Ok(account)
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
    require_current_authority(&stored.pins, &verified)?;
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
    crate::platform::fs::create_owner_only_dir(path)
}
fn create_private_temp(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    let mut file = crate::platform::fs::create_new_owner_only(path)?;
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
    let message_layer_sequences = super::layer_declaration::sequence_high_water(
        &record.body.account_anchor,
        &record.body.devices,
    )?;
    let mut pins = AuthorityPins::default();
    pins.observe(&verified)?;
    pins.discard_retained_records();
    let dir = genesis::reserve_account(root, &input.local_account_id, &record.body.account_anchor)?;
    let reference =
        custody_vault_reference(root, &input.local_account_id, &record.body.account_anchor)?;
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
            networking_reason: None,
            networking_node: None,
            capacity_retry_at: None,
            pending_branch: false,
            custody_v3_observed: true,
            pairing_adoption_required: false,
            primary_vault_ref: reference.clone(),
            branch_vault_ref: branch_reference.clone(),
            vault_class: vault.vault_class().into(),
            record,
            compacted_ids: None,
            custodian_publication: None,
            pins,
            message_layer_sequences,
            custodian_account_id: input.custodian_account_id.clone(),
            agent_provisioning_vault_ref: agent_provisioning_reference.clone(),
        };
        #[cfg(test)]
        race_hooks::run(race_hooks::Stage::BeforeAuthorityPublish, root, &input.local_account_id)?;
        genesis::require_owned_reservation(
            root,
            &input.local_account_id,
            &stored.record.body.account_anchor,
            &dir,
        )?;
        if let Some(gate) = commit_gate {
            gate.commit()?;
        }
        genesis::write_public(
            &dir.join("authority.json"),
            &ramflux_protocol::canonical_json_bytes(&stored)?,
        )?;
        Ok(BornAccount { stored, verified, authority_blocked: false, networking_path: dir.clone() })
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
    let passphrase = {
        let source = ExportSource::copy(&secret);
        std::str::from_utf8(&source.0).map_err(|_| invalid())?.to_owned()
    };
    let bundle =
        AgentProvisioningBundle { account_id: account_id.to_owned(), data_passphrase: passphrase };
    let bytes = BundleBytes::serialize(&bundle)?;
    let mut created = false;
    let result = (|| {
        let mut file = crate::platform::fs::create_new_owner_only(path)?;
        created = true;
        file.write_all(&bytes.0)?;
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
        self.require_current_snapshot()?;
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        if device_id != self.local_device_id()? {
            return Err(invalid());
        }
        require_current_authority(&self.stored.pins, &self.verified)?;
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
        if self.branch_pending() {
            return Err(SdkError::NetworkingPending);
        }
        let dir = directory(root, self.local_account_id())?;
        let lock = crate::platform::fs::open_owner_only_read_write(&dir.join(".authority.lock"))?;
        crate::platform::fs::lock_exclusive(&lock)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        let mut current = load_account(root, self.local_account_id(), now)?;
        if current.record() != self.record() {
            return Err(invalid());
        }
        current.stored.state = CreationState::Live;
        current.stored.networking_reason = None;
        current.stored.capacity_retry_at = None;
        let bytes = ramflux_protocol::canonical_json_bytes(&current.stored)?;
        if bytes.len() > MAX_STORED_AUTHORITY_BYTES {
            return Err(invalid());
        }
        let temp = dir.join(format!(
            ".authority-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        create_private_temp(&temp, &bytes)?;
        fs::rename(temp, dir.join("authority.json"))?;
        fs::File::open(&dir)?.sync_all()?;
        self.stored.state = CreationState::Live;
        self.stored.networking_reason = None;
        self.stored.capacity_retry_at = None;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn mark_live_for_test(&mut self, root: &Path) -> Result<(), SdkError> {
        self.mark_live(root)
    }
}

#[cfg(test)]
mod reservation_tests;
