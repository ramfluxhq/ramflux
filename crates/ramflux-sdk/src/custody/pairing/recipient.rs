// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recipient J0/J1: own branch vault and data-store passphrase, no master/SS.

use super::coordinator::verify_invitation;
use super::install_gate;
use super::install_store::{self, Install};
use super::local_credential::{
    LocalCredentialProvider, PersistedReservation, RecipientSecrets, SecretUtf8, acquire_setup,
    acquire_unlock, load_reservation, persist_reservation, remove_reservation,
};
use crate::SdkError;
use crate::custody::{BranchCredentials, PrimaryVault, require_vault_reference};
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::pairing::{PairingWire, WireError};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AccountDb, FileVaultSecretSource, FloorRow, LiveRow};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Inputs for new-recipient J0/J1 staging.
pub struct StageNew<'a> {
    pub root: &'a Path,
    pub account_id: &'a str,
    pub invitation: &'a Envelope<Invitation>,
    pub vault: &'a dyn PrimaryVault,
    pub provider: &'a dyn LocalCredentialProvider,
    pub frontend_generation: u64,
}

/// Existing-target reservation: original credential and refs are preserved.
pub struct StageExisting<'a> {
    pub new: StageNew<'a>,
    pub recipient_ref: DeviceRef,
    pub branch_vault_ref: &'a str,
    pub data_vault_ref: &'a str,
}

/// Durable recipient staging result. Public refs only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedRecipient {
    pub account_id: String,
    pub reservation_id: String,
    pub recipient_ref: DeviceRef,
    pub branch_vault_ref: String,
    pub data_vault_ref: String,
    pub install: Install,
}

/// Join-path staging before the recipient commitment. Injected into [`super::PairingActor`].
pub trait RecipientKeyStaging: Send + Sync {
    /// Stage own keys from the verified invitation before `queue_commit`.
    /// Returns the staged device identity the Join commitment must cover.
    ///
    /// # Errors
    /// Reservation, provider, vault, or journal failures.
    fn stage(
        &self,
        invitation: &Envelope<Invitation>,
        generation: u64,
    ) -> Result<DeviceRef, SdkError>;
    /// Stage with distinct frontend and durable ceremony generations.
    /// # Errors
    /// Same failures as `stage`; existing non-journal providers delegate to it.
    fn stage_with_generation(
        &self,
        invitation: &Envelope<Invitation>,
        frontend_generation: u64,
        _ceremony_generation: u64,
    ) -> Result<DeviceRef, SdkError> {
        self.stage(invitation, frontend_generation)
    }
}

/// Production [`RecipientKeyStaging`] over [`stage_new`].
pub struct RecipientStaging {
    pub root: PathBuf,
    pub account_id: String,
    pub vault: Arc<dyn PrimaryVault>,
    pub provider: Arc<dyn LocalCredentialProvider>,
}

impl RecipientKeyStaging for RecipientStaging {
    fn stage(
        &self,
        invitation: &Envelope<Invitation>,
        generation: u64,
    ) -> Result<DeviceRef, SdkError> {
        Ok(stage_new(&StageNew {
            root: &self.root,
            account_id: &self.account_id,
            invitation,
            vault: &*self.vault,
            provider: &*self.provider,
            frontend_generation: generation,
        })?
        .recipient_ref)
    }
}

/// J0+J1 for a NEW recipient. Generates a local branch seed. Never stores master/SS.
///
/// # Errors
/// Reservation, provider, vault, or journal failures. Refusal leaves the run unadmitted.
pub fn stage_new(request: &StageNew<'_>) -> Result<StagedRecipient, SdkError> {
    stage_new_on_client(request, &mut crate::RamfluxClient::new())
}

pub(crate) fn stage_new_on_client(
    request: &StageNew<'_>,
    client: &mut crate::RamfluxClient,
) -> Result<StagedRecipient, SdkError> {
    stage_new_for_generation(request, client, 1)
}

pub(crate) fn stage_new_for_generation(
    request: &StageNew<'_>,
    client: &mut crate::RamfluxClient,
    generation: u64,
) -> Result<StagedRecipient, SdkError> {
    verify_invitation(request.invitation)?;
    let reservation = reserve_new(request)?;
    let credential = setup_secret(request, &reservation.reservation_id)?;
    commit_new(request, reservation, &credential, client, generation)
}

/// Existing-target J0/J1: original password, branch and data refs, zero setup callbacks.
///
/// # Errors
/// Reservation or unlock failures. Setup action is refused.
pub fn stage_existing(request: &StageExisting<'_>) -> Result<StagedRecipient, SdkError> {
    stage_existing_for_generation(request, &mut crate::RamfluxClient::new(), 1)
}

pub(crate) fn stage_existing_for_generation(
    request: &StageExisting<'_>,
    client: &mut crate::RamfluxClient,
    generation: u64,
) -> Result<StagedRecipient, SdkError> {
    verify_invitation(request.new.invitation)?;
    let staged = existing_reservation(request, client)?;
    write_floor_live(client.account_db()?, &request.new, &staged, generation)?;
    Ok(staged)
}

/// Ordinary networking stays closed until install, DB, vault and authority agree.
/// Legacy accounts with no pairing install keep their existing reader.
///
/// # Errors
/// Install-store field or I/O errors.
pub fn ordinary_networking_allowed(root: &Path, account_id: &str) -> Result<bool, SdkError> {
    ordinary_session_admitted_at(root, account_id, None, authority_present(root, account_id))
}

/// True when a pairing reservation exists without authority, so data unlock may skip born load.
///
/// # Errors
/// Install-store field or I/O errors.
pub fn unadmitted_data_unlock(root: &Path, account_id: &str) -> Result<bool, SdkError> {
    Ok(install_store::list_pending(root, account_id)?
        .iter()
        .any(|row| matches!(row.state.as_str(), "reserved" | "vault_durable")))
}

/// Session admission used by `native_account::unlock` after the data store is open.
///
/// # Errors
/// Install-store or DB errors.
pub fn ordinary_session_admitted(
    client: &crate::RamfluxClient,
    account_id: &str,
) -> Result<bool, SdkError> {
    let root = client.account_index()?.root();
    let adoption = client.account_db()?.pairing_adoption()?;
    let installed = install_store::read_installed(root, account_id)?;
    if let (Some(install), Some(adoption)) = (&installed, &adoption)
        && (install.full_transfer.is_some()
            || adoption.full_generation_nonce.is_some()
            || adoption.full_initial_union_root.is_some())
    {
        let account =
            crate::custody::load_data_account(root, account_id, crate::custody::network_now()?)?;
        return Ok(super::full_generation::require_completed_full_generation(
            root, &account, install, adoption,
        )
        .is_ok());
    }
    if !ordinary_session_admitted_at(
        root,
        account_id,
        adoption.as_ref().map(|row| row.record_hash.as_str()),
        authority_present(root, account_id),
    )? {
        return Ok(false);
    }
    let installed = install_store::read_installed(root, account_id)?;
    match (installed, adoption) {
        (None, None) => Ok(true),
        (Some(install), Some(adoption)) => {
            let account = crate::custody::load_data_account(
                root,
                account_id,
                crate::custody::network_now()?,
            )?;
            Ok(super::activate::adoption(&install)? == adoption
                && crate::custody::matches_install(&account, &install)?)
        }
        _ => Ok(false),
    }
}

fn ordinary_session_admitted_at(
    root: &Path,
    account_id: &str,
    adoption_hash: Option<&str>,
    authority: bool,
) -> Result<bool, SdkError> {
    let pending = install_store::list_pending(root, account_id)?;
    let installed = install_store::read_installed(root, account_id)?;
    if pending.is_empty() && installed.is_none() {
        return Ok(true);
    }
    Ok(install_gate::reopen(root, account_id, adoption_hash, authority)?
        .admits_ordinary_networking())
}

fn authority_present(root: &Path, account_id: &str) -> bool {
    root.join("custody_accounts").join(account_id).join("authority.json").is_file()
}

fn reserve_new(request: &StageNew<'_>) -> Result<StagedRecipient, SdkError> {
    let body = &request.invitation.body;
    let reservation_id = encode_base64url(*random_32()?);
    let recipient_ref = DeviceRef {
        account_anchor: body.account_anchor.clone(),
        device_id: encode_base64url(*random_32()?),
        device_epoch: 1,
    };
    crate::custody::reserve_pairing_account(
        request.root,
        request.account_id,
        &body.account_anchor,
    )?;
    persist_reservation(
        request.root,
        &PersistedReservation {
            account_id: request.account_id.into(),
            reservation_id: reservation_id.clone(),
            frontend_generation: request.frontend_generation,
        },
    )?;
    let hashed = crate::custody::custody_vault_reference(
        request.root,
        request.account_id,
        &body.account_anchor,
    )?;
    let branch_vault_ref = format!("branch:{hashed}");
    require_vault_reference(&branch_vault_ref, "branch:")?;
    let data_vault_ref = FileVaultSecretSource::owner_ref(request.account_id);
    let install = reserved_install(request, &recipient_ref, &branch_vault_ref, &data_vault_ref)?;
    install_store::write_pending(request.root, &install)?;
    Ok(StagedRecipient {
        account_id: request.account_id.into(),
        reservation_id,
        recipient_ref,
        branch_vault_ref,
        data_vault_ref,
        install,
    })
}

fn setup_secret(request: &StageNew<'_>, reservation_id: &str) -> Result<SecretUtf8, SdkError> {
    let stored = load_reservation(request.root, request.account_id)?
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    if stored.reservation_id != reservation_id {
        return Err(SdkError::PairingField("credential_reservation"));
    }
    let expected = credential_request(request, reservation_id, "setup")?;
    let binding = super::private_credential::PrivateCredentialScope::data(
        expected.clone(),
        Some(request.invitation.body.request_id.clone()),
    )?;
    let provider = super::local_credential::scoped(request.provider, binding);
    acquire_setup(request.root, &expected, &provider, &stored)
}

fn commit_new(
    request: &StageNew<'_>,
    mut staged: StagedRecipient,
    credential: &SecretUtf8,
    client: &mut crate::RamfluxClient,
    generation: u64,
) -> Result<StagedRecipient, SdkError> {
    let mut secrets = generate_secrets()?;
    let outcome =
        commit_vault_and_db(request, &staged, &secrets, credential.as_bytes(), client, generation);
    match outcome {
        Ok(()) => {
            staged.install.state = "vault_durable".into();
            install_store::write_pending(request.root, &staged.install)?;
            secrets.cleanup();
            Ok(staged)
        }
        Err(error) => {
            secrets.cleanup();
            Err(error)
        }
    }
}

fn generate_secrets() -> Result<RecipientSecrets, SdkError> {
    let mut branch = Zeroizing::new([0_u8; 64]);
    getrandom::fill(&mut *branch).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    Ok(RecipientSecrets::new(branch))
}

fn commit_vault_and_db(
    request: &StageNew<'_>,
    staged: &StagedRecipient,
    secrets: &RecipientSecrets,
    passphrase: &[u8],
    client: &mut crate::RamfluxClient,
    generation: u64,
) -> Result<(), SdkError> {
    request.vault.preflight()?;
    let mut written = false;
    let outcome = (|| {
        request.vault.store_branch(&staged.branch_vault_ref, &secrets.branch)?;
        written = true;
        let _ = BranchCredentials::from_vault_seeds(
            &staged.recipient_ref.account_anchor,
            &staged.recipient_ref,
            &secrets.branch,
        )?;
        client.open_account_index(request.root)?;
        client.seal_new_account_data(
            request.account_id,
            &staged.recipient_ref.account_anchor,
            passphrase,
        )?;
        client.unlock_account(request.account_id, passphrase)?;
        write_floor_live(client.account_db()?, request, staged, generation)?;
        let wrapped = client
            .account_index()?
            .load_wrapped_db_key(request.account_id)?
            .ok_or(SdkError::PairingField("data_vault_ref"))?;
        if wrapped.key_wrapping_ref != staged.data_vault_ref {
            return Err(SdkError::PairingField("data_vault_ref"));
        }
        Ok(())
    })();
    if outcome.is_err() {
        abort_owned(request.vault, &staged.branch_vault_ref, written);
    }
    outcome
}

fn write_floor_live(
    db: &AccountDb,
    request: &StageNew<'_>,
    staged: &StagedRecipient,
    generation: u64,
) -> Result<(), SdkError> {
    let body = &request.invitation.body;
    let sequence = db
        .pairing_floor()?
        .map_or(Ok(1), |row| row.issued_seq.checked_add(1).ok_or(SdkError::PairingCode("Busy")))?;
    let mut live = invited_live(request, staged, generation)?;
    live.local_seq = sequence;
    live.primary_vault_ref.clone_from(&staged.install.primary_vault_ref);
    db.commit_pairing_invitation(
        &FloorRow {
            account_id: request.account_id.into(),
            account_anchor: body.account_anchor.clone(),
            issued_seq: sequence,
            next_generation: generation.checked_add(1).ok_or(SdkError::PairingCode("Busy"))?,
        },
        &live,
    )?;
    Ok(())
}

fn invited_live(
    request: &StageNew<'_>,
    staged: &StagedRecipient,
    generation: u64,
) -> Result<LiveRow, SdkError> {
    let body = &request.invitation.body;
    Ok(LiveRow {
        account_id: request.account_id.into(),
        operation_id: body.request_id.clone(),
        invitation_id: body.invitation_id.clone(),
        issuer_seq: body.issuer_seq,
        local_seq: 1,
        generation,
        role: "responder".into(),
        descriptor: canonical_json_bytes(request.invitation)?,
        phase: "invited".into(),
        context: None,
        transcript_hash: None,
        proposal_hash: None,
        transfer_ciphertext_hash: None,
        candidate_id: None,
        branch_reservation: None,
        branch_vault_ref: Some(staged.branch_vault_ref.clone()),
        primary_vault_ref: None,
        base_record_hash: body.base_record_hash.clone(),
        base_epoch: body.base_epoch,
        expires_at: body.expires_at,
        result: None,
    })
}

fn existing_reservation(
    request: &StageExisting<'_>,
    client: &mut crate::RamfluxClient,
) -> Result<StagedRecipient, SdkError> {
    let destination = request
        .new
        .invitation
        .body
        .destination_ref
        .as_ref()
        .ok_or(SdkError::PairingField("destination_ref"))?;
    if &request.recipient_ref != destination {
        return Err(SdkError::PairingField("recipient_ref"));
    }
    let native = crate::custody::load_account(
        request.new.root,
        request.new.account_id,
        crate::custody::network_now()?,
    )?;
    require_existing_refs(request, &native)?;
    unlock_existing(request, client)?;
    write_existing_install(request, &encode_base64url(*random_32()?))
}

fn require_existing_refs(
    request: &StageExisting<'_>,
    native: &crate::custody::BornAccount,
) -> Result<(), SdkError> {
    if request.recipient_ref.account_anchor != native.record().body.account_anchor {
        return Err(SdkError::PairingField("recipient_ref"));
    }
    if request.recipient_ref.device_id != native.local_device_id()? {
        return Err(SdkError::PairingField("recipient_ref"));
    }
    if request.branch_vault_ref != native.branch_vault_ref() {
        return Err(SdkError::PairingField("branch_vault_ref"));
    }
    if request.data_vault_ref != stored_data_vault_ref(request.new.root, request.new.account_id)? {
        return Err(SdkError::PairingField("data_vault_ref"));
    }
    Ok(())
}

fn stored_data_vault_ref(root: &Path, account_id: &str) -> Result<String, SdkError> {
    let index = ramflux_storage::AccountIndex::open(root)?;
    let wrapped =
        index.load_wrapped_db_key(account_id)?.ok_or(SdkError::PairingField("data_vault_ref"))?;
    Ok(wrapped.key_wrapping_ref)
}

fn unlock_existing(
    request: &StageExisting<'_>,
    client: &mut crate::RamfluxClient,
) -> Result<(), SdkError> {
    let reservation_id = encode_base64url(*random_32()?);
    persist_reservation(
        request.new.root,
        &PersistedReservation {
            account_id: request.new.account_id.into(),
            reservation_id: reservation_id.clone(),
            frontend_generation: request.new.frontend_generation,
        },
    )?;
    let stored = load_reservation(request.new.root, request.new.account_id)?
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    let expected = credential_request(&request.new, &reservation_id, "unlock")?;
    expected.validate_recipient_mode("existing").map_err(|error| wire(&error))?;
    client.open_account_index(request.new.root)?;
    let binding = super::private_credential::PrivateCredentialScope::data(
        expected.clone(),
        Some(request.new.invitation.body.request_id.clone()),
    )?;
    let provider = super::local_credential::scoped(request.new.provider, binding);
    let secret = match acquire_unlock(request.new.root, &expected, &provider, &stored) {
        Ok(secret) => secret,
        Err(error) => {
            let _ = remove_reservation(request.new.root, request.new.account_id);
            return Err(error);
        }
    };
    if client.active_account_db.is_some() {
        client.verify_active_account_secret(request.new.account_id, secret.as_bytes())?;
    } else {
        client.unlock_account(request.new.account_id, secret.as_bytes())?;
    }
    Ok(())
}

fn write_existing_install(
    request: &StageExisting<'_>,
    primary_vault_ref: &str,
) -> Result<StagedRecipient, SdkError> {
    let stored = load_reservation(request.new.root, request.new.account_id)?
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    let mut install = reserved_install(
        &request.new,
        &request.recipient_ref,
        request.branch_vault_ref,
        request.data_vault_ref,
    )?;
    install.recipient_mode = "existing".into();
    install.install_purpose = "transfer_destination".into();
    install.primary_vault_ref = Some(primary_vault_ref.into());
    install.prior_record_hash = Some(request.new.invitation.body.base_record_hash.clone());
    install.validate()?;
    install_store::write_pending(request.new.root, &install)?;
    install.state = "vault_durable".into();
    install.validate()?;
    install_store::write_pending(request.new.root, &install)?;
    Ok(StagedRecipient {
        account_id: request.new.account_id.into(),
        reservation_id: stored.reservation_id,
        recipient_ref: request.recipient_ref.clone(),
        branch_vault_ref: request.branch_vault_ref.into(),
        data_vault_ref: request.data_vault_ref.into(),
        install,
    })
}

fn reserved_install(
    request: &StageNew<'_>,
    recipient_ref: &DeviceRef,
    branch_vault_ref: &str,
    data_vault_ref: &str,
) -> Result<Install, SdkError> {
    let body = &request.invitation.body;
    let install = Install {
        schema: "ramflux.pairing.Install.v2".into(),
        version: 2,
        account_id: request.account_id.into(),
        account_anchor: body.account_anchor.clone(),
        operation_id: body.request_id.clone(),
        recipient_ref: recipient_ref.clone(),
        recipient_mode: "new".into(),
        install_purpose: if body.purpose == "primary_transfer" {
            "transfer_destination"
        } else {
            "enroll"
        }
        .into(),
        record_hash: None,
        prior_record_hash: None,
        branch_vault_ref: branch_vault_ref.into(),
        data_vault_ref: data_vault_ref.into(),
        primary_vault_ref: if body.purpose == "primary_transfer" {
            Some(encode_base64url(*random_32()?))
        } else {
            None
        },
        state: "reserved".into(),
        cleanup_ref: None,
        cleanup_owner_ref: None,
        full_transfer: None,
    };
    install.validate()?;
    Ok(install)
}

fn credential_request(
    request: &StageNew<'_>,
    reservation_id: &str,
    action: &str,
) -> Result<CredentialRequest, SdkError> {
    let value = CredentialRequest {
        local_account_id: request.account_id.into(),
        reservation_id: reservation_id.into(),
        frontend_generation: request.frontend_generation,
        action: action.into(),
    };
    value.validate().map_err(|error| wire(&error))?;
    Ok(value)
}

fn abort_owned(vault: &dyn PrimaryVault, candidate: &str, written: bool) {
    if written {
        let _ = vault.delete(candidate);
    }
}

fn random_32() -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    Ok(bytes)
}

fn wire(error: &WireError) -> SdkError {
    match error {
        WireError::Field(name) => SdkError::PairingField(name),
        WireError::Size | WireError::Json | WireError::Shape | WireError::NonCanonical => {
            SdkError::PairingCode("InvalidInput")
        }
    }
}

/// Unlock through the ordinary data-store path after a private provider returns a secret.
///
/// # Errors
/// `VaultUnavailable` on provider refusal; existing data-store errors on a wrong secret.
pub fn unlock_with_provider(
    client: &mut crate::RamfluxClient,
    account_id: &str,
    expected: &CredentialRequest,
    provider: &dyn LocalCredentialProvider,
) -> Result<(), SdkError> {
    let root = client.account_index()?.root().to_path_buf();
    let stored = load_reservation(&root, account_id)?
        .ok_or(SdkError::PairingField("credential_reservation"))?;
    let secret = acquire_unlock(&root, expected, provider, &stored)?;
    client.unlock_account(account_id, secret.as_bytes())
}

#[cfg(test)]
pub(crate) mod tests;
