// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Recipient J0/J1: own branch and data vault, no master/SS, no ordinary networking.

use super::install_gate;
use super::install_store::{self, Install};
use super::local_credential::{
    LocalCredentialProvider, RecipientSecrets, SecretUtf8, acquire_setup, acquire_unlock,
};
use crate::SdkError;
use crate::custody::{BranchCredentials, PrimaryVault};
use ramflux_protocol::canonical_json_bytes;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use ramflux_protocol::custody::pairing::native::Invitation;
use ramflux_protocol::custody::pairing::{PairingWire, WireError};
use ramflux_protocol::custody::{DeviceRef, Envelope};
use ramflux_protocol::encode_base64url;
use ramflux_storage::{AccountDb, FloorRow, LiveRow};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
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

/// J0+J1 for a NEW recipient. Generates local branch/data keys. Never stores master/SS.
///
/// # Errors
/// Reservation, provider, vault, or journal failures. Refusal leaves the run unadmitted.
pub fn stage_new(request: &StageNew<'_>) -> Result<StagedRecipient, SdkError> {
    request.invitation.body.validate().map_err(|error| wire(&error))?;
    let reservation = reserve_new(request)?;
    let credential = setup_secret(request, &reservation.reservation_id)?;
    commit_new(request, reservation, &credential)
}

/// Existing-target J0/J1: original password, branch and data refs, zero setup callbacks.
///
/// # Errors
/// Reservation or unlock failures. Setup action is refused.
pub fn stage_existing(request: &StageExisting<'_>) -> Result<StagedRecipient, SdkError> {
    request.new.invitation.body.validate().map_err(|error| wire(&error))?;
    existing_reservation(request)
}

/// Ordinary networking stays closed until install, DB, vault and authority agree.
/// Legacy accounts with no pairing install keep their existing reader.
///
/// # Errors
/// Install-store field or I/O errors.
pub fn ordinary_networking_allowed(root: &Path, account_id: &str) -> Result<bool, SdkError> {
    let pending = install_store::list_pending(root, account_id)?;
    let installed = install_store::read_installed(root, account_id)?;
    if pending.is_empty() && installed.is_none() {
        return Ok(true);
    }
    Ok(install_gate::reopen(root, account_id, None, false)?.admits_ordinary_networking())
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

/// Ordinary pre-ACK send. Admission is checked before any socket is opened.
///
/// # Errors
/// `PublicationPending` while the head is not durable; transport errors after admission.
pub fn try_ordinary_network_send(
    root: &Path,
    account_id: &str,
    origin: &str,
    payload: &[u8],
) -> Result<(), SdkError> {
    if !ordinary_networking_allowed(root, account_id)? {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    ordinary_session_post(origin, "/client/session/v1/send", payload)?;
    Ok(())
}

/// Ordinary session POST. Pairing transport is HTTPS-only and is not used here.
/// Admission must already have been checked: this opens TCP.
fn ordinary_session_post(origin: &str, path: &str, body: &[u8]) -> Result<(), SdkError> {
    let (host, addr) = ordinary_dial_addr(origin)?;
    let addr = addr
        .to_socket_addrs()
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?
        .next()
        .ok_or(SdkError::PairingCode("InvalidInput"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.set_nodelay(true)?;
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let _ = ordinary_split_http(&raw)?;
    Ok(())
}

fn ordinary_dial_addr(origin: &str) -> Result<(String, String), SdkError> {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or(origin);
    let host = rest.split('/').next().ok_or(SdkError::PairingCode("InvalidInput"))?;
    if host.is_empty() {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok((host.to_owned(), host.to_owned()))
}

fn ordinary_split_http(raw: &[u8]) -> Result<(String, Vec<u8>), SdkError> {
    let text = std::str::from_utf8(raw).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or(SdkError::PairingCode("InvalidInput"))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.splitn(3, ' ');
            let _ = parts.next()?;
            let code = parts.next()?;
            let reason = parts.next().unwrap_or("");
            Some(format!("{code} {reason}"))
        })
        .ok_or(SdkError::PairingCode("InvalidInput"))?;
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let bytes = body.as_bytes();
    let body = match length {
        Some(n) => bytes.get(..n).unwrap_or(bytes).to_vec(),
        None => bytes.to_vec(),
    };
    Ok((status, body))
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
    let branch_vault_ref = format!("branch:{}", request.account_id);
    let data_vault_ref = format!("data:{}", request.account_id);
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
    let expected = credential_request(request, reservation_id, "setup")?;
    acquire_setup(&expected, request.provider)
}

fn commit_new(
    request: &StageNew<'_>,
    mut staged: StagedRecipient,
    credential: &SecretUtf8,
) -> Result<StagedRecipient, SdkError> {
    let mut secrets = generate_secrets(credential.as_bytes())?;
    let outcome = commit_vault_and_db(request, &staged, &secrets);
    match outcome {
        Ok(()) => {
            staged.install.state = "vault_durable".into();
            install_store::write_pending(request.root, &staged.install)?;
            secrets.cleanup();
            Ok(staged)
        }
        Err(error) => {
            abort_provisional(request.vault, &[&staged.branch_vault_ref, &staged.data_vault_ref]);
            secrets.cleanup();
            Err(error)
        }
    }
}

fn generate_secrets(passphrase: &[u8]) -> Result<RecipientSecrets, SdkError> {
    let mut branch = Zeroizing::new([0_u8; 64]);
    getrandom::fill(&mut *branch).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let data = random_32()?;
    Ok(RecipientSecrets::new(branch, data, passphrase))
}

fn commit_vault_and_db(
    request: &StageNew<'_>,
    staged: &StagedRecipient,
    secrets: &RecipientSecrets,
) -> Result<(), SdkError> {
    request.vault.preflight()?;
    request.vault.store_branch(&staged.branch_vault_ref, &secrets.branch)?;
    request.vault.store_provisioning_secret(&staged.data_vault_ref, secrets.data.as_slice())?;
    let _ = BranchCredentials::from_vault_seeds(
        &staged.recipient_ref.account_anchor,
        &staged.recipient_ref,
        &secrets.branch,
    )?;
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(request.root)?;
    client.seal_new_account_data(
        request.account_id,
        &staged.recipient_ref.account_anchor,
        secrets.passphrase.as_slice(),
    )?;
    client.unlock_account(request.account_id, secrets.passphrase.as_slice())?;
    write_floor_live(client.account_db()?, request, staged)?;
    Ok(())
}

fn write_floor_live(
    db: &AccountDb,
    request: &StageNew<'_>,
    staged: &StagedRecipient,
) -> Result<(), SdkError> {
    let body = &request.invitation.body;
    db.put_pairing_floor(&FloorRow {
        account_id: request.account_id.into(),
        account_anchor: body.account_anchor.clone(),
        issued_seq: 1,
        next_generation: 2,
    })?;
    db.put_pairing_live(&invited_live(request, staged)?)?;
    db.persist_actor_state("pairing/local-sentinel", &"sealed")?;
    Ok(())
}

fn invited_live(request: &StageNew<'_>, staged: &StagedRecipient) -> Result<LiveRow, SdkError> {
    let body = &request.invitation.body;
    Ok(LiveRow {
        account_id: request.account_id.into(),
        operation_id: body.request_id.clone(),
        invitation_id: body.invitation_id.clone(),
        issuer_seq: body.issuer_seq,
        local_seq: 1,
        generation: 1,
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

fn existing_reservation(request: &StageExisting<'_>) -> Result<StagedRecipient, SdkError> {
    let expected =
        credential_request(&request.new, &request.new.invitation.body.request_id, "unlock")?;
    expected.validate_recipient_mode("existing").map_err(|error| wire(&error))?;
    let mut install = reserved_install(
        &request.new,
        &request.recipient_ref,
        request.branch_vault_ref,
        request.data_vault_ref,
    )?;
    install.recipient_mode = "existing".into();
    install.prior_record_hash = Some(request.new.invitation.body.base_record_hash.clone());
    install.validate()?;
    install_store::write_pending(request.new.root, &install)?;
    install.state = "vault_durable".into();
    install.validate()?;
    install_store::write_pending(request.new.root, &install)?;
    Ok(StagedRecipient {
        account_id: request.new.account_id.into(),
        reservation_id: expected.reservation_id,
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
        install_purpose: "enroll".into(),
        record_hash: None,
        prior_record_hash: None,
        branch_vault_ref: branch_vault_ref.into(),
        data_vault_ref: data_vault_ref.into(),
        primary_vault_ref: None,
        state: "reserved".into(),
        cleanup_ref: None,
        cleanup_owner_ref: None,
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

fn abort_provisional(vault: &dyn PrimaryVault, refs: &[&str]) {
    for reference in refs {
        let _ = vault.delete(reference);
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
    let secret = acquire_unlock(expected, provider)?;
    match client.unlock_account(account_id, secret.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
