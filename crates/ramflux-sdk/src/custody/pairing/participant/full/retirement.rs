// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact source secondary installation and positive old-management-key cleanup.
use crate::custody::pairing::{
    Installation,
    install_store::{self, Install},
};
use crate::{SdkError, custody};
use ramflux_protocol::{
    custody::{CustodyAuthority, DeviceRef, object_hash},
    parse_i_json,
};
use ramflux_storage::HeadRow;
use std::path::Path;
mod cleanup;
/// Local key cleanup never rolls back the published role or waits for the tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullSourceRetirementOutcome {
    Complete,
    CleanupPending,
}
/// Retry an independent positive old-key cleanup receipt on unlock/hourly/status work.
/// No approval, publisher or original actor is reconstructed; current native fields stay unchanged.
/// # Errors
/// Refuses another selected writer, incomplete role installation or missing old-owner proof.
pub fn retry_full_source_cleanup(
    local: &Installation<'_>,
    operation: &str,
) -> Result<FullSourceRetirementOutcome, SdkError> {
    cleanup::retry(local, operation)
}
fn wrong() -> SdkError {
    SdkError::PairingCode("PublicationPending")
}
pub(super) fn install(
    root: &Path,
    head: &HeadRow,
    authority: &CustodyAuthority,
    local: &Installation<'_>,
) -> Result<FullSourceRetirementOutcome, SdkError> {
    if std::fs::canonicalize(root)? != std::fs::canonicalize(local.root)?
        || local.db.local_account_id != head.account_id
    {
        return Err(wrong());
    }
    let verified = ramflux_crypto::custody::verify_publication(authority, local.now)?;
    if object_hash(verified.envelope())? != head.candidate_hash {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    let source: DeviceRef = parse_i_json(&head.publisher_ref)?;
    if source == verified.envelope().body.master_certificate.body.primary_device_ref {
        return Err(wrong());
    }
    let _authority = super::super::super::activate::authority_lock(root, &head.account_id)?;
    let account = custody::load_data_account(root, &head.account_id, local.now)?;
    if account.local_device_id()? != source.device_id {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    if object_hash(account.record())? != head.candidate_hash {
        return cleanup::after_refresh(root, head, local, &source, &account);
    }
    let owner = local.db.full_source_retirement_owner(
        &head.operation_id,
        &head.candidate_hash,
        local.now,
    )?;
    if !account.primary_vault_ref().is_empty() && account.primary_vault_ref() != owner.reference() {
        return Err(wrong());
    }
    let pending = pending_install(head, source, &account, owner.reference());
    pending.validate()?;
    let saved = install_store::read_pending(root, &head.account_id, &head.operation_id)?;
    if saved.as_ref().is_some_and(|row| row != &pending) {
        return Err(wrong());
    }
    let mut installed = pending.clone();
    installed.state = "installed".into();
    installed.cleanup_ref = None;
    installed.cleanup_owner_ref = None;
    let adoption = super::super::super::full_generation::preserved_refresh_adoption(
        root, local.db, &installed,
    )?;
    if saved.is_none() && cleanup::already_complete(local, &installed, &adoption, &account)? {
        return Ok(FullSourceRetirementOutcome::Complete);
    }
    custody::verify_pairing_local(&installed, authority, local.vault, local.now)?;
    // Positive reference survives BEFORE authority fields stop naming the old key.
    install_store::write_pending(root, &pending)?;
    custody::write_pairing_authority(root, &installed, authority, local.vault, local.now)?;
    let updated = custody::load_data_account(root, &head.account_id, local.now)?;
    if !custody::matches_install(&updated, &installed)? {
        return Err(wrong());
    }
    if local.db.pairing_adoption()?.as_ref() != Some(&adoption) {
        local.db.commit_pairing_install(&adoption)?;
    }
    install_store::write_installed(root, &installed)?;
    local.db.retire_full_source_install_head(&adoption)?;
    // Only this immutable old reference is deleted. Branch/data owners stay live;
    // any provider or file failure retains the concordant cleanup-only latch.
    if local.vault.delete(owner.reference()).is_err() {
        return Ok(FullSourceRetirementOutcome::CleanupPending);
    }
    if install_store::remove_pending(root, &head.account_id, &head.operation_id).is_err() {
        return Ok(FullSourceRetirementOutcome::CleanupPending);
    }
    Ok(FullSourceRetirementOutcome::Complete)
}

fn pending_install(
    head: &HeadRow,
    source: DeviceRef,
    account: &custody::BornAccount,
    old_primary_ref: &str,
) -> Install {
    Install {
        schema: "ramflux.pairing.Install.v2".into(),
        version: 2,
        account_id: head.account_id.clone(),
        account_anchor: source.account_anchor.clone(),
        operation_id: head.operation_id.clone(),
        recipient_ref: source.clone(),
        recipient_mode: "existing".into(),
        install_purpose: "transfer_source".into(),
        record_hash: Some(head.candidate_hash.clone()),
        prior_record_hash: Some(head.base_record_hash.clone()),
        branch_vault_ref: account.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&head.account_id),
        primary_vault_ref: None,
        state: "cleanup_pending".into(),
        cleanup_ref: Some(old_primary_ref.into()),
        cleanup_owner_ref: Some(source),
        full_transfer: None,
    }
}
