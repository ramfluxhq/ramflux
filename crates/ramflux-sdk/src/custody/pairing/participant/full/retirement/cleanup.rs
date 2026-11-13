// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An independent old-key cleanup receipt never rewrites a later installed native head.
use super::{FullSourceRetirementOutcome, custody, install_store, wrong};
use crate::{SdkError, custody::pairing::Installation};
use ramflux_protocol::custody::DeviceRef;
use ramflux_storage::HeadRow;
use std::path::Path;
pub(super) fn after_refresh(
    root: &Path,
    original: &HeadRow,
    local: &Installation<'_>,
    source: &DeviceRef,
    account: &custody::BornAccount,
) -> Result<FullSourceRetirementOutcome, SdkError> {
    let pending = install_store::read_pending(root, &original.account_id, &original.operation_id)?
        .ok_or_else(wrong)?;
    if pending.recipient_ref != *source
        || pending.record_hash.as_deref() != Some(original.candidate_hash.as_str())
        || pending.prior_record_hash.as_deref() != Some(original.base_record_hash.as_str())
    {
        return Err(wrong());
    }
    finish(root, local, &pending, account)
}

pub(super) fn retry(
    local: &Installation<'_>,
    operation: &str,
) -> Result<FullSourceRetirementOutcome, SdkError> {
    let id = &local.db.local_account_id;
    let selected = ramflux_storage::AccountIndex::open(local.root)?.account(id)?;
    if std::fs::canonicalize(&local.db.path)?
        != std::fs::canonicalize(local.root.join(selected.db_relative_path))?
    {
        return Err(wrong());
    }
    let _lock = crate::custody::pairing::activate::authority_lock(local.root, id)?;
    let Some(pending) = install_store::read_pending(local.root, id, operation)? else {
        return Ok(FullSourceRetirementOutcome::Complete);
    };
    let account = custody::load_data_account(local.root, id, local.now)?;
    finish(local.root, local, &pending, &account)
}
fn finish(
    root: &Path,
    local: &Installation<'_>,
    pending: &install_store::Install,
    account: &custody::BornAccount,
) -> Result<FullSourceRetirementOutcome, SdkError> {
    let installed = install_store::read_installed(root, &pending.account_id)?.ok_or_else(wrong)?;
    if !matches!(installed.install_purpose.as_str(), "transfer_source" | "authority_refresh")
        || installed.state != "installed"
        || installed.primary_vault_ref.is_some()
        || account.record().body.master_certificate.body.primary_device_ref == pending.recipient_ref
        || install_store::pending_blocks_network(std::slice::from_ref(pending), Some(&installed))
        || !custody::matches_install(account, &installed)?
    {
        return Err(wrong());
    }
    let expected = crate::custody::pairing::full_generation::preserved_refresh_adoption(
        root, local.db, &installed,
    )?;
    if local.db.pairing_adoption()?.as_ref() != Some(&expected) {
        return Err(wrong());
    }
    let owner = local.db.full_source_retirement_owner(
        &pending.operation_id,
        pending.record_hash.as_deref().ok_or_else(wrong)?,
        local.now,
    )?;
    if pending.cleanup_ref.as_deref() != Some(owner.reference()) {
        return Err(wrong());
    }
    // Retry addresses only the immutable old reference, without reading branch/data keys,
    // seeking approval, or rewriting current native authority/installation/adoption.
    if local.vault.delete(owner.reference()).is_err() {
        return Ok(FullSourceRetirementOutcome::CleanupPending);
    }
    if install_store::remove_pending(root, &pending.account_id, &pending.operation_id).is_err() {
        return Ok(FullSourceRetirementOutcome::CleanupPending);
    }
    Ok(FullSourceRetirementOutcome::Complete)
}

pub(super) fn already_complete(
    local: &Installation<'_>,
    installed: &install_store::Install,
    adoption: &ramflux_storage::AdoptionRow,
    account: &custody::BornAccount,
) -> Result<bool, SdkError> {
    Ok(local.db.pairing_head()?.is_none()
        && install_store::read_installed(local.root, &installed.account_id)?.as_ref()
            == Some(installed)
        && local.db.pairing_adoption()?.as_ref() == Some(adoption)
        && custody::matches_install(account, installed)?)
}
