// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Completed local G3 owner agreement and the last interrupted cleanup boundaries.
use super::{SdkError, StatusRequest, full_generation, install_store};
use crate::custody::pairing::LocalPairingParticipant;
use ramflux_storage::{AccountDb, FullLocalUnlockGuard};

type Snapshot = (install_store::Install, FullLocalUnlockGuard, bool);
pub(super) fn snapshot(
    local: &LocalPairingParticipant,
    owned: &StatusRequest,
    db: &AccountDb,
) -> Result<Option<Snapshot>, SdkError> {
    let head = db.pairing_head()?;
    let has_head = head.is_some();
    let Some(install) = install_store::read_installed(&local.root, &local.account_id)? else {
        return Ok(None);
    };
    if has_head && !install_store::list_pending(&local.root, &local.account_id)?.is_empty() {
        return Ok(None);
    }
    let Some(adoption) =
        db.pairing_adoption()?.filter(|adoption| adoption.full_generation_nonce.is_some())
    else {
        return Ok(None);
    };
    let selected = ramflux_storage::AccountIndex::open(&local.root)?
        .account_generation_selection(&local.account_id)?;
    let bytes = zeroize::Zeroizing::new(
        selected.manifest_json.ok_or(SdkError::PairingCode("PublicationPending"))?,
    );
    let marker = full_generation::FullGenerationManifest::decode(&bytes)?;
    if marker.operation_id != owned.operation_id {
        return Ok(None);
    }
    local.full_selected_db(db, Some(&install.account_anchor))?;
    if let Some(head) = head {
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == owned.operation_id)
            .ok_or(SdkError::PairingCode("WrongContext"))?;
        if live.role != "responder"
            || live.generation != owned.generation
            || head.operation_id != owned.operation_id
            || head.generation != owned.generation
            || head.state != "acknowledged"
            || head.kind != "transfer"
            || Some(head.candidate_hash.as_str()) != install.record_hash.as_deref()
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
    }
    let now = crate::custody::network_now()?;
    let native = crate::custody::load_data_account(&local.root, &local.account_id, now)?;
    full_generation::require_completed_full_generation(&local.root, &native, &install, &adoption)?;
    Ok(Some((install, db.full_local_unlock_guard()?, has_head)))
}
pub(super) fn finish_interrupted_cleanup(
    local: &LocalPairingParticipant,
    install: &install_store::Install,
    db: &AccountDb,
) -> Result<(), SdkError> {
    local.full_selected_db(db, Some(&install.account_anchor))?;
    let adoption = db.pairing_adoption()?.ok_or(SdkError::PairingCode("PublicationPending"))?;
    let native = crate::custody::load_data_account(
        &local.root,
        &local.account_id,
        crate::custody::network_now()?,
    )?;
    full_generation::require_completed_full_generation(&local.root, &native, install, &adoption)?;
    let mut directory =
        crate::bus::backup_jobs::full_generation::FullGenerationDirectory::recover_selected(
            &local.root,
            install,
        )?;
    directory.finish_g3()?;
    db.retire_full_recipient_install_head(&adoption)?;
    Ok(())
}
