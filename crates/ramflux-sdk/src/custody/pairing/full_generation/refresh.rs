// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Later native heads preserve the immutable data-generation receipt without changing Install.v2.
use super::{FullGenerationManifest, pending};
use crate::{
    SdkError,
    custody::pairing::{
        activate,
        install_store::{self, Install},
    },
};
use ramflux_storage::{AccountDb, AccountGenerationSelection, AccountIndex, AdoptionRow};
use std::path::Path;
use zeroize::Zeroizing;
#[derive(serde::Deserialize)]
struct Origin {
    origin: Option<String>,
}
fn selected(
    root: &Path,
    id: &str,
) -> Result<Option<(FullGenerationManifest, AccountGenerationSelection)>, SdkError> {
    let mut selected = AccountIndex::open(root)?.account_generation_selection(id)?;
    let Some(bytes) = selected.manifest_json.take().map(Zeroizing::new) else { return Ok(None) };
    // Read only the discriminator before closed decoding; another generation
    // profile may contain private metadata that must never enter a generic Value.
    let origin: Origin = ramflux_protocol::parse_i_json(&bytes)?;
    if origin.origin.as_deref() != Some("full_transfer") {
        return Ok(None);
    }
    let manifest = FullGenerationManifest::decode(&bytes)?;
    Ok(Some((manifest, selected)))
}
pub(crate) fn has_selected(root: &Path, id: &str) -> Result<bool, SdkError> {
    Ok(selected(root, id)?.is_some())
}
fn receipt(
    install: &Install,
    manifest: &FullGenerationManifest,
    selected: &AccountGenerationSelection,
) -> Result<AdoptionRow, SdkError> {
    let full = &manifest.full_transfer;
    if install.full_transfer.is_some()
        || install.version != 2
        || !matches!(install.install_purpose.as_str(), "authority_refresh" | "transfer_source")
        || manifest.local_account_id != install.account_id
        || manifest.account_anchor != install.account_anchor
        || selected.account.account_state != "active"
        || selected.account.local_account_id != install.account_id
        || selected.account.principal_commitment != install.account_anchor
        || selected.account.db_relative_path != full.db_relative_path
        || selected.account.object_dir_relative_path != full.object_relative_path
    {
        return Err(pending());
    }
    let mut adoption = activate::adoption(install)?;
    adoption.full_generation_nonce = Some(full.generation_nonce.clone());
    adoption.full_initial_union_root = Some(full.initial_union_root.clone());
    Ok(adoption)
}
pub(super) fn expected(root: &Path, install: &Install) -> Result<AdoptionRow, SdkError> {
    let (manifest, selection) = selected(root, &install.account_id)?.ok_or_else(pending)?;
    receipt(install, &manifest, &selection)
}
pub(super) fn require(
    root: &Path,
    install: &Install,
    actual: &AdoptionRow,
) -> Result<(), SdkError> {
    if expected(root, install)? != *actual {
        return Err(pending());
    }
    Ok(())
}
/// Ordinary native refresh may replace mutable role/ref/hash fields only after
/// the same selected generation already completed its original full G3 adoption.
pub(crate) fn preserve(
    root: &Path,
    db: &AccountDb,
    install: &Install,
) -> Result<AdoptionRow, SdkError> {
    let Some(actual) = db.pairing_adoption()? else {
        return if has_selected(root, &install.account_id)? {
            Err(pending())
        } else {
            activate::adoption(install)
        };
    };
    if actual.full_generation_nonce.is_none() && actual.full_initial_union_root.is_none() {
        return if has_selected(root, &install.account_id)? {
            Err(pending())
        } else {
            activate::adoption(install)
        };
    }
    let expected = expected(root, install)?;
    if actual == expected {
        return Ok(expected);
    } // Exact post-adoption crash retry.
    let previous = install_store::read_installed(root, &install.account_id)?.ok_or_else(pending)?;
    if previous.state != "installed" {
        return Err(pending());
    }
    if previous.full_transfer.is_some() {
        if activate::adoption(&previous)? != actual {
            return Err(pending());
        }
        super::require_selected_full_generation(root, &previous, &actual)?;
    } else {
        require(root, &previous, &actual)?;
    }
    Ok(expected)
}
