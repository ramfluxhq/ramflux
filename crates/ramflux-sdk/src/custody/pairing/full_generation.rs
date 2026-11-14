// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! G2 metadata comparison only. Actual union verification and generation selection are separate.
use super::install_store::{FullInstall, Install};
use crate::SdkError;
use ramflux_protocol::{canonical_json_bytes, parse_i_json};
use ramflux_storage::{AccountGenerationSelection, AccountIndex, AdoptionRow};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

pub mod owner;
mod refresh;
pub(crate) use refresh::has_selected as has_selected_full_generation;
pub(crate) use refresh::preserve as preserved_refresh_adoption;
const LIMIT: usize = 4096;
fn pending() -> SdkError {
    SdkError::PairingCode("PublicationPending")
}

/// Full-profile extension of the existing native-data generation recovery marker.
/// It remains local and contains no key/credential. A legacy three-field marker cannot
/// stand in for this object. It does not attest to union bytes merely by being decoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullGenerationManifest {
    pub schema: String,
    pub local_account_id: String,
    pub account_anchor: String,
    pub origin: String,
    pub operation_id: String,
    pub record_hash: String,
    pub full_transfer: FullInstall,
}
impl FullGenerationManifest {
    /// Construct the exact G2 recovery object from a validated complete full Install.
    /// The generation installer still owns prior-generation recheck and verified bytes.
    /// # Errors
    /// Refuses legacy/incomplete installs, invalid fields or the existing bounded layout.
    pub fn for_install(install: &Install) -> Result<Self, SdkError> {
        install.validate()?;
        let value = Self {
            schema: "ramflux.local.native_data_generation.v1".into(),
            local_account_id: install.account_id.clone(),
            account_anchor: install.account_anchor.clone(),
            origin: "full_transfer".into(),
            operation_id: install.operation_id.clone(),
            record_hash: install.record_hash.clone().ok_or_else(pending)?,
            full_transfer: install.full_transfer.clone().ok_or_else(pending)?,
        };
        value.encode()?;
        Ok(value)
    }
    /// Encode the closed canonical, bounded local G2 marker.
    /// # Errors
    /// Refuses invalid marker fields or oversized metadata.
    pub fn encode(&self) -> Result<Vec<u8>, SdkError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| pending())?;
        if bytes.len() > LIMIT {
            return Err(pending());
        }
        Ok(bytes)
    }
    /// Decode only the complete full-profile marker; no legacy fallback.
    /// # Errors
    /// Refuses missing/unknown/duplicate fields, noncanonical bytes and oversized metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, SdkError> {
        if bytes.len() > LIMIT {
            return Err(pending());
        }
        let value: Self = parse_i_json(bytes).map_err(|_| pending())?;
        if value.encode()?.as_slice() != bytes {
            return Err(pending());
        }
        Ok(value)
    }
    fn validate(&self) -> Result<(), SdkError> {
        if self.schema != "ramflux.local.native_data_generation.v1"
            || self.origin != "full_transfer"
        {
            return Err(pending());
        }
        // Reuse the same exact local ID/hash/path policy as the Install codec.
        super::install_store::ident(&self.local_account_id, "local_account_id")?;
        for (hash, field) in [
            (&self.account_anchor, "account_anchor"),
            (&self.operation_id, "operation_id"),
            (&self.record_hash, "record_hash"),
        ] {
            super::install_store::b32(hash, field)?;
        }
        self.full_transfer.validate()
    }
}

pub(crate) fn require_selected_full_generation(
    root: &Path,
    install: &Install,
    adoption: &AdoptionRow,
) -> Result<(), SdkError> {
    let selected = AccountIndex::open(root)?.account_generation_selection(&install.account_id)?;
    compare_selected_full_generation(install, adoption, selected)
}

/// Native-file load checks local G3 metadata; the network owner must additionally
/// supply the adoption row read from its actual opened database.
pub(crate) fn require_installed_native_generation(
    root: &Path,
    account: &crate::custody::BornAccount,
    install: &Install,
) -> Result<(), SdkError> {
    let adoption = if install.full_transfer.is_some() {
        super::activate::adoption(install)?
    } else {
        refresh::expected(root, install)?
    };
    require_completed_full_generation(root, account, install, &adoption)
}

/// Completed G3 admission requires every durable local owner to agree. A decoded
/// marker alone never supplies the caller's actual selected-database adoption row.
pub(crate) fn require_completed_full_generation(
    root: &Path,
    account: &crate::custody::BornAccount,
    install: &Install,
    adoption: &AdoptionRow,
) -> Result<(), SdkError> {
    if account.authority_blocked()
        || install.state != "installed"
        || super::install_store::pending_blocks_network(
            &super::install_store::list_pending(root, &install.account_id)?,
            Some(install),
        )
    {
        return Err(pending());
    }
    if install.full_transfer.is_some() {
        if super::activate::adoption(install)? != *adoption
            || !crate::custody::matches_generation_install(account, install)?
        {
            return Err(pending());
        }
        require_selected_full_generation(root, install, adoption)
    } else {
        if !crate::custody::matches_install(account, install)? {
            return Err(pending());
        }
        refresh::require(root, install, adoption)
    }
}

fn compare_selected_full_generation(
    install: &Install,
    adoption: &AdoptionRow,
    mut selected: AccountGenerationSelection,
) -> Result<(), SdkError> {
    let full = install.full_transfer.as_ref().ok_or_else(pending)?;
    let bytes = Zeroizing::new(selected.manifest_json.take().ok_or_else(pending)?);
    let manifest = FullGenerationManifest::decode(&bytes)?;
    if selected.account.account_state != "active"
        || selected.account.local_account_id != install.account_id
        || selected.account.principal_commitment != install.account_anchor
        || selected.account.db_relative_path != full.db_relative_path
        || selected.account.object_dir_relative_path != full.object_relative_path
        || adoption.account_id != install.account_id
        || adoption.operation_id != install.operation_id
        || adoption.record_hash != install.record_hash.as_deref().ok_or_else(pending)?
        || adoption.full_generation_nonce.as_deref() != Some(full.generation_nonce.as_str())
        || adoption.full_initial_union_root.as_deref() != Some(full.initial_union_root.as_str())
        || manifest != FullGenerationManifest::for_install(install)?
    {
        return Err(pending());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
