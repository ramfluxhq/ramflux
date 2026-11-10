// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing's native authority-file owner. No seed or credential crosses this boundary.

use super::{BornAccount, CreationState, StoredAuthority, directory, invalid};
use crate::SdkError;
use crate::custody::PrimaryVault;
use crate::custody::pairing::install_store::Install;
use ramflux_crypto::custody::{AuthorityPins, PinOutcome};
use ramflux_protocol::custody::{CustodyAuthority, object_hash};
use std::{fs, path::Path};

pub(crate) fn verify_local(
    install: &Install,
    authority: &CustodyAuthority,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(), SdkError> {
    install.validate()?;
    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
    let body = &verified.envelope().body;
    if body.account_anchor != install.account_anchor
        || install.record_hash.as_deref() != Some(object_hash(verified.envelope())?.as_str())
        || install.recipient_ref.account_anchor != body.account_anchor
    {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    let cert = verified.authorize(&install.recipient_ref, "register", now)?;
    let branch =
        vault.load_branch(&install.branch_vault_ref, &body.principal_id, &install.recipient_ref)?;
    if ramflux_protocol::encode_base64url(branch.signing.signing_key.verifying_key().to_bytes())
        != cert.branch_signing_public_key
        || ramflux_protocol::encode_base64url(branch.agreement.public)
            != cert.agreement_identity_public_key
    {
        return Err(SdkError::PairingCode("VaultUnavailable"));
    }
    if let Some(reference) = &install.primary_vault_ref {
        if body.master_certificate.body.primary_device_ref != install.recipient_ref
            || vault.load_primary(reference)?.public_key()
                != body.master_certificate.body.self_signing_public_key
        {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
    } else if body.master_certificate.body.primary_device_ref == install.recipient_ref {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    if install.data_vault_ref
        != ramflux_storage::FileVaultSecretSource::owner_ref(&install.account_id)
    {
        return Err(SdkError::PairingField("data_vault_ref"));
    }
    Ok(())
}

/// Caller holds the authority lock and has verified independent native head evidence.
pub(crate) fn write_authority(
    root: &Path,
    install: &Install,
    authority: &CustodyAuthority,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(), SdkError> {
    verify_local(install, authority, vault, now)?;
    let dir = directory(root, &install.account_id)?;
    super::genesis::require_owned_reservation(
        root,
        &install.account_id,
        &install.account_anchor,
        &dir,
    )?;
    let verified = ramflux_crypto::custody::verify_publication(authority, now)?;
    let mut stored = if dir.join("authority.json").try_exists()? {
        let current = super::load_data_account(root, &install.account_id, now)?;
        if current.record().body.account_anchor != install.account_anchor
            || current.stored.branch_vault_ref != install.branch_vault_ref
        {
            return Err(invalid());
        }
        let mut stored = current.stored;
        if !matches!(
            stored.pins.observe_with_previous(&verified, Some(&stored.record))?,
            PinOutcome::Advanced | PinOutcome::Unchanged
        ) {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        stored
    } else {
        if install.recipient_mode != "new" || install.prior_record_hash.is_some() {
            return Err(invalid());
        }
        let mut pins = AuthorityPins::default();
        pins.observe(&verified)?;
        pins.discard_retained_records();
        StoredAuthority {
            schema: "ramflux.local.custody_account.v1".into(),
            local_account_id: install.account_id.clone(),
            local_device_id: install.recipient_ref.device_id.clone(),
            state: CreationState::NetworkingPending,
            networking_reason: None,
            networking_node: None,
            capacity_retry_at: None,
            pending_branch: false,
            custody_v3_observed: true,
            primary_vault_ref: String::new(),
            branch_vault_ref: install.branch_vault_ref.clone(),
            vault_class: vault.vault_class().into(),
            record: authority.publication.record.clone(),
            compacted_ids: authority.publication.compacted_ids.clone(),
            custodian_publication: authority.custodian_publication.clone().map(Box::new),
            pins,
            message_layer_sequences: std::collections::BTreeMap::default(),
            custodian_account_id: None,
            agent_provisioning_vault_ref: None,
        }
    };
    stored.record = authority.publication.record.clone();
    stored.compacted_ids.clone_from(&authority.publication.compacted_ids);
    stored.custodian_publication = authority.custodian_publication.clone().map(Box::new);
    stored.primary_vault_ref = install.primary_vault_ref.clone().unwrap_or_default();
    super::super::layer_declaration::remember_sequences(
        &mut stored.message_layer_sequences,
        &stored.record.body.account_anchor,
        &stored.record.body.devices,
    )?;
    let bytes = ramflux_protocol::canonical_json_bytes(&stored)?;
    if bytes.len() > super::MAX_STORED_AUTHORITY_BYTES {
        return Err(invalid());
    }
    let temp = dir.join(format!(
        ".authority-{}",
        ramflux_protocol::encode_base64url(*super::super::random()?)
    ));
    let result = (|| {
        super::create_private_temp(&temp, &bytes)?;
        fs::rename(&temp, dir.join("authority.json"))?;
        fs::File::open(&dir)?.sync_all()?;
        Ok::<_, SdkError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn matches_install(account: &BornAccount, install: &Install) -> Result<bool, SdkError> {
    Ok(object_hash(account.record())?.as_str() == install.record_hash.as_deref().unwrap_or("")
        && account.local_account_id() == install.account_id
        && account.local_device_id()? == install.recipient_ref.device_id
        && account.record().body.account_anchor == install.account_anchor
        && account.branch_vault_ref() == install.branch_vault_ref
        && account.primary_vault_ref() == install.primary_vault_ref.as_deref().unwrap_or(""))
}

pub(super) fn require_installed_marker(root: &Path, account: &BornAccount) -> Result<(), SdkError> {
    use crate::custody::pairing::install_store;
    let id = account.local_account_id();
    if !install_store::list_pending(root, id)?.is_empty() {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    if let Some(row) = install_store::read_installed(root, id)?
        && (row.state != "installed" || !matches_install(account, &row)?)
    {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    Ok(())
}
