// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! J7 ordered installation. Every partial owner commit leaves a durable admission fence.

use super::install_store::{self, Install};
use crate::{SdkError, custody};
use ramflux_protocol::custody::{CustodyAuthority, object_hash};
use ramflux_storage::{AccountDb, AdoptionRow};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

/// Target-local storage owners for an installation attempt. No network capability.
pub struct Installation<'a> {
    pub root: &'a Path,
    pub db: &'a AccountDb,
    pub vault: &'a dyn custody::PrimaryVault,
    pub now: u64,
}

/// Independently query the native head and activate exactly the acknowledged publication.
/// The provider is the native query path; relay acknowledgements never implement this contract.
pub trait PairingAuthorityQuery: Send + Sync {
    /// # Errors
    /// Returns native query errors without granting ordinary account admission.
    fn current_authority(&self, anchor: &str) -> Result<CustodyAuthority, SdkError>;
}

/// Install an exact independently verified native publication using target-local vault refs.
///
/// # Errors
/// Wrong ACK/head, absent local keys, owner disagreement, or any durable write failure keeps
/// networking closed. Retrying the same operation completes the ordered owner sequence.
pub fn activate_recipient(
    local: &Installation<'_>,
    install: &Install,
    acknowledged_hash: &str,
    query: &dyn PairingAuthorityQuery,
) -> Result<(), SdkError> {
    let authority = query.current_authority(&install.account_anchor)?;
    if object_hash(&authority.publication.record)? != acknowledged_hash {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    install_exact(local, install, acknowledged_hash, &authority)
}

pub(crate) fn install_exact(
    local: &Installation<'_>,
    install: &Install,
    acknowledged_hash: &str,
    authority: &CustodyAuthority,
) -> Result<(), SdkError> {
    let Installation { root, db, vault, now } = *local;
    let _lock = authority_lock(root, &install.account_id)?;
    let saved = install_store::read_pending(root, &install.account_id, &install.operation_id)?;
    let installed = install_store::read_installed(root, &install.account_id)?;
    let mut row = saved
        .or(installed.filter(|row| row.operation_id == install.operation_id))
        .ok_or(SdkError::PairingField("operation_id"))?;
    if row.account_anchor != install.account_anchor
        || row.recipient_ref != install.recipient_ref
        || row.branch_vault_ref != install.branch_vault_ref
        || row.data_vault_ref != install.data_vault_ref
        || row.primary_vault_ref != install.primary_vault_ref
        || row.record_hash.as_deref().is_some_and(|hash| hash != acknowledged_hash)
    {
        return Err(SdkError::PairingCode("HeadChanged"));
    }
    if let Some(head) = db.pairing_head()? {
        if head.operation_id != row.operation_id
            || head.candidate_hash != acknowledged_hash
            || head.state != "acknowledged"
        {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
    } else if row.install_purpose != "authority_refresh" {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    row.record_hash = Some(acknowledged_hash.into());
    custody::verify_pairing_local(&row, authority, vault, now)?;
    row.state = "adopt_prepared".into();
    install_store::write_pending(root, &row)?;
    custody::write_pairing_authority(root, &row, authority, vault, now)?;
    let account = custody::load_data_account(root, &row.account_id, now)?;
    if !custody::matches_install(&account, &row)? {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    custody::verify_pairing_local(&row, authority, vault, now)?;
    row.state = "authority_durable".into();
    install_store::write_pending(root, &row)?;
    db.commit_pairing_install(&adoption(&row)?)?;
    row.state = "installed".into();
    install_store::write_installed(root, &row)?;
    install_store::remove_pending(root, &row.account_id, &row.operation_id)?;
    Ok(())
}

pub(crate) fn adoption(row: &Install) -> Result<AdoptionRow, SdkError> {
    Ok(AdoptionRow {
        account_id: row.account_id.clone(),
        operation_id: row.operation_id.clone(),
        record_hash: row.record_hash.clone().ok_or(SdkError::PairingField("record_hash"))?,
        local_ref: ramflux_protocol::canonical_json_bytes(&row.recipient_ref)?,
        local_role: if row.primary_vault_ref.is_some() { "primary" } else { "secondary" }.into(),
        branch_vault_ref: row.branch_vault_ref.clone(),
        data_vault_ref: row.data_vault_ref.clone(),
        primary_vault_ref: row.primary_vault_ref.clone(),
    })
}

/// Adopt later verified heads through the same retained marker, preserving local key owners.
///
/// # Errors
/// Refuses missing/mismatched keys and leaves an incomplete refresh fenced for retry.
pub fn refresh_authority(
    root: &Path,
    db: &AccountDb,
    vault: &dyn custody::PrimaryVault,
    account_id: &str,
    authority: &CustodyAuthority,
    now: u64,
) -> Result<(), SdkError> {
    let account = custody::load_data_account(root, account_id, now)?;
    let hash = object_hash(&authority.publication.record)?;
    let reference = ramflux_protocol::custody::DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: account.local_device_id()?.into(),
        device_epoch: account
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == account.local_device_id().unwrap_or(""))
            .ok_or(SdkError::PairingCode("HeadChanged"))?
            .device_epoch,
    };
    let is_primary =
        authority.publication.record.body.master_certificate.body.primary_device_ref == reference;
    let pending = install_store::list_pending(root, account_id)?;
    let row = if let Some(row) = pending.iter().find(|row| {
        row.install_purpose == "authority_refresh"
            && row.record_hash.as_deref() == Some(hash.as_str())
    }) {
        row.clone()
    } else {
        if !pending.is_empty() {
            return Err(SdkError::PairingCode("PublicationPending"));
        }
        let row = Install {
            schema: "ramflux.pairing.Install.v2".into(),
            version: 2,
            account_id: account_id.into(),
            account_anchor: reference.account_anchor.clone(),
            operation_id: match db.pairing_head()? {
                Some(head) if head.state == "acknowledged" && head.candidate_hash == hash => {
                    head.operation_id
                }
                Some(_) => return Err(SdkError::PairingCode("PublicationPending")),
                None => ramflux_protocol::encode_base64url(*super::super::random()?),
            },
            recipient_ref: reference,
            recipient_mode: "existing".into(),
            install_purpose: "authority_refresh".into(),
            record_hash: Some(hash.clone()),
            prior_record_hash: Some(object_hash(account.record())?),
            branch_vault_ref: account.branch_vault_ref().into(),
            data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(account_id),
            primary_vault_ref: is_primary.then(|| account.primary_vault_ref().to_owned()),
            state: "adopt_prepared".into(),
            cleanup_ref: None,
            cleanup_owner_ref: None,
        };
        custody::verify_pairing_local(&row, authority, vault, now)?;
        install_store::write_pending(root, &row)?;
        row
    };
    install_exact(&Installation { root, db, vault, now }, &row, &hash, authority)
}

/// Account-scoped process fence. Never held over a network request.
pub(crate) fn authority_lock(root: &Path, id: &str) -> Result<fs::File, SdkError> {
    super::super::valid_id(id)?;
    let path = root.join("custody_accounts").join(id).join(".authority.lock");
    let file = fs::File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(std::io::Error::from)?,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SdkError::PairingCode("Busy"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
}
