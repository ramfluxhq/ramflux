// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon device-secret store. Items live in the session default Secret Service collection.
//! No file is written. The collection is never created or unlocked. Prompt timeout is zero.

use std::collections::HashMap;

use dbus_secret_service::{Collection, EncryptionType, Item, SearchItemsResult, SecretService};
use ramflux_crypto::custody::{AgentMasterRequest, MasterKey, SelfSigningKey};
use ramflux_protocol::custody::{Envelope, MasterCertificate};
use zeroize::Zeroizing;

use super::super::agent_master_item::{self, AgentMasterCells};
use super::super::{BranchCredentials, PrimaryVault};
use crate::SdkError;
use crate::custody::CustodyVaultReason;

const SERVICE: &str = "ramflux.device-held.v1";
const LABEL: &str = "Ramflux device secret";
const SCHEMA: &str = "org.freedesktop.Secret.Generic";
const CONTENT_TYPE: &str = "application/octet-stream";
const MAX_SECRET: usize = 8192;
const MAX_REFERENCE: usize = 256;
const CLASS: &str = "software_secret_service";

/// Session default collection. One item per vault reference. Insert never overwrites.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxDesktopVault;

enum Hit<'a> {
    Absent,
    One(Item<'a>),
    Locked,
    Corrupt,
}

fn reason(reason: CustodyVaultReason) -> SdkError {
    SdkError::CustodyVault(reason)
}

fn reference_ok(reference: &str) -> Result<(), SdkError> {
    let usable = !reference.is_empty()
        && reference.len() <= MAX_REFERENCE
        && reference.bytes().all(|byte| (0x20..0x7f).contains(&byte));
    if usable { Ok(()) } else { Err(SdkError::CustodyVaultUnavailable) }
}

fn secret_ok(secret: &[u8]) -> Result<(), SdkError> {
    if secret.is_empty() || secret.len() > MAX_SECRET {
        Err(SdkError::CustodyVaultUnavailable)
    } else {
        Ok(())
    }
}

fn attributes(reference: &str) -> HashMap<String, String> {
    HashMap::from([
        ("xdg:schema".to_owned(), SCHEMA.to_owned()),
        ("service".to_owned(), SERVICE.to_owned()),
        ("account".to_owned(), reference.to_owned()),
    ])
}

fn view(owned: &HashMap<String, String>) -> HashMap<&str, &str> {
    owned.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect()
}

fn map_name(name: Option<&str>) -> SdkError {
    let name = name.unwrap_or("");
    if name.ends_with("ServiceUnknown")
        || name.ends_with("NameHasNoOwner")
        || name.ends_with("NoServer")
        || name.ends_with("Disconnected")
    {
        reason(CustodyVaultReason::Unavailable)
    } else if name.ends_with("AccessDenied") || name.ends_with("AuthFailed") {
        reason(CustodyVaultReason::Permission)
    } else if name.ends_with("Locked") {
        reason(CustodyVaultReason::Locked)
    } else {
        reason(CustodyVaultReason::Unavailable)
    }
}

fn map_ss(error: dbus_secret_service::Error) -> SdkError {
    use dbus_secret_service::Error as StoreError;
    match error {
        StoreError::Locked | StoreError::Prompt => reason(CustodyVaultReason::Locked),
        StoreError::Dbus(error) => map_name(error.name()),
        StoreError::Crypto(_)
        | StoreError::Parse
        | StoreError::Path(_)
        | StoreError::UnsupportedSecretFormat => reason(CustodyVaultReason::Corrupt),
        _ => reason(CustodyVaultReason::Unavailable),
    }
}

fn access<T>(
    op: impl FnOnce(&SecretService, &Collection<'_>) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let service =
        SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0).map_err(map_ss)?;
    let collection = service.get_default_collection().map_err(map_ss)?;
    if collection.is_locked().map_err(map_ss)? {
        return Err(reason(CustodyVaultReason::Locked));
    }
    op(&service, &collection)
}

fn same_membership(local: &[Item<'_>], wide: &SearchItemsResult<Item<'_>>) -> bool {
    let Some(wide_count) = wide.unlocked.len().checked_add(wide.locked.len()) else {
        return false;
    };
    wide_count == local.len()
        && wide
            .unlocked
            .iter()
            .chain(wide.locked.iter())
            .all(|item| local.iter().any(|local_item| local_item.path == item.path))
}

fn classify<'item>(
    service: &SecretService,
    collection: &'item Collection<'_>,
    reference: &str,
) -> Result<Hit<'item>, SdkError> {
    let owned = attributes(reference);
    let queried = view(&owned);
    let wide = service.search_items(queried.clone()).map_err(map_ss)?;
    let local = collection.search_items(queried).map_err(map_ss)?;
    if !same_membership(&local, &wide) || local.len() > 1 {
        return Ok(Hit::Corrupt);
    }
    let Some(item) = local.into_iter().next() else {
        return Ok(Hit::Absent);
    };
    let locked_wide = wide.locked.iter().any(|other| other.path == item.path);
    let locked = locked_wide || item.is_locked().map_err(map_ss)?;
    if locked { Ok(Hit::Locked) } else { Ok(Hit::One(item)) }
}

fn insert(reference: &str, secret: &[u8]) -> Result<(), SdkError> {
    reference_ok(reference)?;
    secret_ok(secret)?;
    access(|service, collection| match classify(service, collection, reference)? {
        Hit::Absent => {
            let owned = attributes(reference);
            collection
                .create_item(LABEL, view(&owned), secret, false, CONTENT_TYPE)
                .map_err(map_ss)?;
            Ok(())
        }
        Hit::One(_) => Err(SdkError::CustodyVaultUnavailable),
        Hit::Locked => Err(reason(CustodyVaultReason::Locked)),
        Hit::Corrupt => Err(reason(CustodyVaultReason::Corrupt)),
    })
}

fn load(reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    reference_ok(reference)?;
    access(|service, collection| match classify(service, collection, reference)? {
        Hit::One(item) => {
            let secret = Zeroizing::new(item.get_secret().map_err(map_ss)?);
            if secret.is_empty() || secret.len() > MAX_SECRET {
                Err(reason(CustodyVaultReason::Corrupt))
            } else {
                Ok(secret)
            }
        }
        Hit::Absent => Err(SdkError::CustodyVaultUnavailable),
        Hit::Locked => Err(reason(CustodyVaultReason::Locked)),
        Hit::Corrupt => Err(reason(CustodyVaultReason::Corrupt)),
    })
}

fn remove(reference: &str) -> Result<(), SdkError> {
    reference_ok(reference)?;
    access(|service, collection| match classify(service, collection, reference)? {
        Hit::Absent => Ok(()),
        Hit::One(item) => item.delete().map_err(map_ss),
        Hit::Locked => Err(reason(CustodyVaultReason::Locked)),
        Hit::Corrupt => Err(reason(CustodyVaultReason::Corrupt)),
    })
}

fn array_from<const N: usize>(bytes: &Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; N]>, SdkError> {
    let Ok(array) = <[u8; N]>::try_from(bytes.as_slice()) else {
        return Err(SdkError::CustodyVaultUnavailable);
    };
    Ok(Zeroizing::new(array))
}

struct Cells;

impl AgentMasterCells for Cells {
    fn read_item(&self, reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        match load(reference) {
            Ok(value) => Ok(Some(value)),
            Err(SdkError::CustodyVaultUnavailable) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn insert_item(&self, reference: &str, value: &[u8]) -> Result<(), SdkError> {
        insert(reference, value)
    }

    fn remove_item(&self, reference: &str) -> Result<(), SdkError> {
        remove(reference)
    }
}

impl PrimaryVault for LinuxDesktopVault {
    fn vault_class(&self) -> &'static str {
        CLASS
    }

    fn preflight(&self) -> Result<(), SdkError> {
        access(|_service, _collection| Ok(()))
    }

    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        insert(reference, &*key.vault_seed())
    }

    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        let seed = array_from::<32>(&load(reference)?)?;
        Ok(SelfSigningKey::from_vault_seed(&seed))
    }

    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        if reference.starts_with(ramflux_storage::FileVaultSecretSource::OWNER_PREFIX) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        remove(reference)
    }

    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        insert(reference, seeds.as_slice())
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        let seeds = array_from::<64>(&load(reference)?)?;
        BranchCredentials::from_vault_seeds(principal, device, &seeds)
    }

    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        insert(reference, secret)
    }

    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        load(reference)
    }

    fn store_agent_master(&self, reference: &str, master: &MasterKey) -> Result<(), SdkError> {
        agent_master_item::store(&Cells, reference, master)
    }

    fn certify_agent_master(
        &self,
        reference: &str,
        request: AgentMasterRequest,
    ) -> Result<Envelope<MasterCertificate>, SdkError> {
        agent_master_item::certify(&Cells, reference, request)
    }

    fn delete_agent_master(&self, reference: &str, last_range: u64) -> Result<(), SdkError> {
        agent_master_item::delete(&Cells, reference, last_range)
    }
}
