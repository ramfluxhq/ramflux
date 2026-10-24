// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub mod a2i;
pub mod account;
pub mod contact;
pub(crate) mod contact_resolution;
pub(crate) mod contact_roots;
mod contact_safety_preview;
pub mod conversation;
mod deferred_attachment;
pub mod dm;
pub mod dm_session;
pub mod federation;
pub mod group;
pub mod group_delivery;
mod group_identity;
mod group_key_safety;
pub(crate) mod group_quarantine;
pub mod group_session;
pub mod identity;
pub(crate) mod inbox_failure;
pub mod mcp_a2ui;
pub mod object;
pub(crate) mod own_device_copy;
mod own_device_group_pins;
mod own_device_group_restore;
pub mod own_device_sync;
mod own_device_sync_receipts;
pub mod recovery;
pub(crate) mod routed;
pub mod storage;
pub(crate) mod surface;

use crate::prelude::*;

pub struct RamfluxClient {
    pub(crate) node_relay_options: Option<crate::object::RelayTransferOptions>,
    pub(crate) identity_root: Option<IdentityRoot>,
    pub(crate) device_branch: Option<DeviceBranch>,
    pub(crate) account_index: Option<AccountIndex>,
    pub(crate) vault_secret_source: Option<Box<dyn VaultSecretSource>>,
    pub(crate) vault_secret_source_is_custom: bool,
    pub(crate) active_account_db: Option<AccountDb>,
    pub(crate) object_store: ObjectStore,
    pub(crate) mcp_registry: McpRegistry,
    pub(crate) federation_mesh: FederationMesh,
}

impl Default for RamfluxClient {
    fn default() -> Self {
        Self {
            node_relay_options: None,
            identity_root: None,
            device_branch: None,
            account_index: None,
            vault_secret_source: None,
            vault_secret_source_is_custom: false,
            active_account_db: None,
            object_store: ObjectStore::new(),
            mcp_registry: McpRegistry::new(),
            federation_mesh: FederationMesh::new(),
        }
    }
}

impl RamfluxClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn account_index(&self) -> Result<&AccountIndex, SdkError> {
        self.account_index.as_ref().ok_or(SdkError::AccountIndexNotOpen)
    }

    pub(crate) fn account_db(&self) -> Result<&AccountDb, SdkError> {
        self.active_account_db.as_ref().ok_or(SdkError::AccountDbNotUnlocked)
    }

    pub(crate) fn vault_secret_source(&self) -> Result<&dyn VaultSecretSource, SdkError> {
        self.vault_secret_source.as_deref().ok_or(SdkError::AccountIndexNotOpen)
    }
}
