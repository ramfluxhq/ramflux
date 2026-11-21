// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub mod a2i;
pub mod account;
mod account_authority;
pub(crate) mod attachment_diagnostics;
pub(crate) mod attachment_roster;
mod backup_activation;
mod backup_contacts;
pub(crate) mod call;
pub mod contact;
pub(crate) mod contact_requests;
pub(crate) mod contact_resolution;
pub(crate) mod contact_roots;
mod contact_safety_preview;
pub(crate) mod contact_verification_cas;
pub mod conversation;
pub(crate) mod conversation_projection;
mod deferred_attachment;
pub(crate) mod manifest_demand;
pub(crate) use deferred_attachment::job::{FetchBinding, FetchFence, FetchPreparation};
pub(crate) mod agent_custody;
pub(crate) mod agent_custody_calls;
pub(crate) mod application_outbox;
mod authored_delete;
mod authored_send;
#[cfg(test)]
mod authored_send_owner_tests;
pub(crate) mod delivery_receipts;
pub mod dm;
pub mod dm_session;
pub mod federation;
pub(crate) mod generated_call;
mod generated_capacity;
pub(crate) mod generated_content;
pub(crate) mod generated_control;
mod generated_delete_fence;
mod generated_edit_retirement;
mod generated_fields;
pub(crate) mod generated_group;
mod generated_history;
mod generated_identity;
mod generated_pending_edit;
mod generated_receipts;
mod generated_restore;
pub(crate) mod generated_surface;
pub mod group;
mod group_control_roots;
pub mod group_delivery;
mod group_distribution_auth;
mod group_identity;
mod group_key_safety;
#[cfg(test)]
#[cfg(test)]
pub(crate) mod group_quarantine;
pub mod group_session;
pub mod home_migration;
pub mod identity;
pub mod identity_authority;
pub(crate) mod inbox_failure;
#[cfg(test)]
mod legacy_activation_guard_tests;
pub mod mcp_a2ui;
pub(crate) mod message_mutations;
mod native_branch;
mod native_safety;
#[cfg(test)]
pub(crate) mod native_test_support;
pub mod object;
mod own_contact;
pub(crate) mod own_device_copy;
mod own_device_group_pins;
mod own_device_group_state;
pub mod own_device_sync;
mod own_group_lazy_authority;
mod own_sent_delivery;
pub(crate) mod own_sent_message;
mod private_prekeys;
pub(crate) mod raw_inner_origin;
mod raw_inner_reparse;
mod receipt_bindings;
pub mod recovery;
pub use raw_inner_reparse::ReparseProgress;
mod generated_updates;
pub(crate) mod reply_outbox;
pub(crate) mod routed;
pub mod self_sync;
pub(crate) mod shared_group;
pub mod storage;
pub(crate) mod surface;
pub(crate) mod target_selection;
pub(crate) mod task;
pub mod typed_messages;
pub mod typed_read_model;
pub mod typing;
mod unsupported_view;

#[cfg(test)]
mod activation_guard_tests;

use crate::prelude::*;

type HeldManifests = std::cell::RefCell<BTreeMap<String, crate::SdkDeviceManifestResponse>>;

pub struct RamfluxClient {
    pub(crate) typing_receiver: std::cell::RefCell<typing::TypingReceiver>,
    pub(crate) typing_sender: std::cell::RefCell<typing::sender::TypingSender>,
    pub(crate) self_sync_live_generation: std::cell::Cell<Option<u64>>,
    pub(crate) self_sync_restore_clock:
        std::cell::RefCell<Option<self_sync::restore::RefreshClock>>,
    pub(crate) native_head_freshness: std::cell::RefCell<identity_authority::NativeHeadFreshness>,
    pub(crate) manifest_demand: manifest_demand::ManifestDemand,
    /// Test scaffolding only, true by default in tests: fixtures that build a peer's input by
    /// sealing do not run the sender's per-send authority fetch. Tests of send authorization set
    /// it false first. Compiled only for tests and the `test-support` feature, which production
    /// and release builds refuse.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) scaffold_seal_without_fetch: std::cell::Cell<bool>,
    pub(crate) verified_authority_cache:
        std::cell::RefCell<identity_authority::VerifiedAuthorityCache>,
    pub(crate) verified_durable_authority: std::cell::RefCell<crate::custody::PublicAuthorityCache>,
    pub(crate) born_v3_account: Option<Box<crate::custody::BornAccount>>,
    pub(crate) born_v3_vault: Option<std::sync::Arc<dyn crate::custody::PrimaryVault>>,
    // Fetched compare material. Preview keeps it here; only a successful CAS commit stores it.
    pub(crate) held_manifests: HeldManifests,
    pub(crate) voice_calls: BTreeMap<String, call::state::LiveCall>,
    // One account-owned plan crosses the synchronous receive transaction's commit boundary.
    // It is never shared across accounts, held over an await, or serialized with media secrets.
    pub(crate) voice_transition: std::cell::RefCell<Option<(String, Box<call::state::LiveCall>)>>,
    pub(crate) node_relay_options: Option<crate::object::RelayTransferOptions>,
    pub(crate) profile_read_cache:
        std::cell::RefCell<Option<Box<identity_authority::profile_read::ProfileReadCache>>>,
    pub(crate) identity_root: Option<IdentityRoot>,
    pub(crate) reader_device_identity: Option<ramflux_crypto::RootQualifiedDeviceRef>,
    // Public authority files are read directly; readers never open the mutable index.
    pub(crate) reader_account_root: Option<PathBuf>,
    pub(crate) device_branch: Option<DeviceBranch>,
    pub(crate) account_index: Option<AccountIndex>,
    pub(crate) vault_secret_source: Option<Box<dyn VaultSecretSource>>,
    pub(crate) vault_secret_source_is_custom: bool,
    pub(crate) active_account_db: Option<AccountDb>,
    pub(crate) object_store: ObjectStore,
    /// Production stays `None`. A send with prepares then returns `authority_unavailable`.
    pub(crate) attachment_plane: Option<std::sync::Arc<dyn crate::attachment_send::Plane>>,
    /// Set only while one attachment message is being authored; binds its grants to the id.
    pub(crate) attachment_binding: Option<crate::attachment_send::Binding>,
    pub(crate) mcp_registry: McpRegistry,
    pub(crate) federation_mesh: FederationMesh,
    #[cfg(test)]
    pub(crate) native_bus_fixture: Option<Box<native_test_support::bus::Material>>,
}

impl Default for RamfluxClient {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            native_bus_fixture: None,
            typing_receiver: std::cell::RefCell::default(),
            typing_sender: std::cell::RefCell::default(),
            self_sync_live_generation: std::cell::Cell::new(None),
            self_sync_restore_clock: std::cell::RefCell::default(),
            native_head_freshness: std::cell::RefCell::default(),
            manifest_demand: manifest_demand::ManifestDemand::default(),
            #[cfg(any(test, feature = "test-support"))]
            scaffold_seal_without_fetch: std::cell::Cell::new(true),
            verified_authority_cache: std::cell::RefCell::default(),
            verified_durable_authority: std::cell::RefCell::default(),
            born_v3_account: None,
            born_v3_vault: None,
            held_manifests: std::cell::RefCell::new(BTreeMap::new()),
            voice_calls: BTreeMap::new(),
            voice_transition: std::cell::RefCell::new(None),
            node_relay_options: None,
            profile_read_cache: std::cell::RefCell::new(None),
            identity_root: None,
            reader_device_identity: None,
            reader_account_root: None,
            device_branch: None,
            account_index: None,
            vault_secret_source: None,
            vault_secret_source_is_custom: false,
            active_account_db: None,
            object_store: ObjectStore::new(),
            attachment_plane: None,
            attachment_binding: None,
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

mod own_device_history_authority;
