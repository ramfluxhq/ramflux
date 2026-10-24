// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client-local storage primitives for MVP-1 multi-account tests.

mod account_db;
mod account_index;
mod clock;
mod constants;
mod conversation_helpers;
mod database;
mod encryption;
mod error;
mod event_store;
mod group_permissions;
mod history_hash;
mod records;
mod row_mappers;
mod schema;
mod schema_device_namespace;
mod schema_group_control_identity;
mod schema_group_sender_identity;
mod schema_identity_keys;
mod schema_receipt_identity;

pub use account_db::AccountDb;
pub use account_db::journal::{
    InboxFailurePolicy, InboxFailureSource, JournalBounds, JournalEvent,
};
pub use account_db::runtime::AccountOutboxEntry;
pub use account_index::AccountIndex;
pub use clock::{AccountClock, unix_now};
pub use constants::*;
pub use encryption::{
    AccountDbKey, AccountKeyWrappingProvider, EncryptionMode, FileVaultSecretSource,
    LocalVaultKeyWrappingProvider, VaultSecretSource, WrappedAccountDbKey,
    unwrap_with_vault_secret, wrap_with_vault_secret,
};
pub use error::StorageError;
pub use event_store::{EventStore, ProjectionStore};
pub use records::*;

#[cfg(test)]
mod tests;
