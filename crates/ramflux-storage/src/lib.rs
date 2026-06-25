//! Client-local storage primitives for MVP-1 multi-account tests.

mod account_db;
mod account_index;
mod clock;
mod constants;
mod conversation_helpers;
mod encryption;
mod error;
mod event_store;
mod group_permissions;
mod history_hash;
mod records;
mod row_mappers;
mod schema;

pub use account_db::AccountDb;
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
