// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! What the browser store is allowed to claim and how loss is recognised.
//!
//! Storage in a browser is best-effort unless the user agent grants persistence, and loss is
//! always whole-origin. The policy never deletes messages to make room and never opens a
//! database without page-level encryption.

/// Name of the SQLite VFS: OPFS sync access handles, no COOP/COEP requirement, one connection.
pub const OPFS_VFS_NAME: &str = "opfs-sahpool";
/// OPFS directory that holds the pool.
pub const OPFS_POOL_DIRECTORY: &str = ".ramflux-store-v1";
/// Database file name inside the pool.
pub const DATABASE_FILE: &str = "/account.db";
/// IndexedDB record written at first link: "this origin was linked".
pub const SENTINEL_KEY: &str = "linked.v1";
/// The client's own cap on local history. OPEN-VALUE OV-W4.
pub const MAX_HISTORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// OPFS directory of the attachment spool. Swept at start, deleted on abort.
pub const SPOOL_DIRECTORY: &str = "ramflux-spool-v1";
/// Same cap as every other platform.
pub const MAX_SPOOL_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
/// Exactly one SQLite connection per database on this target.
pub const MAX_CONNECTIONS_PER_DATABASE: u32 = 1;
/// SQLCipher page format shared with every other platform.
pub const CIPHER_PAGE_SIZE: u32 = 4096;

/// Answer of `navigator.storage.persisted()` / `persist()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persistence {
    /// The user agent will not evict without the user.
    Persistent,
    /// The request was refused or never granted: the origin may be evicted under pressure.
    BestEffort,
    /// The Storage API is absent (some private modes).
    Unknown,
}

/// What the client tells the user about durability. It never claims more than the user agent did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurabilityClaim {
    /// "Kept on this browser until you clear site data."
    KeptUntilCleared,
    /// "This browser may delete the data; you can always link again."
    MayBeEvicted,
    /// "Storage in this window does not last; link again next time."
    SessionOnly,
}

/// Map the user agent's answers to the claim shown at link time.
#[must_use]
pub const fn durability_claim(persistence: Persistence, opfs_available: bool) -> DurabilityClaim {
    match (persistence, opfs_available) {
        (Persistence::Persistent, true) => DurabilityClaim::KeptUntilCleared,
        (Persistence::BestEffort, true) => DurabilityClaim::MayBeEvicted,
        _ => DurabilityClaim::SessionOnly,
    }
}

/// What was found at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreInventory {
    /// The IndexedDB sentinel exists.
    pub sentinel: bool,
    /// The encrypted database exists in the pool.
    pub database: bool,
    /// The wrapped database key and branch seed exist in IndexedDB.
    pub vault: bool,
}

/// The condition of local state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreCondition {
    /// Nothing exists: a fresh browser.
    NotLinked,
    /// Everything exists.
    Intact,
    /// Any partial state: keys without a database, a database without keys, or a sentinel
    /// without either. The device is lost; fresh state is never created under its identity.
    Lost,
}

/// What the client does about the condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreAction {
    /// Show the link screen.
    OfferLink,
    Open,
    /// Wipe what remains, tell the user, ask them to remove the old web device from a native
    /// device, link again.
    WipeReportAndRelink,
}

/// Classify what was found. Storage is whole-origin, so partial state means loss.
#[must_use]
pub const fn classify(inventory: StoreInventory) -> (StoreCondition, StoreAction) {
    match (inventory.sentinel, inventory.database, inventory.vault) {
        (false, false, false) => (StoreCondition::NotLinked, StoreAction::OfferLink),
        (true, true, true) => (StoreCondition::Intact, StoreAction::Open),
        _ => (StoreCondition::Lost, StoreAction::WipeReportAndRelink),
    }
}

/// Whether a write of `write_bytes` may start, from `navigator.storage.estimate()`. A write is
/// refused when less than twice its size is free; nothing is deleted to make room.
#[must_use]
pub const fn write_allowed(usage: u64, quota: u64, write_bytes: u64) -> bool {
    quota.saturating_sub(usage) >= write_bytes.saturating_mul(2)
}

/// The seam between the policy and whichever SQLite build the S-STORE spike selects. The leader
/// worker holds exactly one implementation and one connection.
pub trait StoreEngine {
    /// Open the database in the `opfs-sahpool` pool with the raw 256-bit key.
    ///
    /// # Errors
    /// Returns [`crate::WebError::StoreUnavailable`] when the engine or the pool is unavailable.
    fn open(&mut self, key: &[u8; 32]) -> Result<CipherProbe, crate::WebError>;
    /// Close the connection and release every sync access handle.
    fn close(&mut self);
}

/// The engine used until S-STORE selects one: the store stays closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStoreEngine;

impl StoreEngine for NoStoreEngine {
    fn open(&mut self, _: &[u8; 32]) -> Result<CipherProbe, crate::WebError> {
        Err(crate::WebError::StoreUnavailable("no encrypted SQLite engine is linked"))
    }

    fn close(&mut self) {}
}

/// Page-level encryption the opened database reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherProbe {
    /// `PRAGMA cipher_version` returned a version and the keyed read succeeded.
    SqlCipher,
    /// The engine has no cipher, or the database opened without the key.
    None,
}

/// A store without page-level encryption stays closed.
///
/// # Errors
/// Returns [`crate::WebError::StoreUnavailable`] when the engine cannot encrypt pages.
pub const fn require_cipher(probe: CipherProbe) -> Result<(), crate::WebError> {
    match probe {
        CipherProbe::SqlCipher => Ok(()),
        CipherProbe::None => {
            Err(crate::WebError::StoreUnavailable("page-level encryption is not available"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_mode_never_claims_persistence() {
        assert_eq!(durability_claim(Persistence::Unknown, false), DurabilityClaim::SessionOnly);
        assert_eq!(durability_claim(Persistence::Persistent, false), DurabilityClaim::SessionOnly);
        assert_eq!(durability_claim(Persistence::BestEffort, true), DurabilityClaim::MayBeEvicted);
    }

    #[test]
    fn any_partial_state_is_loss_and_never_opens_fresh_state() {
        for (sentinel, database, vault) in [
            (false, false, true),
            (true, false, true),
            (true, true, false),
            (true, false, false),
            (false, true, true),
        ] {
            let found = StoreInventory { sentinel, database, vault };
            assert_eq!(classify(found), (StoreCondition::Lost, StoreAction::WipeReportAndRelink));
        }
        let fresh = StoreInventory { sentinel: false, database: false, vault: false };
        assert_eq!(classify(fresh).1, StoreAction::OfferLink);
    }

    #[test]
    fn a_write_needs_twice_its_size_free() {
        assert!(write_allowed(0, 200, 100));
        assert!(!write_allowed(1, 200, 100));
        assert!(!write_allowed(300, 200, 1));
    }

    #[test]
    fn a_plaintext_engine_keeps_the_store_closed() {
        assert!(require_cipher(CipherProbe::None).is_err());
        assert!(require_cipher(CipherProbe::SqlCipher).is_ok());
    }
}
