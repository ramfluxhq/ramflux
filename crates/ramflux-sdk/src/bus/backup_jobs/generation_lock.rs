// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account generation leases exclude cleanup from the entire prepare/commit interval.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Clone, Default)]
pub(crate) struct GenerationLocks(Arc<Mutex<BTreeMap<String, Weak<AtomicBool>>>>);
pub(crate) struct GenerationLease {
    slot: Arc<AtomicBool>,
    // A live lease must keep the canonical-root registry owner alive even when
    // its short-lived creator/service has gone away.
    _owner: GenerationLocks,
}
impl GenerationLocks {
    /// Share one generation owner across backup services and pairing at the same root.
    pub(crate) fn for_root(root: &std::path::Path) -> Result<Self, crate::SdkError> {
        type Slots = Mutex<BTreeMap<String, Weak<AtomicBool>>>;
        type Roots = Mutex<BTreeMap<std::path::PathBuf, Weak<Slots>>>;
        static ROOTS: OnceLock<Roots> = OnceLock::new();
        let root = std::fs::canonicalize(root)?;
        let mut roots = ROOTS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| super::service::refused("interrupted"))?;
        roots.retain(|_, owner| owner.strong_count() > 0);
        let owner = roots.get(&root).and_then(Weak::upgrade).unwrap_or_else(|| {
            let owner = Arc::new(Mutex::new(BTreeMap::new()));
            roots.insert(root, Arc::downgrade(&owner));
            owner
        });
        Ok(Self(owner))
    }
    pub(crate) fn try_acquire(
        &self,
        account: &str,
    ) -> Result<Option<GenerationLease>, crate::SdkError> {
        let mut slots = self.0.lock().map_err(|_| super::service::refused("interrupted"))?;
        slots.retain(|_, slot| slot.strong_count() > 0);
        let slot = slots.get(account).and_then(Weak::upgrade).unwrap_or_else(|| {
            let slot = Arc::new(AtomicBool::new(false));
            slots.insert(account.into(), Arc::downgrade(&slot));
            slot
        });
        Ok(slot
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| GenerationLease { slot, _owner: self.clone() }))
    }
}
impl Drop for GenerationLease {
    fn drop(&mut self) {
        self.slot.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_account_generation_cleanup_is_skipped_until_its_lease_is_released()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("backup-generation-lease");
        let index = ramflux_storage::AccountIndex::open(&root)?;
        index.create_account("alice", "root")?;
        let generation = root.join("accounts/alice/generation_pending");
        std::fs::create_dir_all(&generation)?;
        std::fs::write(generation.join("account.db"), b"prepared encrypted database")?;
        super::super::recovery::mark_install(&generation)?;
        let locks = GenerationLocks::default();
        let lease = locks.try_acquire("alice")?.ok_or("lease")?;
        super::super::recovery::recover_generations(&root, &index, &locks)?;
        assert!(generation.exists());
        drop(lease);
        super::super::recovery::recover_generations(&root, &index, &locks)?;
        assert!(!generation.exists());
        drop(index);
        Ok(())
    }
}

#[cfg(test)]
mod root_tests {
    use super::*;
    #[test]
    fn pairing_and_backup_generation_owners_share_canonical_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("pairing-shared-generation-owner");
        std::fs::create_dir_all(&root)?;
        let backup = GenerationLocks::for_root(&root)?;
        let pairing = GenerationLocks::for_root(&root.join("."))?;
        let lease = backup.try_acquire("acct")?.ok_or("first generation owner")?;
        assert!(
            pairing.try_acquire("acct")?.is_none(),
            "independent service bypassed the generation owner"
        );
        assert!(pairing.try_acquire("other")?.is_some());
        drop(lease);
        assert!(pairing.try_acquire("acct")?.is_some());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
