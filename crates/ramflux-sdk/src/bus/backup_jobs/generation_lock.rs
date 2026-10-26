// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-account generation leases exclude cleanup from the entire prepare/commit interval.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Clone, Default)]
pub(super) struct GenerationLocks(Arc<Mutex<BTreeMap<String, Weak<AtomicBool>>>>);
pub(super) struct GenerationLease(Arc<AtomicBool>);
impl GenerationLocks {
    pub(super) fn try_acquire(
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
            .map(|_| GenerationLease(slot)))
    }
}
impl Drop for GenerationLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
