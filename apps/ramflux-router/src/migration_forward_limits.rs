// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared per-destination permits for committed submissions and migration drain work.
use std::sync::{Arc, Mutex, OnceLock, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

type Peers = std::collections::BTreeMap<String, Weak<Semaphore>>;
pub(crate) fn acquire(peer: &str) -> Result<OwnedSemaphorePermit, TryAcquireError> {
    static PEERS: OnceLock<Mutex<Peers>> = OnceLock::new();
    let mut peers =
        PEERS.get_or_init(Mutex::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    peers.retain(|_, semaphore| semaphore.strong_count() > 0);
    let semaphore = peers.get(peer).and_then(Weak::upgrade).unwrap_or_else(|| {
        let semaphore = Arc::new(Semaphore::new(4));
        peers.insert(peer.into(), Arc::downgrade(&semaphore));
        semaphore
    });
    semaphore.try_acquire_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn migration_forward_limit_is_four_per_peer_and_releases_on_drop() -> anyhow::Result<()> {
        let permits: Vec<_> =
            (0..4).map(|_| super::acquire("limit-A")).collect::<Result<_, _>>()?;
        assert!(super::acquire("limit-A").is_err());
        let other = super::acquire("limit-B")?;
        drop(permits);
        drop(super::acquire("limit-A")?);
        drop(other);
        Ok(())
    }
}
