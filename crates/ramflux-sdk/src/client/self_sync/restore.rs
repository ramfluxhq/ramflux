// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restored registers wait for an authenticated sibling round before local revision allocation.
use super::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use tokio::time::{Duration, Instant};

const GENERATION: &str = "self-sync/restore-generation";
const QUIET: Duration = Duration::from_secs(30);

pub(crate) struct RefreshClock {
    generation: String,
    since: Instant,
    last_peer: Option<Instant>,
}

impl RamfluxClient {
    /// Called inside the fresh restore activation transaction. These markers are
    /// durable; the monotonic waiting clock restarts conservatively after a reboot.
    pub(crate) fn mark_self_sync_restore_refresh(&self) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let generation = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        db.persist_actor_state(GENERATION, &generation)?;
        *self.self_sync_restore_clock.borrow_mut() = None;
        Ok(())
    }

    pub(super) fn require_self_sync_restore_refresh(&self, _scope: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let Some(generation) = db.load_actor_state::<String>(GENERATION)? else { return Ok(()) };
        let now = Instant::now();
        let mut clock = self.self_sync_restore_clock.borrow_mut();
        let clock = clock.get_or_insert_with(|| RefreshClock {
            generation: generation.clone(),
            since: now,
            last_peer: None,
        });
        if clock.generation != generation {
            *clock = RefreshClock { generation, since: now, last_peer: None };
        }
        if now.duration_since(clock.since) < QUIET || clock.last_peer.is_some() {
            return Err(SdkError::InboundPending(
                "self sync: restored scope needs a sibling refresh".into(),
            ));
        }
        db.remove_actor_state(GENERATION)?;
        Ok(())
    }

    /// An authenticated packet proves a reachable sibling, never a completed
    /// snapshot round. The current profile has no floor-bearing round carrier.
    pub(super) fn note_self_sync_sibling_reachable(
        &self,
        source: &RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        if source == &self.owned_device_identity()? {
            return Ok(());
        }
        let db = self.account_db()?;
        let Some(generation) = db.load_actor_state::<String>(GENERATION)? else { return Ok(()) };
        let now = Instant::now();
        let mut clock = self.self_sync_restore_clock.borrow_mut();
        let clock = clock.get_or_insert_with(|| RefreshClock {
            generation: generation.clone(),
            since: now,
            last_peer: None,
        });
        if clock.generation != generation {
            *clock = RefreshClock { generation, since: now, last_peer: None };
        }
        clock.last_peer = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use ramflux_protocol::message as g;

    #[tokio::test(start_paused = true)]
    async fn self_sync_restore_does_not_reissue_stale_revision() -> TestResult {
        let own = Fixture::new("self-sync-restore-wait").await?;
        let mute = || g::SelfSync { operation: 6, revision: 1, mute: true, ..Default::default() };
        assert_eq!(own.client.change_self_sync("c", mute())?.revision, 1);
        let db = own.client.account_db()?;
        db.write_transaction(|| own.client.mark_self_sync_restore_refresh())?;
        assert!(matches!(
            own.client.change_self_sync("c", mute()),
            Err(SdkError::InboundPending(_))
        ));
        assert!(matches!(
            own.client.change_self_sync("new-after-restore", mute()),
            Err(SdkError::InboundPending(_))
        ));
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(matches!(
            own.client.change_self_sync("c", mute()),
            Err(SdkError::InboundPending(_))
        ));
        assert_eq!(own.client.self_sync_state("c", &mute())?.ok_or("state")?.value.revision, 1);
        let scope = db.actor_state_keys("self-sync/state/")?.into_iter().next().ok_or("scope")?;
        db.write_transaction(|| own.client.remember_self_sync_revision("c", &scope, 20))?;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(own.client.change_self_sync("c", mute())?.revision, 21);
        // A process restart cannot reuse the elapsed clock for a later restore.
        db.write_transaction(|| own.client.mark_self_sync_restore_refresh())?;
        assert!(matches!(
            own.client.change_self_sync("c", mute()),
            Err(SdkError::InboundPending(_))
        ));
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn self_sync_restore_restart_at_twenty_nine_seconds_restarts_the_barrier() -> TestResult {
        let mut own = Fixture::new("self-sync-restore-restart").await?;
        let mute = || g::SelfSync { operation: 6, revision: 1, mute: true, ..Default::default() };
        own.client.account_db()?.write_transaction(|| own.client.mark_self_sync_restore_refresh())?;
        assert!(matches!(own.client.change_self_sync("new-scope", mute()), Err(SdkError::InboundPending(_))));
        tokio::time::advance(Duration::from_secs(29)).await;
        let account = own.client.account_db()?.local_account_id.clone();
        own.client.active_account_db = None;
        own.client.unlock_account(&account, b"native fixture data passphrase")?;
        assert!(matches!(own.client.change_self_sync("another-new-scope", mute()), Err(SdkError::InboundPending(_))));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(own.client.change_self_sync("another-new-scope", mute()), Err(SdkError::InboundPending(_))));
        tokio::time::advance(Duration::from_secs(29)).await;
        assert_eq!(own.client.change_self_sync("another-new-scope", mute())?.revision, 1);
        Ok(())
    }

}
