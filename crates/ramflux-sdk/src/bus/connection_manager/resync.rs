// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive passes acknowledge only the overflow epoch captured before their pull.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct ResyncState {
    requested: AtomicU64,
    applied: AtomicU64,
}

impl ResyncState {
    pub(crate) fn request(&self) {
        self.requested.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.requested.load(Ordering::Acquire)
    }
    pub(crate) fn needed(&self) -> bool {
        self.epoch() != self.applied.load(Ordering::Acquire)
    }
    pub(crate) fn applied(&self, epoch: u64) {
        self.applied.fetch_max(epoch, Ordering::AcqRel);
    }
}

#[cfg(test)]
pub(crate) type ReceiveProfile =
    std::collections::BTreeMap<&'static str, (usize, std::time::Duration, std::time::Duration)>;

#[cfg(test)]
impl super::ConnectionHandle {
    pub(crate) async fn test_wait_receive(&self, trigger: super::ReceiveTrigger) {
        loop {
            let completed = self.shared.receive_completed.notified();
            if self.test_receive_trace().contains(&(trigger, true)) {
                return;
            }
            completed.await;
        }
    }

    pub(crate) async fn test_observe_sql(
        &self,
    ) -> Result<ramflux_storage::SqlWorkProbe, crate::SdkError> {
        let sender = self.shared.account_work.clone().ok_or(crate::SdkError::NetworkingPending)?;
        crate::bus::couriers::writer::Writer::new(sender, self.generation())
            .apply(|account| Ok(account.client.account_db()?.observe_sql_work()))
            .await
    }
    pub(crate) fn test_record_receive(&self, phase: &'static str, elapsed: std::time::Duration) {
        let mut profile =
            self.shared.receive_profile.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (count, sum, maximum) = profile.entry(phase).or_default();
        *count += 1;
        *sum += elapsed;
        *maximum = (*maximum).max(elapsed);
    }
    pub(crate) fn test_receive_profile(&self) -> ReceiveProfile {
        self.shared
            .receive_profile
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub(crate) fn test_buffer_stats(&self) -> crate::gateway::host_frames::BufferStats {
        *self.shared.buffer_stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(crate) fn test_receive_trace(&self) -> Vec<(super::ReceiveTrigger, bool)> {
        self.shared.receive_trace.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
    pub(crate) fn test_receive_last_error(&self) -> Option<String> {
        self.shared
            .receive_last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::ResyncState;

    #[test]
    fn receive_completion_preserves_an_overflow_during_the_pull() {
        let state = ResyncState::default();
        state.request();
        let pulled = state.epoch();
        state.request();
        state.applied(pulled);
        assert!(state.needed());
        state.applied(state.epoch());
        assert!(!state.needed());
        state.applied(pulled);
        assert!(!state.needed(), "an older completion cannot undo newer progress");
    }
}
