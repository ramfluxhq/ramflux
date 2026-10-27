// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Linearize durable setup against disconnect, shutdown and the ceremony deadline.
use crate::SdkError;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

pub(crate) struct CommitGate {
    state: AtomicU8,
    deadline: Instant,
}
impl CommitGate {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self { state: AtomicU8::new(0), deadline }
    }
    pub(crate) fn cancel(&self) {
        let _ = self.state.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }
    pub(super) fn commit(&self) -> Result<(), SdkError> {
        if Instant::now() >= self.deadline {
            self.cancel();
            return Err(SdkError::CustodyExpired);
        }
        self.state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| SdkError::CustodySetupInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn setup_commit_and_disconnect_have_one_winner() -> Result<(), SdkError> {
        let cancelled = CommitGate::new(Instant::now() + Duration::from_secs(60));
        cancelled.cancel();
        assert!(cancelled.commit().is_err());
        let committed = CommitGate::new(Instant::now() + Duration::from_secs(60));
        committed.commit()?;
        committed.cancel();
        assert_eq!(committed.state.load(Ordering::Acquire), 2);
        let expired = CommitGate::new(Instant::now());
        assert!(matches!(expired.commit(), Err(SdkError::CustodyExpired)));
        for _ in 0..100 {
            let gate = Arc::new(CommitGate::new(Instant::now() + Duration::from_secs(60)));
            let other = Arc::clone(&gate);
            let thread = std::thread::spawn(move || other.cancel());
            let committed = gate.commit().is_ok();
            thread.join().map_err(|_| SdkError::CustodySetupInvalid)?;
            assert_eq!(gate.state.load(Ordering::Acquire), if committed { 2 } else { 1 });
        }
        Ok(())
    }
}
