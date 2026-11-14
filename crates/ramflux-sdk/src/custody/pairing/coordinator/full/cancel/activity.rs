// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wake an ordinary driver after local work is queued or an owned async job finishes.
use super::{AtomicBool, FullRuntimeCancel, Ordering};
use std::sync::Arc;
pub(crate) struct Completion {
    finished: Arc<AtomicBool>,
    signal: Arc<tokio::sync::Notify>,
}
impl Completion {
    pub(crate) fn flag(&self) -> Arc<AtomicBool> {
        self.finished.clone()
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        self.signal.notify_one();
    }
}
impl FullRuntimeCancel {
    pub(crate) fn completion(&self) -> Completion {
        Completion { finished: Arc::new(AtomicBool::new(false)), signal: self.activity.clone() }
    }
    pub(crate) fn activity_signal(&self) -> Arc<tokio::sync::Notify> {
        self.activity.clone()
    }
    pub(crate) fn notify_activity(&self) {
        self.activity.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_driver_keeps_completion_wakeup_before_wait_and_on_root_stop()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(async {
            let root = FullRuntimeCancel::default();
            let signal = root.activity_signal();
            let completion = root.completion();
            let finished = completion.flag();
            let job = tokio::spawn(async move {
                let _completion = completion;
                17
            });
            assert_eq!(job.await?, 17, "test: worker did not complete before delayed observer");
            signal.notified().await;
            assert!(
                finished.load(Ordering::Acquire),
                "test: notification preceded the finished predicate"
            );
            root.stop();
            signal.notified().await;
            assert!(root.require_live().is_err(), "test: shutdown wakeup left the old root usable");
            Ok(())
        })
        .await
    }
}
