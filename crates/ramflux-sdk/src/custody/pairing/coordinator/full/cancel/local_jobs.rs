// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-owned completion of blocking work, including a caller dropped before its reply.
use super::FullRuntimeCancel;
use crate::SdkError;
use std::sync::Arc;
use tokio::task::{AbortHandle, JoinHandle};

pub(super) struct LocalJob {
    abort: AbortHandle,
    completion: JoinHandle<()>,
}
impl FullRuntimeCancel {
    /// The root retains a completion owner, never a private result. The caller's receiver
    /// lives within its actor callback. Root shutdown closes that callback/actor state,
    /// then awaits these completions before dropping the actual account data owner.
    pub(crate) async fn run_blocking<T: Send + 'static>(
        self: Arc<Self>,
        work: impl FnOnce() -> Result<T, SdkError> + Send + 'static,
    ) -> Result<T, SdkError> {
        self.require_live()?;
        let (send, receive) = tokio::sync::oneshot::channel();
        let runtime = self.clone();
        #[cfg(test)]
        let frozen = crate::time::test_clock::frozen();
        let worker = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _clock = frozen.map(crate::time::FixedClock::set);
            runtime.require_live()?;
            let value = work()?;
            runtime.require_live()?;
            Ok(value)
        });
        let abort = worker.abort_handle();
        let completion = tokio::spawn(async move {
            let result = worker
                .await
                .map_err(|_| SdkError::PairingCode("Retired"))
                .and_then(std::convert::identity);
            // On caller cancellation the private result drops here, BEFORE completion.
            let _ = send.send(result);
        });
        {
            let mut jobs =
                self.local_jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            jobs.retain(|job| !job.completion.is_finished());
            if self.require_live().is_err() {
                abort.abort();
            }
            jobs.push(LocalJob { abort, completion });
        }
        let value = receive.await.map_err(|_| SdkError::PairingCode("Retired"))??;
        self.require_live()?;
        Ok(value)
    }
    pub(super) fn abort_local_jobs(&self) {
        let jobs = self.local_jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for job in jobs.iter() {
            job.abort.abort();
        }
    }
    /// Call after the retired actor callback/receiver is closed. Never abort a completion
    /// task: it must await and destroy even a detached blocking worker's private output.
    pub(crate) async fn drain_local_jobs(&self) {
        loop {
            let jobs = std::mem::take(
                &mut *self.local_jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            if jobs.is_empty() {
                break;
            }
            for job in jobs {
                job.abort.abort();
                let _ = job.completion.await;
            }
        }
    }
    #[cfg(test)]
    pub(crate) async fn settle_local_jobs(&self) {
        let jobs = std::mem::take(
            &mut *self.local_jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for job in jobs {
            let _ = job.completion.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    #[tokio::test]
    async fn pairing_full_native_clock_is_preserved_across_owned_local_workers()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(async {
            let _clock = crate::time::FixedClock::set(1_700_000_123);
            let root = Arc::new(FullRuntimeCancel::default());
            assert_eq!(
                crate::custody::network_now()?,
                1_700_000_123,
                "test: native status ignored the controlled clock"
            );
            assert_eq!(
                root.clone().run_blocking(crate::custody::network_now).await?,
                1_700_000_123,
                "test: off-loan native work observed another clock"
            );
            root.drain_local_jobs().await;
            Ok(())
        })
        .await
    }
    struct PrivateOutput {
        bytes: zeroize::Zeroizing<[u8; 32]>,
        erased: Arc<AtomicBool>,
    }
    impl Drop for PrivateOutput {
        fn drop(&mut self) {
            use zeroize::Zeroize as _;
            self.bytes.zeroize();
            self.erased.store(true, Ordering::Release);
        }
    }
    #[tokio::test]
    async fn pairing_full_root_drain_reclaims_detached_blocking_private_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Arc::new(FullRuntimeCancel::default());
        let erased = Arc::new(AtomicBool::new(false));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let runtime = root.clone();
        let output_erased = erased.clone();
        let caller = tokio::spawn(async move {
            runtime
                .run_blocking(move || {
                    let output = PrivateOutput {
                        bytes: zeroize::Zeroizing::new([7; 32]),
                        erased: output_erased,
                    };
                    entered.send(()).map_err(|()| SdkError::PairingCode("Retired"))?;
                    wait.recv().map_err(|_| SdkError::PairingCode("Retired"))?;
                    Ok(output)
                })
                .await
        });
        started.await?;
        caller.abort();
        assert!(caller.await.is_err(), "caller cancellation did not close its private receiver");
        root.stop();
        release.send(())?;
        root.drain_local_jobs().await;
        assert!(
            erased.load(Ordering::Acquire),
            "root drain returned before private output erasure"
        );
        assert!(root.local_jobs.lock().map_err(|_| "local jobs")?.is_empty());
        Ok(())
    }
}
