// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-owned worker completion publishes a private reply before its readiness notification.
use super::{AtomicBool, FullRuntimeCancel, Ordering};
use crate::SdkError;
use std::sync::Arc;
use tokio::{
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
};
pub(crate) struct Joined<T> {
    abort: AbortHandle,
    drained: Option<oneshot::Receiver<()>>,
    receive: Option<oneshot::Receiver<Result<T, SdkError>>>,
    finished: Arc<AtomicBool>,
}
impl<T> Drop for Joined<T> {
    fn drop(&mut self) {
        self.abort.abort();
        // Do not abort the completion owner: it must drain the worker and erase a
        // private result whose receiver has disappeared, including on caller cancellation.
    }
}
impl<T> Joined<T> {
    pub(crate) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    pub(crate) async fn finish(mut self) -> Result<T, SdkError> {
        if !self.finished() {
            return Err(SdkError::PairingCode("Busy"));
        }
        let result = self
            .receive
            .take()
            .ok_or(SdkError::PairingCode("Retired"))?
            .try_recv()
            .map_err(|_| SdkError::PairingCode("Retired"))?;
        if let Some(drained) = self.drained.take() {
            drained.await.map_err(|_| SdkError::PairingCode("Retired"))?;
        }
        result
    }
    pub(crate) async fn abort_and_drain(mut self) {
        self.abort.abort();
        // Close the result owner before waiting, so a late private result is erased
        // inside the root-owned completion task before its drain receipt is sent.
        self.receive.take();
        if let Some(drained) = self.drained.take() {
            let _ = drained.await;
        }
    }
}
impl FullRuntimeCancel {
    pub(crate) fn own_join<T: Send + 'static>(&self, worker: JoinHandle<T>) -> Joined<T> {
        let (send, receive) = oneshot::channel();
        let (drain, drained) = oneshot::channel();
        let done = self.completion();
        let finished = done.flag();
        let abort = worker.abort_handle();
        let completion = tokio::spawn(async move {
            let result = worker.await.map_err(|_| SdkError::PairingCode("Retired"));
            // On a closed receiver SendError owns and drops the private result here,
            // before the readiness flag/notification and completion join are released.
            let _ = send.send(result);
            drop(done);
            let _ = drain.send(());
        });
        self.retain_join_completion(abort.clone(), completion);
        Joined { abort, drained: Some(drained), receive: Some(receive), finished }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct PrivateOutput(Arc<AtomicBool>, zeroize::Zeroizing<[u8; 32]>);
    impl Drop for PrivateOutput {
        fn drop(&mut self) {
            use zeroize::Zeroize as _;
            self.1.zeroize();
            self.0.store(true, Ordering::Release);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_join_owner_signals_only_after_private_result_is_owned()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(async {
            let root = FullRuntimeCancel::default();
            let signal = root.activity_signal();
            let erased = Arc::new(AtomicBool::new(false));
            let private = PrivateOutput(erased.clone(), zeroize::Zeroizing::new([7; 32]));
            let (release, wait) = oneshot::channel();
            let worker = tokio::spawn(async move {
                let _ = wait.await;
                private
            });
            let owned = root.own_join(worker);
            root.settle_local_jobs().await;
            root.notify_activity();
            signal.notified().await;
            assert!(!owned.finished(), "test: an I/O wakeup released an unfinished private owner");
            release.send(()).map_err(|()| "test: worker release closed")?;
            signal.notified().await;
            assert!(owned.finished(), "test: completion notification preceded the private reply");
            let output = owned.finish().await?;
            assert!(
                !erased.load(Ordering::Acquire),
                "test: joined result lost its actual private owner"
            );
            drop(output);
            assert!(
                erased.load(Ordering::Acquire),
                "test: private result did not erase on owner drop"
            );
            Ok(())
        })
        .await
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_join_owner_abort_drains_late_private_output()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(async {
            let root = FullRuntimeCancel::default();
            let erased = Arc::new(AtomicBool::new(false));
            let private = PrivateOutput(erased.clone(), zeroize::Zeroizing::new([9; 32]));
            let (entered, started) = oneshot::channel();
            let worker = tokio::spawn(async move {
                let _private = private;
                let _ = entered.send(());
                std::future::pending::<()>().await;
            });
            let owned = root.own_join(worker);
            started.await?;
            root.stop();
            owned.abort_and_drain().await;
            assert!(
                erased.load(Ordering::Acquire),
                "test: root drain returned with a live private worker output"
            );
            Ok(())
        })
        .await
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_root_drain_retains_a_dropped_async_join_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::bus::credentials::contract_tests::deadline(async {
            let root = FullRuntimeCancel::default();
            let erased = Arc::new(AtomicBool::new(false));
            let private = PrivateOutput(erased.clone(), zeroize::Zeroizing::new([11; 32]));
            let (entered, started) = oneshot::channel();
            let worker = tokio::spawn(async move {
                let _private = private;
                let _ = entered.send(());
                std::future::pending::<()>().await;
            });
            let owned = root.own_join(worker);
            started.await?;
            drop(owned);
            root.stop();
            root.drain_local_jobs().await;
            assert!(
                erased.load(Ordering::Acquire),
                "test: dropped actor callback detached its private output beyond root drain"
            );
            Ok(())
        })
        .await
    }
}
