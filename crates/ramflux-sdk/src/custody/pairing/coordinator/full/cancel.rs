// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immediate root-owner fence, independent of the async actor mutex.
use crate::SdkError;
use ramflux_storage::FullStageIoCancel;
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};

mod local_jobs;

#[derive(Default)]
pub(crate) struct FullRuntimeCancel {
    stopped: AtomicBool,
    stopped_signal: tokio::sync::Notify,
    local_workers: Mutex<usize>,
    local_jobs: Mutex<Vec<local_jobs::LocalJob>>,
    idle: Condvar,
    stage: Mutex<Option<FullStageIoCancel>>,
    tail_stages: Mutex<Vec<FullStageIoCancel>>,
    preparation: Mutex<Option<ramflux_storage::FullSourcePreparationCancel>>,
    job: Mutex<Option<tokio::task::AbortHandle>>,
}
/// A synchronous local key/DB use only. Never hold this permit across an await.
pub(crate) struct FullLocalWork<'a>(&'a FullRuntimeCancel);
impl Drop for FullLocalWork<'_> {
    fn drop(&mut self) {
        let mut workers =
            self.0.local_workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *workers -= 1;
        self.0.idle.notify_all();
    }
}
impl FullRuntimeCancel {
    pub(crate) fn local_work(&self) -> Result<FullLocalWork<'_>, SdkError> {
        let mut workers =
            self.local_workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.require_live()?;
        *workers = workers.checked_add(1).ok_or(SdkError::PairingCode("Busy"))?;
        Ok(FullLocalWork(self))
    }
    /// Local workers do no async/network work while counted. Their key/DB owners must
    /// drop before a root lock/removal returns, including detached `spawn_blocking` work.
    pub(crate) fn drain_local_work(&self) {
        let mut workers =
            self.local_workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.idle.notify_all();
        while *workers != 0 {
            workers = self.idle.wait(workers).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.stopped_signal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
    pub(crate) fn require_live(&self) -> Result<(), SdkError> {
        if self.stopped.load(Ordering::Acquire) {
            Err(SdkError::PairingCode("Retired"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn register_preparation(
        &self,
        preparation: ramflux_storage::FullSourcePreparationCancel,
    ) -> Result<(), SdkError> {
        let mut slot = self.preparation.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = self.require_live() {
            preparation.cancel();
            return Err(error);
        }
        if let Some(old) = slot.replace(preparation) {
            old.cancel();
        }
        Ok(())
    }
    pub(crate) fn stage_owner(&self) -> Result<FullStageIoCancel, SdkError> {
        self.require_live()?;
        self.stage
            .lock()
            .map_err(|_| SdkError::PairingCode("Busy"))?
            .as_ref()
            .cloned()
            .ok_or(SdkError::PairingCode("WrongContext"))
    }
    pub(crate) fn register_stage(&self, stage: FullStageIoCancel) -> Result<(), SdkError> {
        let mut slot = self.stage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = self.require_live() {
            stage.cancel();
            return Err(error);
        }
        if let Some(old) = slot.replace(stage) {
            old.cancel();
        }
        Ok(())
    }
    pub(crate) fn register_tail_stage(&self, stage: FullStageIoCancel) -> Result<(), SdkError> {
        let mut stages = self.tail_stages.lock().map_err(|_| SdkError::PairingCode("Busy"))?;
        if let Err(error) = self.require_live() {
            stage.cancel();
            return Err(error);
        }
        stages.retain(|stage| !stage.is_cancelled());
        if stages.len() >= 3 {
            stage.cancel();
            return Err(SdkError::PairingCode("TransferCapacity"));
        }
        stages.push(stage);
        Ok(())
    }
    pub(crate) fn register_job(&self, job: tokio::task::AbortHandle) -> Result<(), SdkError> {
        let mut slot = self.job.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = self.require_live() {
            job.abort();
            return Err(error);
        }
        if let Some(old) = slot.replace(job) {
            old.abort();
        }
        Ok(())
    }
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stopped_signal.notify_waiters();
        if let Some(job) = self.job.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            job.abort();
        }
        if let Some(stage) =
            self.stage.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            stage.cancel();
        }
        for stage in
            self.tail_stages.lock().unwrap_or_else(std::sync::PoisonError::into_inner).drain(..)
        {
            stage.cancel();
        }
        if let Some(preparation) =
            self.preparation.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            preparation.cancel();
        }
        self.abort_local_jobs();
        self.drain_local_work();
    }
}

#[cfg(test)]
mod tests {
    use crate::SdkError;
    use crate::custody::pairing::{
        PairingActor, PairingConfig, PairingIdentity, install_actor, remove_actor,
    };
    use ramflux_node_core::pairing_relay::{
        PairingRelayConfig, PairingRelayStore, TestPairingClock,
    };
    use ramflux_protocol::custody::DeviceRef;
    use ramflux_protocol::custody::pairing::{
        context_v3::{DataSelectionV3, FullAccountData, TransferProfile},
        local_dto::FullTransferBegin,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn pairing_full_root_stop_drains_local_key_work_before_return()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        let owner = Arc::new(super::FullRuntimeCancel::default());
        let erased = Arc::new(AtomicBool::new(false));
        let (entered, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker_owner = owner.clone();
        let worker_erased = erased.clone();
        let worker = std::thread::spawn(move || -> Result<(), &'static str> {
            let permit = worker_owner.local_work().map_err(|_| "initial local use")?;
            let key = zeroize::Zeroizing::new([7u8; 32]);
            entered.send(()).map_err(|_| "entered observer")?;
            wait.recv().map_err(|_| "release local key use")?;
            drop(key);
            worker_erased.store(true, Ordering::Release);
            drop(permit);
            Ok(())
        });
        started.recv()?;
        let stop_owner = owner.clone();
        let stop_erased = erased.clone();
        let stopper = std::thread::spawn(move || {
            stop_owner.stop();
            assert!(
                stop_erased.load(Ordering::Acquire),
                "root stop returned while local key owner remained live"
            );
        });
        // The stop fence and its condition-variable notification are production events;
        // no timer or scheduler sleep establishes the negative admission assertion.
        let mut workers = owner.local_workers.lock().map_err(|_| "local workers")?;
        while !owner.stopped.load(Ordering::Acquire) {
            workers = owner.idle.wait(workers).map_err(|_| "local workers")?;
        }
        drop(workers);
        assert!(matches!(owner.local_work(), Err(SdkError::PairingCode("Retired"))));
        release.send(())?;
        worker.join().map_err(|_| "local worker panicked")??;
        stopper.join().map_err(|_| "root stopper panicked")?;
        assert!(matches!(owner.local_work(), Err(SdkError::PairingCode("Retired"))));
        Ok(())
    }
    #[tokio::test]
    async fn pairing_full_remove_actor_fences_new_work_without_waiting_for_actor_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let now = crate::custody::network_now()?;
        let store = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: TestPairingClock::new(now),
            node_seed: [7; 32],
            public_origin: "https://relay.example:443".into(),
        })?));
        let actor = PairingActor::new(
            PairingIdentity {
                account_id: "primary".into(),
                local_ref: DeviceRef {
                    account_anchor: ramflux_protocol::encode_base64url([1; 32]),
                    device_id: "primary".into(),
                    device_epoch: 1,
                },
                master_public_key: None,
                base_record_hash: ramflux_protocol::encode_base64url([2; 32]),
                base_epoch: 1,
                is_primary: true,
            },
            None,
            Arc::new(crate::custody::pairing::tests::MemoryRelay { store }),
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        install_actor(root.path(), "primary".into(), actor)?;
        let entry = super::super::super::registry::find(root.path(), "primary")?;
        let mut actor = entry.actor.lock().await;
        // Removal must fence an already-held callback, without waiting for this actor loan.
        remove_actor(root.path(), "primary")?;
        let refused = actor
            .begin_full(FullTransferBegin {
                schema: "ramflux.pairing.TransferBegin.v3".into(),
                version: 3,
                recipient_mode: "new".into(),
                destination_ref: None,
                capabilities: vec!["message".into()],
                lease_not_before: now,
                lease_expires_at: now + 604_800,
                data_selection: DataSelectionV3::FullAccountDataV1(FullAccountData {}),
                transfer_profile: TransferProfile::FullAccountDataV1,
                display_name: "Source".into(),
            })
            .await;
        assert!(
            matches!(refused, Err(SdkError::PairingCode("Retired"))),
            "an already-loaned actor passed the removed-owner fence"
        );
        assert!(matches!(entry.require_live(), Err(SdkError::PairingCode("Retired"))));
        Ok(())
    }
}
