// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-lifetime task couriers, isolated from the inbound synchronization cycle.

use crate::prelude::*;

pub(super) struct TaskCourier {
    wake: mpsc::Sender<()>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl TaskCourier {
    pub(super) fn start(account: &mut LocalBusAccountState) -> Result<Self, SdkError> {
        let mut courier = account.clone_for_task_courier()?;
        let (wake, mut work) = mpsc::channel(1);
        let (stop, mut stopping) = watch::channel(false);
        account.task_courier_wake = Some(wake.clone());
        let task = tokio::task::spawn_local(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    signal = work.recv() => {
                        if signal.is_none() {
                            break;
                        }
                    }
                }
                let pass = run_pass(&mut courier);
                tokio::pin!(pass);
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    result = &mut pass => {
                        if let Err(error) = result {
                            tracing::warn!(%error, "task courier pass deferred");
                        }
                    }
                }
                tokio::task::yield_now().await;
            }
        });
        let result = Self { wake, stop, task };
        result.signal();
        Ok(result)
    }

    pub(super) fn signal(&self) {
        let _ = self.wake.try_send(());
    }

    pub(super) async fn stop(self, account: Option<&mut LocalBusAccountState>) {
        if let Some(account) = account {
            account.task_courier_wake = None;
        }
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn run_pass(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    super::dispatch::grant_mcp::hydrate_local_mcp_state(account)?;
    if let Err(error) = super::dispatch::task_approval::drive(account).await {
        tracing::warn!(%error, "task approval courier deferred");
    }
    tokio::task::yield_now().await;
    if let Err(error) = super::dispatch::task_transport::drain_confirmations(account).await {
        tracing::warn!(%error, "task confirmation courier deferred");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn account_courier_starts_signals_and_stops_with_its_account() -> Result<(), SdkError> {
        LocalSet::new()
            .run_until(async {
                let root = crate::bus::runtime_tests::root("task-courier-lifecycle");
                let mut account = crate::bus::runtime_tests::account(
                    &root,
                    "account",
                    None,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                )?;
                let courier = TaskCourier::start(&mut account)?;
                assert!(account.task_courier_wake.is_some());
                courier.signal();
                tokio::time::timeout(Duration::from_secs(1), courier.stop(Some(&mut account)))
                    .await
                    .map_err(|_| SdkError::LocalBus("task courier did not stop".into()))?;
                assert!(account.task_courier_wake.is_none());
                drop(account);
                std::fs::remove_dir_all(root)?;
                Ok(())
            })
            .await
    }
}
