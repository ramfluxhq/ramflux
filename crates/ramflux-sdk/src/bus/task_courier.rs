// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preparation-only courier: no account, database, identity or gateway session ownership.
//!
//! Each pass selects at most two items per queue. With N items, concurrency C (default 4)
//! and item deadline T (default 5 s), preparation takes at most ceil(N/C) * T plus
//! executor scheduling time. The result channel holds a whole pass (six items plus
//! control messages), so a busy actor cannot extend preparation by blocking result delivery.
//! The deadline starts after acquiring a semaphore permit and covers every manifest
//! required by that one item.
//! Results stream independently: a healthy item never waits for a stalled sibling.

use crate::prelude::*;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(super) enum ManifestSource {
    Gateway(Box<GatewaySessionConfig>),
    Federation(String),
}

#[derive(Clone, Debug)]
pub(super) struct ManifestRequest {
    pub source: ManifestSource,
    pub commitment: String,
}

#[derive(Clone, Debug)]
pub(super) struct Item {
    pub key: String,
    pub revision: String,
    pub requests: Vec<ManifestRequest>,
    pub failure: Option<Failure>,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failure {
    UndecodableRow,
    UndecodableCarrier,
    Preparation,
    Deadline,
    Application,
}

#[derive(Debug)]
pub(super) enum Preparation {
    Ready(Vec<SdkDeviceManifestResponse>),
    Charged(Failure),
    Deferred,
}

#[derive(Debug)]
pub(super) enum Outcome {
    Requested { job_id: u64 },
    Item { item: Item, preparation: Preparation },
    Finished,
}

struct Work {
    items: Vec<Item>,
}

pub(super) struct TaskCourier {
    wake: mpsc::Sender<()>,
    prepare: mpsc::Sender<Work>,
    outcomes: mpsc::Receiver<Outcome>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl TaskCourier {
    pub(super) fn start() -> Self {
        Self::with_limits(Duration::from_secs(5), 4)
    }

    pub(super) fn with_limits(deadline: Duration, concurrency: usize) -> Self {
        let (wake, mut signals) = mpsc::channel(1);
        let (prepare, mut work) = mpsc::channel::<Work>(1);
        let (outcome, outcomes) = mpsc::channel(8);
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::task::spawn_local(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
            let mut job_id = 0_u64;
            loop {
                let pass = async {
                    signals.recv().await?;
                    job_id = job_id.wrapping_add(1);
                    outcome.send(Outcome::Requested { job_id }).await.ok()?;
                    let work = work.recv().await?;
                    let mut jobs = tokio::task::JoinSet::new();
                    let mut items = BTreeMap::new();
                    for item in work.items {
                        let requests = item.requests.clone();
                        let failure = item.failure;
                        let slots = semaphore.clone();
                        let job = jobs.spawn_local(async move {
                            let Ok(_permit) = slots.acquire_owned().await else {
                                return Preparation::Deferred;
                            };
                            if let Some(failure) = failure {
                                return Preparation::Charged(failure);
                            }
                            match tokio::time::timeout(deadline, prepare_manifests(requests)).await
                            {
                                Ok(Ok(manifests)) => Preparation::Ready(manifests),
                                Ok(Err(SdkError::TaskManifestWorkerCapacity)) => {
                                    Preparation::Deferred
                                }
                                Ok(Err(_)) => Preparation::Charged(Failure::Preparation),
                                Err(_) => Preparation::Charged(Failure::Deadline),
                            }
                        });
                        items.insert(job.id(), item);
                    }
                    while let Some(joined) = jobs.join_next_with_id().await {
                        let (id, preparation) = match joined {
                            Ok(result) => result,
                            Err(error) => {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                (error.id(), Preparation::Deferred)
                            }
                        };
                        if let Some(item) = items.remove(&id) {
                            outcome.send(Outcome::Item { item, preparation }).await.ok()?;
                        }
                        tokio::task::yield_now().await;
                    }
                    outcome.send(Outcome::Finished).await.ok()?;
                    Some(())
                };
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    result = pass => if result.is_none() { break; },
                }
            }
        });
        let result = Self { wake, prepare, outcomes, stop, task };
        result.signal();
        result
    }

    pub(super) fn wake_sender(&self) -> mpsc::Sender<()> {
        self.wake.clone()
    }

    pub(super) fn signal(&self) {
        let _ = self.wake.try_send(());
    }

    pub(super) fn prepare(&self, items: Vec<Item>) {
        let _ = self.prepare.try_send(Work { items });
    }

    pub(super) async fn recv(&mut self) -> Option<Outcome> {
        self.outcomes.recv().await
    }

    pub(super) async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn prepare_manifests(
    requests: Vec<ManifestRequest>,
) -> Result<Vec<SdkDeviceManifestResponse>, SdkError> {
    let mut manifests = Vec::with_capacity(requests.len());
    for request in requests {
        let manifest = match request.source {
            ManifestSource::Gateway(gateway) => {
                super::dispatch::task_transport::fetch_gateway_manifest(
                    &gateway,
                    &request.commitment,
                )
                .await?
            }
            ManifestSource::Federation(url) => {
                super::dispatch::task_transport::fetch_federated_manifest(&url, &request.commitment)
                    .await?
            }
        };
        manifests.push(manifest);
    }
    Ok(manifests)
}

pub(super) fn manifest_request_keys(requests: &[ManifestRequest]) -> BTreeSet<String> {
    requests
        .iter()
        .map(|request| {
            let source = match &request.source {
                ManifestSource::Gateway(gateway) => gateway
                    .prekey_http_url
                    .clone()
                    .unwrap_or_else(|| format!("gateway://{}", gateway.gateway_addr)),
                ManifestSource::Federation(url) => url.clone(),
            };
            format!("{}/mvp1/device-manifest/{}", source.trim_end_matches('/'), request.commitment)
        })
        .collect()
}
