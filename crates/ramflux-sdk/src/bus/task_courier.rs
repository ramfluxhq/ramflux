// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-lifetime task preparation courier.
//!
//! The courier deliberately owns no account, client, database handle, gateway session or
//! cryptographic identity. It only schedules bounded preparation work and hands readiness back to
//! the account actor. The actor remains the single owner of submission and durable status changes.

use crate::prelude::*;
use serde_json::Value;

const COURIER_CHANNEL_CAPACITY: usize = 4;

#[derive(Clone, Debug)]
pub(super) enum ManifestSource {
    Gateway(Box<GatewaySessionConfig>),
    Federation(String),
    #[cfg(test)]
    Panic,
    #[cfg(test)]
    Stall,
}

#[derive(Clone, Debug)]
pub(super) struct ManifestRequest {
    pub source: ManifestSource,
    pub commitment: String,
}

#[derive(Debug)]
pub(super) struct Prepared {
    pub job_id: u64,
    pub manifests: Vec<SdkDeviceManifestResponse>,
    pub request_keys: BTreeSet<String>,
}

#[derive(Debug)]
pub(super) enum Outcome {
    Requested { job_id: u64 },
    Prepared(Prepared),
    Charged { job_id: u64, reason: String },
    Deferred { job_id: u64, reason: String },
}

struct Work {
    job_id: u64,
    requests: Vec<ManifestRequest>,
}

fn classify(job_id: u64, result: Result<Vec<SdkDeviceManifestResponse>, SdkError>) -> Outcome {
    match result {
        Ok(manifests) => {
            Outcome::Prepared(Prepared { job_id, manifests, request_keys: BTreeSet::new() })
        }
        Err(SdkError::TaskManifestWorkerCapacity) => {
            Outcome::Deferred { job_id, reason: "manifest_worker_capacity".to_owned() }
        }
        Err(error) => Outcome::Charged { job_id, reason: local_bus_error_code(&error).to_owned() },
    }
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
        let (wake, mut work) = mpsc::channel(COURIER_CHANNEL_CAPACITY);
        let (prepare, mut preparations) = mpsc::channel::<Work>(COURIER_CHANNEL_CAPACITY);
        let (outcome, outcomes) = mpsc::channel(COURIER_CHANNEL_CAPACITY);
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::task::spawn_local(async move {
            let mut job_id = 0_u64;
            loop {
                let preparation = tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    signal = work.recv() => {
                        if signal.is_none() {
                            break;
                        }
                        job_id = job_id.wrapping_add(1);
                        tokio::select! {
                            biased;
                            _ = stopping.changed() => break,
                            sent = outcome.send(Outcome::Requested { job_id }) => {
                                if sent.is_err() {
                                    break;
                                }
                            }
                        }
                        continue;
                    }
                    preparation = preparations.recv() => preparation,
                };
                let Some(preparation) = preparation else {
                    break;
                };
                let request_keys = manifest_request_keys(&preparation.requests);
                let prepared = tokio::task::spawn_local(prepare_manifests(preparation.requests));
                let joined = tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    result = prepared => result,
                };
                let result = match joined {
                    Ok(result) => {
                        let mut outcome = classify(preparation.job_id, result);
                        if let Outcome::Prepared(prepared) = &mut outcome {
                            prepared.request_keys = request_keys;
                        }
                        outcome
                    }
                    Err(error) => {
                        tracing::warn!(%error, "task preparation worker panicked; restarting");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Outcome::Deferred {
                            job_id: preparation.job_id,
                            reason: "courier_worker_restart".to_owned(),
                        }
                    }
                };
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    sent = outcome.send(result) => {
                        if sent.is_err() {
                            break;
                        }
                    }
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

    pub(super) fn prepare(&self, job_id: u64, requests: Vec<ManifestRequest>) {
        let _ = self.prepare.try_send(Work { job_id, requests });
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
    let fetch = async move {
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
                    super::dispatch::task_transport::fetch_federated_manifest(
                        &url,
                        &request.commitment,
                    )
                    .await?
                }
                #[cfg(test)]
                ManifestSource::Panic => {
                    std::panic::resume_unwind(Box::new("injected task preparation panic"))
                }
                #[cfg(test)]
                ManifestSource::Stall => {
                    std::future::pending::<Result<SdkDeviceManifestResponse, SdkError>>().await?
                }
            };
            manifests.push(manifest);
        }
        Ok(manifests)
    };
    tokio::time::timeout(Duration::from_secs(5), fetch)
        .await
        .map_err(|_| SdkError::InboundPending("task preparation deadline exceeded".to_owned()))?
}

pub(super) fn manifest_requests(
    account: &LocalBusAccountState,
) -> Result<Vec<ManifestRequest>, SdkError> {
    use crate::client::task::{approval::Job, control::AckJob, control::ForwardJob};

    let db = account.client.account_db()?;
    let now = now_unix_timestamp();
    let mut conversations = BTreeSet::new();
    let mut approvals = Vec::new();
    for prefix in ["task/approval_decision_out/", "task/approval_out/"] {
        approvals.extend(db.task_record_page::<Job>(prefix, prefix, 65)?);
    }
    approvals.sort_by(|left, right| left.0.cmp(&right.0));
    rotate(&mut approvals, account.task_approval_cursor);
    for (_, job) in approvals
        .into_iter()
        .filter(|(_, job)| job.next_at <= now && job.packet.deadline() > now && job.attempts < 8)
        .take(2)
    {
        conversations.insert(job.packet.request().binding.conversation_id.clone());
    }

    let mut acknowledgements = db.task_record_page::<AckJob>("task/ack/", "task/ack/", 65)?;
    acknowledgements.sort_by(|left, right| left.0.cmp(&right.0));
    rotate(&mut acknowledgements, account.task_ack_cursor);
    for (_, job) in acknowledgements.into_iter().filter(|(_, job)| job.next_at <= now).take(2) {
        if let Ok(carrier) = job.ack.original() {
            conversations.insert(carrier.conversation_id);
        }
    }

    let mut forwards = db.task_record_page::<ForwardJob>("task/forward/", "task/forward/", 65)?;
    forwards.sort_by(|left, right| left.0.cmp(&right.0));
    rotate(&mut forwards, account.task_forward_cursor);
    for (_, job) in forwards.into_iter().filter(|(_, job)| job.next_at <= now).take(2) {
        conversations.insert(job.conversation_id);
    }

    let mut requests = BTreeMap::<(String, String), ManifestRequest>::new();
    if !conversations.is_empty() {
        add_request(
            &mut requests,
            ManifestSource::Gateway(Box::new(account.gateway_config.clone())),
            account.principal_commitment.clone(),
        );
    }
    for conversation in conversations {
        let Some(thread) = db.client_record("conversation", &conversation)? else {
            continue;
        };
        if let Some(group) = thread["group_id"].as_str() {
            for route in super::group_delivery::directory(&account.client, group)? {
                let Some(commitment) = route["member_principal_commitment"].as_str() else {
                    continue;
                };
                if commitment == account.principal_commitment {
                    continue;
                }
                let source = route["federation"]["recipient_prekey_url"].as_str().map_or_else(
                    || ManifestSource::Gateway(Box::new(account.gateway_config.clone())),
                    |url| ManifestSource::Federation(url.to_owned()),
                );
                add_request(&mut requests, source, commitment.to_owned());
            }
        } else if let Some(participants) = thread["participants"].as_array() {
            let local =
                account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            for principal in participants.iter().filter_map(Value::as_str) {
                if principal == local.principal_id {
                    continue;
                }
                let Some(identity) = db.client_record("identity", principal)? else {
                    continue;
                };
                let Some(commitment) = identity["contact_identity_commitment"].as_str() else {
                    continue;
                };
                let source = thread["direct_route"]["federation"]["recipient_prekey_url"]
                    .as_str()
                    .map_or_else(
                        || ManifestSource::Gateway(Box::new(account.gateway_config.clone())),
                        |url| ManifestSource::Federation(url.to_owned()),
                    );
                add_request(&mut requests, source, commitment.to_owned());
            }
        }
    }
    Ok(requests.into_values().collect())
}

fn rotate<T>(rows: &mut [(String, T)], cursor: usize) {
    if !rows.is_empty() {
        let offset = cursor % rows.len();
        rows.rotate_left(offset);
    }
}

fn add_request(
    requests: &mut BTreeMap<(String, String), ManifestRequest>,
    source: ManifestSource,
    commitment: String,
) {
    let source_key = match &source {
        ManifestSource::Gateway(gateway) => format!("gateway:{}", gateway.server_name),
        ManifestSource::Federation(url) => format!("federation:{url}"),
        #[cfg(test)]
        ManifestSource::Panic => "panic".to_owned(),
        #[cfg(test)]
        ManifestSource::Stall => "stall".to_owned(),
    };
    requests
        .entry((source_key, commitment.clone()))
        .or_insert(ManifestRequest { source, commitment });
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
                #[cfg(test)]
                ManifestSource::Panic => "panic://worker".to_owned(),
                #[cfg(test)]
                ManifestSource::Stall => "stall://worker".to_owned(),
            };
            format!("{}/mvp1/device-manifest/{}", source.trim_end_matches('/'), request.commitment)
        })
        .collect()
}

pub(super) async fn run_pass(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let approvals = super::dispatch::task_approval::drive(account).await.unwrap_or_else(|error| {
        tracing::warn!(%error, "task approval courier deferred");
        0
    });
    tokio::task::yield_now().await;
    let confirmations = super::dispatch::task_transport::drain_confirmations(account)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "task confirmation courier deferred");
            0
        });
    Ok(approvals + confirmations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    #[tokio::test]
    async fn preparation_courier_owns_no_account_and_stops() -> Result<(), SdkError> {
        LocalSet::new()
            .run_until(async {
                let mut courier = TaskCourier::start();
                let outcome = tokio::time::timeout(Duration::from_secs(1), courier.recv())
                    .await
                    .map_err(|_| SdkError::LocalBus("task courier did not prepare".into()))?;
                let Some(Outcome::Requested { job_id }) = outcome else {
                    return Err(SdkError::LocalBus("task courier did not request work".into()));
                };
                courier.prepare(job_id, Vec::new());
                let outcome = tokio::time::timeout(Duration::from_secs(1), courier.recv())
                    .await
                    .map_err(|_| SdkError::LocalBus("task courier did not finish".into()))?;
                assert!(matches!(outcome, Some(Outcome::Prepared(_))));
                tokio::time::timeout(Duration::from_secs(1), courier.stop())
                    .await
                    .map_err(|_| SdkError::LocalBus("task courier did not stop".into()))?;
                Ok(())
            })
            .await
    }

    #[test]
    fn courier_outcomes_distinguish_charged_and_free_deferral() {
        assert!(matches!(
            classify(7, Err(SdkError::TaskManifestWorkerCapacity)),
            Outcome::Deferred { job_id: 7, .. }
        ));
        assert!(matches!(
            classify(7, Err(SdkError::InboundPending("preparation timeout".to_owned()))),
            Outcome::Charged { job_id: 7, .. }
        ));
    }

    #[tokio::test]
    async fn panicked_preparation_worker_is_restarted_with_backoff() -> Result<(), SdkError> {
        LocalSet::new()
            .run_until(async {
                let mut courier = TaskCourier::start();
                let Some(Outcome::Requested { job_id }) = courier.recv().await else {
                    return Err(SdkError::LocalBus("task courier did not request work".into()));
                };
                courier.prepare(
                    job_id,
                    vec![ManifestRequest {
                        source: ManifestSource::Panic,
                        commitment: "panic".into(),
                    }],
                );
                let outcome = tokio::time::timeout(Duration::from_secs(1), courier.recv())
                    .await
                    .map_err(|_| SdkError::LocalBus("task courier did not restart".into()))?;
                assert!(matches!(
                    outcome,
                    Some(Outcome::Deferred { reason, .. }) if reason == "courier_worker_restart"
                ));
                courier.signal();
                assert!(matches!(
                    tokio::time::timeout(Duration::from_secs(1), courier.recv()).await,
                    Ok(Some(Outcome::Requested { .. }))
                ));
                courier.stop().await;
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn stalled_preparation_keeps_the_single_account_session_actor_owned()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(
            Duration::from_secs(30),
            LocalSet::new().run_until(async {
                let root = super::super::runtime_tests::root("task-courier-single-session");
                let account = super::super::runtime_tests::account(
                    &root,
                    "single-session",
                    None,
                    Arc::new(AtomicBool::new(false)),
                )?;
                let session = account
                    .engine
                    .as_ref()
                    .ok_or("account gateway session missing")?
                    .session()
                    .session_id
                    .clone();
                let mut courier = TaskCourier::start();
                let Some(Outcome::Requested { job_id }) = courier.recv().await else {
                    return Err("task courier did not request work".into());
                };
                courier.prepare(
                    job_id,
                    vec![ManifestRequest {
                        source: ManifestSource::Stall,
                        commitment: "stalled".into(),
                    }],
                );
                tokio::task::yield_now().await;
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                    let engine =
                        account.engine.as_ref().ok_or("account gateway session was lost")?;
                    assert_eq!(engine.session().session_id, session);
                }
                courier.stop().await;
                drop(account);
                std::fs::remove_dir_all(root)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }),
        )
        .await
        .map_err(|_| "single-session courier regression exceeded its outer timeout")??;
        Ok(())
    }
}
