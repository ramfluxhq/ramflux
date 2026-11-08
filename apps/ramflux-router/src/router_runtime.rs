// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROUTER_FORWARD_CONCURRENCY_ENV: &str = "RAMFLUX_ROUTER_FORWARD_CONCURRENCY";
const ROUTER_FORWARD_CONCURRENCY_DEFAULT: usize = 32;
const ROUTER_FORWARD_TIMEOUT_SECONDS_ENV: &str = "RAMFLUX_ROUTER_FORWARD_TIMEOUT_SECONDS";
// The old-home reservation lasts 20 s (whole-second lease timestamps).
// DNS <= 3 s plus socket IO <= 12 s leaves room before that lease expires.
// New-home federation Pending lasts 142 s: two worst-case 71 s router posts;
// it deliberately outlives an old-home retry and prevents duplicate delivery.
const ROUTER_FORWARD_TIMEOUT_SECONDS_DEFAULT: u64 = 20;

pub(crate) struct TokioRouterRuntime {
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    home_node_forward: Option<LocalFederationForwardClient>,
    forward_semaphore: Arc<tokio::sync::Semaphore>,
    forward_timeout: Duration,
    custody: std::sync::OnceLock<Arc<ramflux_node_core::CustodyService>>,
    migration_drain: std::sync::OnceLock<crate::migration_drain::MigrationDrain>,
    migration_courier: std::sync::OnceLock<crate::migration_courier::MigrationCourier>,
    /// Fixture-scoped, always-active ingress observation; compiled only into unit tests.
    #[cfg(test)]
    ingress_probe: IngressProbe,
}

#[cfg(test)]
#[derive(Default)]
struct IngressProbe {
    submit_calls: std::sync::atomic::AtomicUsize,
    dispatches: std::sync::atomic::AtomicUsize,
}

impl TokioRouterRuntime {
    pub(crate) fn new(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
        home_node_forward: Option<LocalFederationForwardClient>,
    ) -> Self {
        let concurrency =
            ramflux_node_core::environment::parsed::<usize>(ROUTER_FORWARD_CONCURRENCY_ENV)
                .filter(|value| (1..=1_024).contains(value))
                .unwrap_or(ROUTER_FORWARD_CONCURRENCY_DEFAULT);
        let timeout_seconds =
            ramflux_node_core::environment::parsed::<u64>(ROUTER_FORWARD_TIMEOUT_SECONDS_ENV)
                .filter(|value| (1..=300).contains(value))
                .unwrap_or(ROUTER_FORWARD_TIMEOUT_SECONDS_DEFAULT);
        Self::new_with_forward_limits(
            state,
            store,
            home_node_forward,
            concurrency,
            Duration::from_secs(timeout_seconds),
        )
    }

    fn new_with_forward_limits(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
        home_node_forward: Option<LocalFederationForwardClient>,
        concurrency: usize,
        forward_timeout: Duration,
    ) -> Self {
        Self {
            state,
            store,
            home_node_forward,
            forward_semaphore: Arc::new(tokio::sync::Semaphore::new(concurrency.max(1))),
            forward_timeout,
            custody: std::sync::OnceLock::new(),
            migration_courier: std::sync::OnceLock::new(),
            migration_drain: std::sync::OnceLock::new(),
            #[cfg(test)]
            ingress_probe: IngressProbe::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) enum RouterHandle {
    Tokio(Arc<TokioRouterRuntime>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalFederationForwardClient {
    pub(crate) url: String,
    pub(crate) admin_token: Option<String>,
    pub(crate) source_node_id: String,
}

impl LocalFederationForwardClient {
    pub(crate) fn forward(
        &self,
        plan: &ramflux_node_core::HomeNodeMigrationForwardPlan,
        timeout: Duration,
    ) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_node_core::NodeCoreError>
    {
        let mut request = plan.federated_forward_request(&self.source_node_id);
        if let Some(admin_token) = &self.admin_token {
            admin_token.clone_into(&mut request.admin_token);
        }
        let body = serde_json::json!({
            "admin_token": self.admin_token.as_deref().unwrap_or_default(),
            "forward": request,
        });
        crate::forward_http::post(&self.url, &body, timeout)
    }
}

impl RouterHandle {
    pub(crate) fn tokio(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
        home_node_forward: Option<LocalFederationForwardClient>,
    ) -> Self {
        Self::Tokio(Arc::new(TokioRouterRuntime::new(state, store, home_node_forward)))
    }

    pub(crate) fn state(&self) -> &ramflux_node_core::RouterCore {
        match self {
            Self::Tokio(runtime) => runtime.state.as_ref(),
        }
    }

    #[cfg(test)]
    fn count_submit_call(&self) {
        match self {
            Self::Tokio(runtime) => {
                runtime
                    .ingress_probe
                    .submit_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    #[cfg(test)]
    fn count_dispatch(&self) {
        match self {
            Self::Tokio(runtime) => {
                runtime.ingress_probe.dispatches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    /// Test-only: `(router submit calls, dispatches into the router engine)` seen by this handle.
    #[cfg(test)]
    #[cfg_attr(
        not(all(target_os = "linux", feature = "compio-mesh")),
        allow(dead_code, reason = "read only by the Linux compio live-path test")
    )]
    pub(crate) fn ingress_probe(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::SeqCst;
        match self {
            Self::Tokio(runtime) => (
                runtime.ingress_probe.submit_calls.load(SeqCst),
                runtime.ingress_probe.dispatches.load(SeqCst),
            ),
        }
    }

    pub(crate) fn store_owner_count(&self) -> usize {
        match self {
            Self::Tokio(runtime) => Arc::strong_count(&runtime.store),
        }
    }

    pub(crate) fn store(&self) -> &ramflux_node_core::RouterRedbStore {
        match self {
            Self::Tokio(runtime) => runtime.store.as_ref(),
        }
    }

    #[cfg(any(test, feature = "itest-http"))]
    pub(crate) fn submit_envelope_from(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        origin: ramflux_node_core::RouterEnvelopeOrigin,
    ) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
        if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
            return Ok(crate::durable_mode::rejected_security(&envelope));
        }
        match self {
            Self::Tokio(runtime) => crate::router_engine::submit_envelope(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                crate::router_engine::AsyncForwardContext {
                    client: runtime.home_node_forward.as_ref(),
                    semaphore: &runtime.forward_semaphore,
                    timeout: runtime.forward_timeout,
                },
                envelope,
                total_started,
                origin,
            ),
        }
    }

    #[cfg(test)]
    pub(crate) async fn submit_envelope_async_from(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        origin: ramflux_node_core::RouterEnvelopeOrigin,
    ) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
        if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
            return Ok(crate::durable_mode::rejected_security(&envelope));
        }
        match self {
            Self::Tokio(runtime) => {
                crate::router_engine::submit_envelope_async(
                    &runtime.state,
                    &runtime.store,
                    crate::router_engine::AsyncForwardContext {
                        client: runtime.home_node_forward.as_ref(),
                        semaphore: &runtime.forward_semaphore,
                        timeout: runtime.forward_timeout,
                    },
                    envelope,
                    total_started,
                    origin,
                )
                .await
            }
        }
    }

    pub(crate) fn submit_envelope_mesh_from(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        origin: ramflux_node_core::RouterEnvelopeOrigin,
    ) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
        #[cfg(test)]
        self.count_submit_call();
        if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
            return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
        }
        #[cfg(test)]
        self.count_dispatch();
        match self {
            Self::Tokio(runtime) => crate::router_engine::submit_envelope_mesh(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                crate::router_engine::AsyncForwardContext {
                    client: runtime.home_node_forward.as_ref(),
                    semaphore: &runtime.forward_semaphore,
                    timeout: runtime.forward_timeout,
                },
                envelope,
                total_started,
                origin,
            ),
        }
    }

    pub(crate) async fn submit_envelope_mesh_async_from(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        origin: ramflux_node_core::RouterEnvelopeOrigin,
    ) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
        #[cfg(test)]
        self.count_submit_call();
        if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
            return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
        }
        #[cfg(test)]
        self.count_dispatch();
        match self {
            Self::Tokio(runtime) => {
                crate::router_engine::submit_envelope_mesh_async(
                    &runtime.state,
                    &runtime.store,
                    crate::router_engine::AsyncForwardContext {
                        client: runtime.home_node_forward.as_ref(),
                        semaphore: &runtime.forward_semaphore,
                        timeout: runtime.forward_timeout,
                    },
                    envelope,
                    total_started,
                    origin,
                )
                .await
            }
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_ack(
        &self,
        ack: &ramflux_protocol::Ack,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => {
                crate::router_engine::apply_ack(runtime.state.as_ref(), runtime.store.as_ref(), ack)
            }
        }
    }

    pub(crate) fn apply_bound_ack(
        &self,
        request: &ramflux_node_core::TargetAckRequest,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_ack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_nack(
        &self,
        nack: &ramflux_protocol::Nack,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                nack,
            ),
        }
    }

    pub(crate) fn apply_bound_nack(
        &self,
        request: &ramflux_node_core::TargetNackRequest,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }

    #[cfg(any(test, feature = "itest-http"))]
    pub(crate) fn own_device_fanout(
        &self,
        request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
        if ramflux_protocol::ephemeral::require_durable(&request.envelope).is_err() {
            anyhow::bail!(crate::durable_mode::DeliveryModeRefused::from_envelope(
                &request.envelope
            ));
        }
        match self {
            Self::Tokio(runtime) => crate::router_engine::own_device_fanout(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }
}

impl RouterHandle {
    pub(crate) fn enable_custody(
        &self,
        config: &ramflux_node_core::NodeServiceConfig,
    ) -> anyhow::Result<()> {
        let Ok(path) = std::env::var("RAMFLUX_CUSTODY_NODE_RECORD_FILE") else {
            if crate::home_migration::enabled()? {
                anyhow::bail!("migration requires RAMFLUX_CUSTODY_NODE_RECORD_FILE");
            }
            self.store().validate_home_migration_runtime(None)?;
            return Ok(());
        };
        if path.trim().is_empty() {
            if crate::home_migration::enabled()? {
                anyhow::bail!("migration requires RAMFLUX_CUSTODY_NODE_RECORD_FILE");
            }
            self.store().validate_home_migration_runtime(None)?;
            return Ok(());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)?.take(512 * 1024 + 1).read_to_end(&mut bytes)?;
        let record = ramflux_protocol::custody::decode(&bytes, 512 * 1024)?;
        let trusted = std::env::var("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY")?;
        let now = ramflux_node_core::now_unix_seconds();
        let node = ramflux_crypto::custody::verify_node_identity_record(
            &record,
            &config.node_id,
            &trusted,
            now,
        )?;
        let allow = std::env::var("RAMFLUX_CUSTODY_ALLOW_NO_CHANNEL_BINDING").as_deref() == Ok("1");
        let settings = ramflux_node_core::CustodyIssuanceSettings::from_env()?;
        let migration = crate::home_migration::configured(config, &record, now)?;
        self.store().validate_home_migration_runtime(
            migration.as_ref().map(|_| (config.node_id.as_str(), trusted.as_str())),
        )?;
        let mut service = ramflux_node_core::CustodyService::with_issuance_settings(
            node,
            allow,
            self.store(),
            now,
            settings,
        )?;
        if let Some(migration) = migration {
            service = service.with_home_migration(migration)?;
        }
        let Self::Tokio(runtime) = self;
        let service = Arc::new(service);
        runtime
            .custody
            .set(service.clone())
            .map_err(|_| anyhow::anyhow!("custody already configured"))?;
        if service.home_migration_enabled() {
            crate::home_migration::require_forward_client(runtime.home_node_forward.is_some())?;
            if let Some(client) = &runtime.home_node_forward {
                let drain = crate::migration_drain::MigrationDrain::start(
                    Arc::downgrade(&runtime.state),
                    Arc::downgrade(&runtime.store),
                    client.clone(),
                    runtime.forward_semaphore.clone(),
                    runtime.forward_timeout,
                )?;
                runtime
                    .migration_drain
                    .set(drain)
                    .map_err(|_| anyhow::anyhow!("migration drain already configured"))?;
            }
            let worker = crate::migration_courier::MigrationCourier::start(
                Arc::downgrade(&service),
                Arc::downgrade(&runtime.store),
            )?;
            runtime
                .migration_courier
                .set(worker)
                .map_err(|_| anyhow::anyhow!("migration courier already configured"))?;
        }
        Ok(())
    }
    pub(crate) fn home_migration_enabled(&self) -> bool {
        let Self::Tokio(runtime) = self;
        runtime.custody.get().is_some_and(|service| service.home_migration_enabled())
    }
    pub(crate) fn migration_peer(
        &self,
        request: &ramflux_node_core::MigrationPeerRequest,
    ) -> anyhow::Result<ramflux_node_core::MigrationPeerReply> {
        let Self::Tokio(runtime) = self;
        let Some(service) = runtime.custody.get() else {
            return Ok(ramflux_node_core::MigrationPeerReply::Refused(
                ramflux_protocol::home_migration::Refusal::PeeringUnavailable,
            ));
        };
        service
            .home_migration_peer(
                self.state(),
                self.store(),
                request,
                ramflux_node_core::now_unix_seconds(),
            )
            .map_err(Into::into)
    }
    pub(crate) fn custody(
        &self,
        request: ramflux_protocol::custody::CustodyMeshRequest,
        peer: &str,
    ) -> ramflux_protocol::custody::CustodyServerFrame {
        let Self::Tokio(runtime) = self;
        runtime.custody.get().map_or(
            ramflux_protocol::custody::CustodyServerFrame::Refused {
                code: ramflux_protocol::custody::CustodyRefusal::Unsupported,
                capacity: None,
                retry: None,
            },
            |service| {
                service.mesh(
                    self.state(),
                    self.store(),
                    request,
                    peer,
                    ramflux_node_core::now_unix_seconds(),
                )
            },
        )
    }
}

impl RouterHandle {
    #[cfg(feature = "itest-http")]
    pub(crate) fn custody_budget_snapshot(&self) -> serde_json::Value {
        let Self::Tokio(runtime) = self;
        runtime.custody.get().map_or(serde_json::Value::Null, |service| service.budget_snapshot())
    }
    pub(crate) fn custody_public_certificate(&self, hash: &str) -> bool {
        let Self::Tokio(runtime) = self;
        runtime.custody.get().is_some_and(|service| service.accepts_public_certificate(hash))
    }
    pub(crate) fn custody_disconnected(&self, connection: &str) {
        let Self::Tokio(runtime) = self;
        if let Some(service) = runtime.custody.get() {
            service.disconnect("direct-tls", connection);
        }
    }
    pub(crate) fn custody_tls(
        &self,
        frame: ramflux_protocol::custody::CustodyClientFrame,
        connection: &str,
        peer: &str,
        mode: ramflux_protocol::custody::BindingMode,
        channel: (Option<[u8; 32]>, Option<&ramflux_node_core::CustodyIngressPermit>),
    ) -> ramflux_protocol::custody::CustodyServerFrame {
        let (exporter, permit) = channel;
        let Self::Tokio(runtime) = self;
        runtime.custody.get().map_or(
            ramflux_protocol::custody::CustodyServerFrame::Refused {
                code: ramflux_protocol::custody::CustodyRefusal::Unsupported,
                capacity: None,
                retry: None,
            },
            |service| {
                service.tls_with_permit(
                    self.state(),
                    self.store(),
                    frame,
                    ramflux_node_core::CustodyTlsContext {
                        connection_id: connection,
                        remote_ip: peer,
                        mode,
                        exporter,
                    },
                    (ramflux_node_core::now_unix_seconds(), permit),
                )
            },
        )
    }
}

impl RouterHandle {
    pub(crate) async fn submit_forwarded_async(
        &self,
        request: ramflux_node_core::ForwardedEnvelopeRequest,
    ) -> anyhow::Result<serde_json::Value> {
        if ramflux_protocol::ephemeral::require_durable(&request.envelope).is_err() {
            return Ok(serde_json::to_value(crate::durable_mode::rejected_security(
                &request.envelope,
            ))?);
        }
        let router = self.clone();
        let operation = tokio::task::spawn_blocking(move || {
            let Self::Tokio(runtime) = &router;
            let node = runtime.custody.get().and_then(|service| service.migration_node());
            router.state().prepare_forwarded_envelope_with_metadata(
                router.store(),
                node,
                request,
                ramflux_node_core::now_unix_seconds(),
            )
        })
        .await??;
        self.forwarded_reply(operation.published().await)
    }

    pub(crate) fn submit_forwarded(
        &self,
        request: ramflux_node_core::ForwardedEnvelopeRequest,
    ) -> anyhow::Result<serde_json::Value> {
        if ramflux_protocol::ephemeral::require_durable(&request.envelope).is_err() {
            return Ok(serde_json::to_value(crate::durable_mode::rejected_security(
                &request.envelope,
            ))?);
        }
        let Self::Tokio(runtime) = self;
        let node = runtime.custody.get().and_then(|s| s.migration_node());
        self.forwarded_reply(
            self.state()
                .prepare_forwarded_envelope_with_metadata(
                    self.store(),
                    node,
                    request,
                    ramflux_node_core::now_unix_seconds(),
                )?
                .published_blocking()?,
        )
    }

    fn forwarded_reply(
        &self,
        outcome: Result<ramflux_node_core::ForwardedSubmission, ramflux_node_core::NodeCoreError>,
    ) -> anyhow::Result<serde_json::Value> {
        match outcome {
            Ok(outcome) => {
                let delivery = crate::router_engine::submit_response_from_outcome(
                    self.state(),
                    outcome.outcome,
                );
                Ok(forwarded_mesh_delivery_reply(&ramflux_node_core::SessionPushSubmitResponse {
                    delivery,
                    incarnation_id: outcome.incarnation_id,
                    retain_until: outcome.retain_until,
                }))
            }
            Err(error) => forwarded_error_reply(error),
        }
    }
}

fn forwarded_error_reply(
    error: ramflux_node_core::NodeCoreError,
) -> anyhow::Result<serde_json::Value> {
    match error {
        ramflux_node_core::NodeCoreError::HomeMigration(reason) => {
            Ok(forwarded_migration_reply(reason))
        }
        error @ (ramflux_node_core::NodeCoreError::SenderRetry(_)
        | ramflux_node_core::NodeCoreError::Publication(_)
        | ramflux_node_core::NodeCoreError::PayloadTooLarge) => {
            let text = error.to_string();
            match crate::router_engine::publication_reason(&text) {
                Some(reason) => Ok(serde_json::json!({"accepted": false,
                    "retryable": matches!(reason, "aborted_retry_safe" | "capacity_retry_after"),
                    "reason": reason})),
                None => Err(error.into()),
            }
        }
        ramflux_node_core::NodeCoreError::Capacity { .. } => Ok(
            serde_json::json!({"accepted":false,"retryable":true,"reason":"foreign_pin_capacity","retry_after":5}),
        ),
        ramflux_node_core::NodeCoreError::SourceAuthorityRefused { .. }
        | ramflux_node_core::NodeCoreError::Unauthorized(_)
        | ramflux_node_core::NodeCoreError::CustodyConflict { .. } => Ok(
            serde_json::json!({"accepted":false,"retryable":false,"reason":"sender_authority_refused"}),
        ),
        error => Err(error.into()),
    }
}

fn forwarded_mesh_delivery_reply(
    response: &ramflux_node_core::SessionPushSubmitResponse,
) -> serde_json::Value {
    let delivery = &response.delivery;
    let accepted = matches!(
        delivery.outcome.as_str(),
        "online" | "offline_queued" | "duplicate_federated_forward"
    );
    serde_json::json!({"accepted":accepted,"retryable":!accepted && !delivery.outcome.starts_with("rejected_") && delivery.outcome!="payload_too_large","delivery":response})
}
#[cfg(test)]
fn forwarded_delivery_reply(
    delivery: &ramflux_node_core::EnvelopeSubmitResponse,
) -> serde_json::Value {
    let accepted = matches!(
        delivery.outcome.as_str(),
        "online" | "offline_queued" | "duplicate_federated_forward"
    );
    serde_json::json!({"accepted": accepted, "retryable": !accepted && !delivery.outcome.starts_with("rejected_") && delivery.outcome != "payload_too_large", "delivery": delivery})
}
fn forwarded_migration_reply(
    reason: ramflux_protocol::home_migration::Refusal,
) -> serde_json::Value {
    use ramflux_protocol::home_migration::Refusal;
    let retryable = matches!(
        reason,
        Refusal::DormantInbox
            | Refusal::EvidenceRequired
            | Refusal::PeeringUnavailable
            | Refusal::StorageUnavailable
            | Refusal::RateLimited
            | Refusal::CapacityRefused
            | Refusal::AuthorityUpdateRequired
            | Refusal::BacklogEvidenceRequired
            | Refusal::CommitOutcomeUnknown
    );
    serde_json::json!({"accepted":false,"retryable":retryable,"reason":reason})
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use ramflux_protocol::{DeliveryClass, Ext, Priority, SignatureAlg, SignedFields};

    use super::*;

    mod forward_hardening;

    #[test]
    fn forwarded_wire_reply_marks_permanent_refusals_and_deleted_targets_nonretryable() {
        use ramflux_protocol::home_migration::Refusal;
        for reason in [Refusal::BaseMismatch, Refusal::HomeFork, Refusal::ActorRevoked] {
            let reply = forwarded_migration_reply(reason);
            assert_eq!(reply["accepted"], false);
            assert_eq!(reply["retryable"], false);
        }
        assert_eq!(forwarded_migration_reply(Refusal::DormantInbox)["retryable"], true);
        for outcome in [
            "rejected_deleted",
            "rejected_deactivated",
            "rejected_security:bad_signature",
            "forward_in_progress",
        ] {
            let reply = forwarded_delivery_reply(&ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: outcome.into(),
                target_delivery_id: "target".into(),
                inbox_seq: None,
                cursor: None,
                nack: None,
            });
            assert_eq!(reply["accepted"], false);
            assert_eq!(reply["retryable"], outcome == "forward_in_progress");
        }
    }

    #[test]
    fn forwarded_capacity_and_stale_sender_are_classified_without_http_errors() -> anyhow::Result<()>
    {
        let full = forwarded_error_reply(ramflux_node_core::NodeCoreError::Capacity {
            resource: "foreign custody pins",
        })?;
        assert_eq!(full["accepted"], false);
        assert_eq!(full["retryable"], true);
        assert_eq!(full["retry_after"], 5);
        let stale =
            forwarded_error_reply(ramflux_node_core::NodeCoreError::Unauthorized("stale".into()))?;
        assert_eq!(stale["accepted"], false);
        assert_eq!(stale["retryable"], false);
        Ok(())
    }

    fn no_forward() -> crate::router_engine::AsyncForwardContext<'static> {
        static SEMAPHORE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        crate::router_engine::AsyncForwardContext {
            client: None,
            semaphore: SEMAPHORE.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32))),
            timeout: Duration::from_secs(20),
        }
    }

    #[test]
    fn tokio_handle_matches_submit_and_replay_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_submit", "target_runtime_submit")?;
        let (oracle_state, oracle_store, _oracle_path) = test_router("submit_oracle")?;
        let oracle = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            no_forward(),
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )?;

        let (handle, _handle_path) = test_handle("submit_handle")?;
        let via_handle = handle.submit_envelope_from(
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )?;
        assert_eq!(via_handle, oracle);

        let replay = handle.submit_envelope_from(
            envelope,
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )?;
        assert_eq!(replay.outcome, "offline_queued");
        assert_eq!(replay.inbox_seq, via_handle.inbox_seq);
        Ok(())
    }

    #[test]
    fn tokio_handle_async_submit_matches_replay_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_async_submit", "target_runtime_async_submit")?;
        let (handle, _handle_path) = test_handle("async_submit_handle")?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let via_handle = runtime.block_on(handle.submit_envelope_async_from(
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        ))?;
        assert_eq!(via_handle.outcome, "offline_queued");

        let replay = runtime.block_on(handle.submit_envelope_async_from(
            envelope,
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        ))?;
        assert_eq!(replay.outcome, "offline_queued");
        assert_eq!(replay.inbox_seq, via_handle.inbox_seq);
        Ok(())
    }

    #[test]
    fn durable_local_delivery_retries_reuse_original_acceptance() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_durable_replay", "target_runtime_replay")?;
        let path = temp_store_path("durable_local_replay")?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let source_root = {
            let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
            let state = Arc::new(ramflux_node_core::RouterCore::new());
            register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
            store.record_identity_registry(&state.mvp1_identities_snapshot())?;
            let source = state.authenticated_envelope_source_durable(&envelope, store.as_ref())?;
            let source_root = source.root_commitment().to_owned();
            let handle = RouterHandle::tokio(state, Arc::clone(&store), None);
            let first = runtime.block_on(handle.submit_envelope_async_from(
                envelope.clone(),
                Instant::now(),
                ramflux_node_core::RouterEnvelopeOrigin::Gateway,
            ))?;
            assert_eq!(first.outcome, "offline_queued");
            assert!(store.has_local_delivery_envelope(
                &source_root,
                &envelope.envelope_id,
                &envelope.target_delivery_id,
                envelope.created_at + 1,
            )?);
            source_root
        };

        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let restored =
            Arc::new(store.load_router()?.ok_or_else(|| {
                anyhow::anyhow!("router WAL did not restore the committed delivery")
            })?);
        let handle = RouterHandle::tokio(restored, Arc::clone(&store), None);
        let old_home_retry = runtime.block_on(handle.submit_envelope_async_from(
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        ))?;
        assert_eq!(old_home_retry.outcome, "offline_queued");
        assert_eq!(old_home_retry.inbox_seq, Some(1));

        let new_home_retry = runtime.block_on(handle.submit_envelope_async_from(
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Federation,
        ))?;
        assert_eq!(new_home_retry.outcome, "offline_queued");
        assert_eq!(new_home_retry.inbox_seq, Some(1));
        assert_eq!(handle.state().resume(&envelope.target_delivery_id, 0, 10).len(), 1);
        let expires_at = envelope.created_at + i64::from(envelope.ttl);
        store.sweep_delivery_retention(expires_at, false)?;
        assert!(!store.has_local_delivery_envelope(
            &source_root,
            &envelope.envelope_id,
            &envelope.target_delivery_id,
            expires_at,
        )?);
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_bound_ack_and_nack_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_ack", "target_runtime_ack")?;

        let (oracle_state, oracle_store, _oracle_path) = test_router("ack_oracle")?;
        let _submitted = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            no_forward(),
            envelope.clone(),
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )?;
        let ack = ack("env_runtime_ack");
        let ack_request = ramflux_node_core::TargetAckRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            ack: ack.clone(),
        };
        let oracle_ack = crate::router_engine::apply_bound_ack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &ack_request,
        )?;

        let (handle, _handle_path) = test_handle("ack_handle")?;
        let _submitted = handle.submit_envelope_from(
            envelope,
            Instant::now(),
            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
        )?;
        let handle_ack = handle.apply_bound_ack(&ack_request)?;
        assert_eq!(handle_ack, oracle_ack);

        let nack = nack("env_runtime_ack");
        let nack_request = ramflux_node_core::TargetNackRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            nack,
        };
        let oracle_nack_response = crate::router_engine::apply_bound_nack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &nack_request,
        )?;
        let handle_nack_response = handle.apply_bound_nack(&nack_request)?;
        assert_eq!(handle_nack_response, oracle_nack_response);
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_fanout_oracle() -> anyhow::Result<()> {
        let request = fanout_request("env_runtime_fanout")?;

        let (oracle_state, oracle_store, _oracle_path) = test_router("fanout_oracle")?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_laptop", "target_laptop", 2)?;
        let oracle = crate::router_engine::own_device_fanout(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &request,
        )?;

        let (handle, _handle_path) = test_handle("fanout_handle")?;
        register_test_device(handle.state(), "alice", "alice_laptop", "target_laptop", 2)?;
        let via_handle = handle.own_device_fanout(&request)?;

        assert_eq!(via_handle, oracle);
        assert_eq!(via_handle.delivered.len(), 1);
        assert_eq!(via_handle.delivered[0].device_id, "alice_laptop");
        Ok(())
    }

    fn rejected_migration_forward(
        forward: ramflux_node_core::FederatedEnvelopeForwardRequest,
    ) -> ramflux_node_core::FederatedEnvelopeForwardResponse {
        ramflux_node_core::FederatedEnvelopeForwardResponse {
            accepted: false,
            source_node_id: forward.source_node_id,
            target_node_id: forward.target_node_id,
            delivery: ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "forward_in_progress".to_owned(),
                target_delivery_id: forward.envelope.target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            },
        }
    }

    fn run_held_forward_responder(
        listener: &TcpListener,
        entered_tx: &mpsc::Sender<()>,
        release_rx: &mpsc::Receiver<()>,
    ) -> Result<(), String> {
        use std::io::Write;

        const PADDING: usize = 120;

        let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
        let request = ramflux_node_core::read_itest_http_request(&mut stream)
            .map_err(|source| source.to_string())?
            .ok_or_else(|| "missing slow forward request".to_owned())?;
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
        let forward: ramflux_node_core::FederatedEnvelopeForwardRequest = serde_json::from_value(
            body.get("forward").cloned().ok_or_else(|| "missing slow forward body".to_owned())?,
        )
        .map_err(|source| source.to_string())?;
        let response = rejected_migration_forward(forward);
        let body = serde_json::to_vec(&response).map_err(|source| source.to_string())?;
        // Keep the five-second HTTP read timeout alive without completing the body.
        // The engine must remain pending until local submissions release this fixture.
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            PADDING + body.len()
        )
        .map_err(|source| source.to_string())?;
        entered_tx.send(()).map_err(|source| source.to_string())?;
        let mut padding_sent = 0;
        loop {
            match release_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => break,
                Err(mpsc::RecvTimeoutError::Timeout) if padding_sent < PADDING => {
                    stream.write_all(b" ").map_err(|source| source.to_string())?;
                    padding_sent += 1;
                }
                Err(error) => return Err(format!("slow forward was not released: {error}")),
            }
        }
        stream
            .write_all(&[b' '; PADDING][padding_sent..])
            .and_then(|()| stream.write_all(&body))
            .map_err(|source| source.to_string())
    }

    #[test]
    fn slow_migrated_forward_does_not_block_local_engine_submits() -> anyhow::Result<()> {
        let runtime =
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let url =
                format!("http://{}/internal/home-node-migration/forward", listener.local_addr()?);
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                run_held_forward_responder(&listener, &entered_tx, &release_rx)
            });
            let now =
                i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
            let (handle, _path) = migrated_test_handle(&url, 1, Duration::from_secs(60), now)?;
            let handle = Arc::new(handle);
            let slow_handle = Arc::clone(&handle);
            let mut slow = tokio::spawn(async move {
                slow_handle
                    .submit_envelope_async_from(
                        current_envelope("env_runtime_slow_forward", "target_alice")?,
                        Instant::now(),
                        ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                    )
                    .await
            });
            tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(30)))
                .await??;

            let full = tokio::select! {
                result = handle.submit_envelope_async_from(
                    current_envelope("env_runtime_full_forward", "target_alice")?,
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                ) => result?,
                result = &mut slow => {
                    return Err(anyhow::anyhow!(
                        "slow migrated forward completed before the saturated submit: {result:?}"
                    ));
                }
            };
            assert_eq!(full.outcome, "forward_in_progress");

            let mut local_submits = tokio::task::JoinSet::new();
            for index in 0..32 {
                let local_handle = Arc::clone(&handle);
                local_submits.spawn(async move {
                    local_handle
                        .submit_envelope_async_from(
                            current_envelope(
                                &format!("env_runtime_local_under_load_{index}"),
                                &format!("target_runtime_local_{index}"),
                            )?,
                            Instant::now(),
                            ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                        )
                        .await
                });
            }
            let local_results = tokio::time::timeout(Duration::from_secs(30), async {
                while let Some(result) = local_submits.join_next().await {
                    let response = result.map_err(|error| anyhow::anyhow!(error))??;
                    anyhow::ensure!(response.outcome == "offline_queued");
                }
                Ok::<(), anyhow::Error>(())
            });
            tokio::pin!(local_results);
            tokio::select! {
                result = &mut local_results => result??,
                result = &mut slow => {
                    return Err(anyhow::anyhow!(
                        "slow migrated forward completed before local submits: {result:?}"
                    ));
                }
            }
            release_tx.send(())?;
            assert_eq!(slow.await??.outcome, "forward_in_progress");
            match server.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(anyhow::anyhow!(error)),
                Err(_) => Err(anyhow::anyhow!("slow federation server panicked")),
            }
        })
    }

    #[test]
    fn migrated_retry_uses_real_engine_and_federation_store() -> anyhow::Result<()> {
        let runtime =
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let url =
                format!("http://{}/internal/home-node-migration/forward", listener.local_addr()?);
            let now =
                i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
            let new_path = temp_store_path("real_forward_new_home")?;
            let new_store = Arc::new(ramflux_node_core::RouterRedbStore::open(&new_path)?);
            let new_state = Arc::new(ramflux_node_core::RouterCore::new());
            register_test_device_at(&new_state, "alice", "alice_phone", "target_alice", 1, now)?;
            new_store.record_identity_registry(&new_state.mvp1_identities_snapshot())?;
            let new_handle = Arc::new(RouterHandle::tokio(new_state, new_store, None));
            let server_handle = Arc::clone(&new_handle);
            let (delivery_tx, delivery_rx) = mpsc::channel();
            let federation_path = temp_store_path("real_forward_federation")?;
            let federation_store = ramflux_node_core::FederationRedbStore::open(&federation_path)?;
            let server = thread::spawn(move || {
                run_real_forward_responder(
                    &listener,
                    &server_handle,
                    &federation_store,
                    &delivery_tx,
                )
            });
            let (old_handle, _old_path) =
                migrated_test_handle(&url, 2, Duration::from_secs(2), now)?;
            let envelope = current_envelope("env_runtime_real_forward", "target_alice")?;
            let first = old_handle
                .submit_envelope_async_from(
                    envelope.clone(),
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )
                .await?;
            let first_delivery = match delivery_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(outcome) => outcome,
                Err(channel_error) => {
                    return match server.join() {
                        Ok(Ok(())) => Err(anyhow::anyhow!(channel_error)),
                        Ok(Err(error)) => Err(anyhow::anyhow!(error)),
                        Err(_) => Err(anyhow::anyhow!("real federation server panicked")),
                    };
                }
            };
            assert_eq!(
                first.outcome, "forwarded_home_node_migrated",
                "new-home delivery outcome: {first_delivery}"
            );
            let retry = old_handle
                .submit_envelope_async_from(
                    envelope,
                    Instant::now(),
                    ramflux_node_core::RouterEnvelopeOrigin::Gateway,
                )
                .await?;
            let retry_delivery = delivery_rx.recv_timeout(Duration::from_secs(1))?;
            assert_eq!(
                retry.outcome, "forwarded_home_node_migrated",
                "new-home retry outcome: {retry_delivery}"
            );
            assert_eq!(new_handle.state().resume("target_alice", 0, 10).len(), 1);
            match server.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(anyhow::anyhow!(error)),
                Err(_) => Err(anyhow::anyhow!("real federation server panicked")),
            }
        })
    }

    fn run_real_forward_responder(
        listener: &TcpListener,
        router: &RouterHandle,
        federation_store: &ramflux_node_core::FederationRedbStore,
        delivery_tx: &mpsc::Sender<String>,
    ) -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|source| source.to_string())?;
        for _attempt in 0..2 {
            let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
            let request = ramflux_node_core::read_itest_http_request(&mut stream)
                .map_err(|source| source.to_string())?
                .ok_or_else(|| "missing real forward request".to_owned())?;
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
            let forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
                serde_json::from_value(
                    body.get("forward")
                        .cloned()
                        .ok_or_else(|| "missing real forward body".to_owned())?,
                )
                .map_err(|source| source.to_string())?;
            let source = router
                .state()
                .authenticated_envelope_source_durable(&forward.envelope, router.store())
                .map_err(|source| source.to_string())?;
            let delivered = federation_store
                .deliver_inbound_forward_once_with_lease(
                    &source,
                    &forward,
                    ramflux_node_core::now_unix_seconds(),
                    2,
                    || {
                        runtime
                            .block_on(router.submit_envelope_async_from(
                                forward.envelope.clone(),
                                Instant::now(),
                                ramflux_node_core::RouterEnvelopeOrigin::Federation,
                            ))
                            .map_err(|source| {
                                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                            })
                    },
                )
                .map_err(|source| source.to_string())?;
            let delivery = delivered.unwrap_or_else(|| ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "duplicate_federated_forward".to_owned(),
                target_delivery_id: forward.envelope.target_delivery_id.clone(),
                inbox_seq: None,
                cursor: None,
                nack: None,
            });
            let response = ramflux_node_core::FederatedEnvelopeForwardResponse {
                accepted: matches!(
                    delivery.outcome.as_str(),
                    "online" | "offline_queued" | "duplicate_federated_forward"
                ),
                source_node_id: forward.source_node_id,
                target_node_id: forward.target_node_id,
                delivery,
            };
            delivery_tx
                .send(response.delivery.outcome.clone())
                .map_err(|source| source.to_string())?;
            ramflux_node_core::write_itest_json_response(&mut stream, "200 OK", &response)
                .map_err(|source| source.to_string())?;
        }
        Ok(())
    }

    #[test]
    fn local_federation_forward_client_posts_source_node_and_admin_token() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/internal/home-node-migration/forward", listener.local_addr()?);
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
            let request = ramflux_node_core::read_itest_http_request(&mut stream)
                .map_err(|source| source.to_string())?
                .ok_or_else(|| "missing forward request".to_owned())?;
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|source| source.to_string())?;
            let admin_token = body
                .get("admin_token")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing admin token".to_owned())?
                .to_owned();
            let forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
                serde_json::from_value(
                    body.get("forward")
                        .cloned()
                        .ok_or_else(|| "missing forward request".to_owned())?,
                )
                .map_err(|source| source.to_string())?;
            let response = ramflux_node_core::FederatedEnvelopeForwardResponse {
                accepted: true,
                source_node_id: forward.source_node_id.clone(),
                target_node_id: forward.target_node_id.clone(),
                delivery: ramflux_node_core::EnvelopeSubmitResponse {
                    migration_refusal: None,
                    outcome: "federation_spooled_offline_peer".to_owned(),
                    target_delivery_id: forward.envelope.target_delivery_id.clone(),
                    inbox_seq: None,
                    cursor: None,
                    nack: None,
                },
            };
            request_tx
                .send((request.path, admin_token, forward))
                .map_err(|source| source.to_string())?;
            ramflux_node_core::write_itest_json_response(&mut stream, "200 OK", &response)
                .map_err(|source| source.to_string())
        });

        let client = LocalFederationForwardClient {
            url,
            admin_token: Some("local-token".to_owned()),
            source_node_id: "node-a".to_owned(),
        };
        let response = client.forward(&forward_plan(), Duration::from_secs(20))?;
        assert!(response.accepted);
        assert_eq!(response.source_node_id, "node-a");
        assert_eq!(response.target_node_id, "node-b");
        assert_eq!(response.delivery.outcome, "federation_spooled_offline_peer");
        let (path, admin_token, forward) = request_rx.recv()?;
        assert_eq!(path, "/internal/home-node-migration/forward");
        assert_eq!(forward.source_node_id, "node-a");
        assert_eq!(admin_token, "local-token");
        assert_eq!(forward.target_node_id, "node-b");
        match server.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!(error)),
            Err(_) => Err(anyhow::anyhow!("stub federation server panicked")),
        }
    }

    fn test_handle(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
        let (state, store, path) = test_router(name)?;
        Ok((RouterHandle::tokio(state, store, None), path))
    }

    fn migrated_test_handle(
        url: &str,
        concurrency: usize,
        forward_timeout: Duration,
        now: i64,
    ) -> anyhow::Result<(RouterHandle, PathBuf)> {
        let path = temp_store_path("migrated_runtime")?;
        crate::router_engine::window_tests::fixture_at(
            &path,
            "target_alice",
            Some(u64::try_from(now)?),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        register_test_device_at(&state, "alice", "alice_phone", "target_alice", 1, now)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
        let client = LocalFederationForwardClient {
            url: url.to_owned(),
            admin_token: Some("local-token".to_owned()),
            source_node_id: "node-old.example".to_owned(),
        };
        let runtime = TokioRouterRuntime::new_with_forward_limits(
            state,
            store,
            Some(client),
            concurrency,
            forward_timeout,
        );
        Ok((RouterHandle::Tokio(Arc::new(runtime)), path))
    }

    pub(crate) fn test_router(
        name: &str,
    ) -> anyhow::Result<(
        Arc<ramflux_node_core::RouterCore>,
        Arc<ramflux_node_core::RouterRedbStore>,
        PathBuf,
    )> {
        let path = temp_store_path(name)?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        register_test_device(&state, "alice", "alice_phone", "target_alice", 1)?;
        store.record_identity_registry(&state.mvp1_identities_snapshot())?;
        Ok((state, store, path))
    }

    pub(crate) fn current_envelope(
        envelope_id: &str,
        target_delivery_id: &str,
    ) -> anyhow::Result<ramflux_protocol::Envelope> {
        let mut envelope = envelope(envelope_id, target_delivery_id, DeliveryClass::OpaqueEvent);
        envelope.created_at =
            i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
        let root = ramflux_crypto::create_identity_root(
            "alice",
            ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice"),
        );
        envelope.ext.ext.insert(
            "source_root_commitment".into(),
            serde_json::json!(ramflux_crypto::identity_root_commitment(
                &root.signing_key.verifying_key()
            )),
        );
        envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(
            &envelope,
            ramflux_crypto::blake3_256("ramflux.test.runtime.device.v1", b"alice/alice_phone"),
        )?;
        let authority = ramflux_node_core::RouterCore::new();
        register_test_device_at(
            &authority,
            "alice",
            "alice_phone",
            "target_alice",
            1,
            envelope.created_at,
        )?;
        authority.refresh_registered_envelope_authority(&mut envelope)?;
        Ok(envelope)
    }

    fn fanout_request(
        envelope_id: &str,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest> {
        Ok(ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
            principal_id: "alice".to_owned(),
            source_device_id: "alice_phone".to_owned(),
            envelope: current_envelope(envelope_id, "target_unused")?,
        })
    }

    fn forward_plan() -> ramflux_node_core::HomeNodeMigrationForwardPlan {
        ramflux_node_core::HomeNodeMigrationForwardPlan {
            migration_evidence: None,
            target_delivery_id: "target-b".to_owned(),
            proof_hash: "proof-hash".to_owned(),
            new_home_node: "node-b".to_owned(),
            route: ramflux_node_core::HomeNodeRouteRecord {
                identity_commitment: "identity-b".to_owned(),
                home_node: "node-b".to_owned(),
                home_node_key_hash: "node-b-key-hash".to_owned(),
                node_public_key: "node-b-public-key".to_owned(),
                node_endpoint: "node-b:7443".to_owned(),
                route_record_hash: "route-record-hash".to_owned(),
                migration_proof_hash: "migration-proof-hash".to_owned(),
                route_update_proof_hash: "route-update-proof-hash".to_owned(),
                updated_at: 1,
                expires_at: 2,
            },
            envelope: envelope("env_forward", "target-b", DeliveryClass::OpaqueEvent),
            forward_count: 1,
        }
    }

    fn envelope(
        envelope_id: &str,
        target_delivery_id: &str,
        delivery_class: DeliveryClass,
    ) -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.envelope.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "alice".to_owned(),
            source_device_id: "alice_phone".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class,
            priority: Priority::Normal,
            ttl: 3_600,
            created_at: 1_760_000_000,
            encrypted_payload: "ciphertext".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn ack(envelope_id: &str) -> ramflux_protocol::Ack {
        ramflux_protocol::Ack {
            schema: "ramflux.ack.v1".to_owned(),
            version: 1,
            domain: "ramflux.ack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            ack_id: format!("ack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            received_at: 1_760_000_010,
            cursor_after: None,
        }
    }

    fn nack(envelope_id: &str) -> ramflux_protocol::Nack {
        ramflux_protocol::Nack {
            schema: "ramflux.nack.v1".to_owned(),
            version: 1,
            domain: "ramflux.nack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            nack_id: format!("nack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            reason: ramflux_protocol::NackReason::MissingDependency,
            received_at: 1_760_000_010,
            retry_after: Some(30),
            proof_hash: None,
            new_home_node_hint: None,
        }
    }

    fn signed_fields() -> SignedFields {
        SignedFields {
            signing_key_id: "test_key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "test_signature".to_owned(),
        }
    }

    fn register_test_device(
        state: &ramflux_node_core::RouterCore,
        principal_id: &str,
        device_id: &str,
        target_delivery_id: &str,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let _request = register_test_device_at(
            state,
            principal_id,
            device_id,
            target_delivery_id,
            nonce,
            1_760_000_010 + i64::try_from(nonce)?,
        )?;
        Ok(())
    }

    pub(crate) fn register_test_device_at(
        state: &ramflux_node_core::RouterCore,
        principal_id: &str,
        device_id: &str,
        target_delivery_id: &str,
        _nonce: u64,
        now: i64,
    ) -> anyhow::Result<ramflux_node_core::IdentityRegisterRequest> {
        let root_seed = ramflux_crypto::blake3_256(
            "ramflux.test.registration_root.v1",
            principal_id.as_bytes(),
        );
        let device_seed = ramflux_crypto::blake3_256(
            "ramflux.test.runtime.device.v1",
            format!("{principal_id}/{device_id}").as_bytes(),
        );
        let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
        let device = ramflux_crypto::create_device_branch(principal_id, device_id, 1, device_seed);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::blake3_256(
            "ramflux.test.runtime.agreement.v1",
            format!("{principal_id}/{device_id}").as_bytes(),
        ));
        let proof = ramflux_crypto::authorize_device_branch_v2(
            &root,
            &device,
            ramflux_crypto::BranchAuthorization {
                audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
                capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
                issued_at: now.saturating_sub(10),
                expires_at: now.saturating_add(3_600),
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                agreement_identity_public_key: agreement.public,
            },
        )?;
        let commitment =
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
        let previous = state.signed_device_set(&commitment);
        let mut entries = previous.as_ref().map_or_else(Vec::new, |set| set.devices.clone());
        let keys = ramflux_crypto::device_key_commitments(
            &ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes()),
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
        entries.retain(|entry| entry.device_id != device_id);
        entries.push(ramflux_protocol::SignedDeviceSetEntry {
            device_id: device_id.into(),
            device_epoch: 1,
            signing_key_commitment: keys.0,
            agreement_key_commitment: keys.1,
            status: ramflux_protocol::DeviceSetStatus::Active,
            revoked_at: None,
        });
        let device_set = ramflux_crypto::sign_device_set(
            &root,
            ramflux_crypto::DeviceSetSigningInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                device_set_epoch: previous.map_or(1, |set| set.device_set_epoch + 1),
                devices: entries,
            },
        )?;
        let root_public_key =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
        let request = ramflux_node_core::IdentityRegisterRequest {
            device_set: Some(device_set),
            principal_commitment: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_public_key_bytes,
            ),
            root_public_key,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: target_delivery_id.to_owned(),
            gateway_id: "ramflux-gateway".to_owned(),
            session_id: format!("session_{device_id}"),
            push_alias_hash: Some(format!("push_{device_id}")),
            now,
            registration_pow: None,
            source_ip_hash: Some("source_ip_hash".to_owned()),
        };
        state.mvp1_register_identity(&request)?;
        Ok(request)
    }

    fn temp_store_path(test_name: &str) -> anyhow::Result<PathBuf> {
        let suffix = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        Ok(std::env::temp_dir().join(format!(
            "ramflux-router-{test_name}-{}-{}.redb",
            std::process::id(),
            suffix
        )))
    }
    mod publication;
    mod sender_retry;
}
