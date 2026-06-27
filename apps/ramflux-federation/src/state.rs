// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub(crate) struct SharedFederationTrustState {
    current: RwLock<Arc<ramflux_node_core::FederationTrustState>>,
    write_gate: Mutex<()>,
}

impl SharedFederationTrustState {
    pub(crate) fn new(initial: ramflux_node_core::FederationTrustState) -> Self {
        Self { current: RwLock::new(Arc::new(initial)), write_gate: Mutex::new(()) }
    }

    pub(crate) fn snapshot(
        &self,
    ) -> Result<Arc<ramflux_node_core::FederationTrustState>, ramflux_node_core::NodeCoreError>
    {
        self.current
            .read()
            .map_err(|_error| {
                ramflux_node_core::NodeCoreError::ItestHttp(
                    "federation state snapshot lock poisoned".to_owned(),
                )
            })
            .map(|state| Arc::clone(&state))
    }

    pub(crate) fn update_and_save<T>(
        &self,
        store: &ramflux_node_core::FederationRedbStore,
        update: impl FnOnce(
            &mut ramflux_node_core::FederationTrustState,
        ) -> Result<T, ramflux_node_core::NodeCoreError>,
    ) -> Result<T, ramflux_node_core::NodeCoreError> {
        let _write_gate = self.write_gate.lock().map_err(|_error| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "federation state write lock poisoned".to_owned(),
            )
        })?;
        let mut next = (*self.snapshot()?).clone();
        let result = update(&mut next)?;
        store.save_state(&next)?;
        let mut current = self.current.write().map_err(|_error| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "federation state publish lock poisoned".to_owned(),
            )
        })?;
        *current = Arc::new(next);
        Ok(result)
    }
}

#[derive(Clone)]
pub(crate) struct RouterMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) client: ramflux_transport::MeshHttpClient,
}

#[derive(Clone)]
pub(crate) struct FederationDiscoverySurface {
    pub(crate) node_id: String,
    pub(crate) public_endpoint: String,
    pub(crate) node_public_key: String,
    pub(crate) node_ca_cert_pem: String,
    pub(crate) node_signing_seed: [u8; 32],
    pub(crate) protocol_versions: Vec<String>,
    pub(crate) transport_backends: Vec<String>,
    pub(crate) node_capabilities: Vec<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum MeshInboundTransport {
    Tcp,
    Quic,
}

#[derive(Default)]
pub(crate) struct FederationMeshObservability {
    quic_listener_ready: AtomicBool,
    tcp_inbound_s8_envelopes: AtomicU64,
    quic_inbound_s8_envelopes: AtomicU64,
    receive_total: FederationTiming,
    receive_target_check: FederationTiming,
    receive_trust_snapshot: FederationTiming,
    receive_policy_check: FederationTiming,
    receive_pin_lookup: FederationTiming,
    receive_signature_verify: FederationTiming,
    receive_signature_body: FederationTiming,
    receive_signature_signature_parse: FederationTiming,
    receive_signature_key_parse: FederationTiming,
    receive_signature_ed25519_verify: FederationTiming,
    receive_router_post: FederationTiming,
    quic_listener_local_addr: Mutex<Option<String>>,
    quic_listener_last_error: Mutex<Option<String>>,
}

#[derive(serde::Serialize)]
pub(crate) struct FederationMeshObservabilitySnapshot {
    pub(crate) quic_listener_ready: bool,
    pub(crate) quic_listener_local_addr: Option<String>,
    pub(crate) quic_listener_last_error: Option<String>,
    pub(crate) tcp_inbound_s8_envelopes: u64,
    pub(crate) quic_inbound_s8_envelopes: u64,
    pub(crate) receive_perf: FederationReceivePerfSnapshot,
    pub(crate) transport_perf: ramflux_transport::MeshHttpPerfSnapshot,
}

#[derive(Default)]
struct FederationTiming {
    count: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
}

#[derive(serde::Serialize)]
pub(crate) struct FederationTimingSnapshot {
    pub(crate) count: u64,
    pub(crate) total_us: u64,
    pub(crate) max_us: u64,
}

#[derive(serde::Serialize)]
pub(crate) struct FederationReceivePerfSnapshot {
    pub(crate) total: FederationTimingSnapshot,
    pub(crate) target_check: FederationTimingSnapshot,
    pub(crate) trust_snapshot: FederationTimingSnapshot,
    pub(crate) policy_check: FederationTimingSnapshot,
    pub(crate) pin_lookup: FederationTimingSnapshot,
    pub(crate) signature_verify: FederationTimingSnapshot,
    pub(crate) signature_body: FederationTimingSnapshot,
    pub(crate) signature_signature_parse: FederationTimingSnapshot,
    pub(crate) signature_key_parse: FederationTimingSnapshot,
    pub(crate) signature_ed25519_verify: FederationTimingSnapshot,
    pub(crate) router_post: FederationTimingSnapshot,
}

impl FederationTiming {
    fn record(&self, elapsed: std::time::Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(micros, Ordering::Relaxed);
        self.max_us.fetch_max(micros, Ordering::Relaxed);
    }

    fn snapshot(&self) -> FederationTimingSnapshot {
        FederationTimingSnapshot {
            count: self.count.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
        }
    }
}

impl FederationMeshObservability {
    pub(crate) fn mark_quic_listener_ready(&self, local_addr: String) {
        self.quic_listener_ready.store(true, Ordering::Release);
        if let Ok(mut addr) = self.quic_listener_local_addr.lock() {
            *addr = Some(local_addr);
        }
        if let Ok(mut error) = self.quic_listener_last_error.lock() {
            *error = None;
        }
    }

    pub(crate) fn mark_quic_listener_error(&self, error: &str) {
        self.quic_listener_ready.store(false, Ordering::Release);
        if let Ok(mut last_error) = self.quic_listener_last_error.lock() {
            *last_error = Some(error.to_owned());
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn mark_quic_listener_disabled(&self) {
        self.quic_listener_ready.store(false, Ordering::Release);
        if let Ok(mut last_error) = self.quic_listener_last_error.lock() {
            *last_error = Some("disabled by itest affordance".to_owned());
        }
    }

    pub(crate) fn record_inbound_s8_envelope(&self, transport: MeshInboundTransport) {
        let counter = match transport {
            MeshInboundTransport::Tcp => &self.tcp_inbound_s8_envelopes,
            MeshInboundTransport::Quic => &self.quic_inbound_s8_envelopes,
        };
        counter.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn record_receive_total(&self, elapsed: std::time::Duration) {
        self.receive_total.record(elapsed);
    }

    pub(crate) fn record_receive_target_check(&self, elapsed: std::time::Duration) {
        self.receive_target_check.record(elapsed);
    }

    pub(crate) fn record_receive_trust_snapshot(&self, elapsed: std::time::Duration) {
        self.receive_trust_snapshot.record(elapsed);
    }

    pub(crate) fn record_receive_policy_check(&self, elapsed: std::time::Duration) {
        self.receive_policy_check.record(elapsed);
    }

    pub(crate) fn record_receive_pin_lookup(&self, elapsed: std::time::Duration) {
        self.receive_pin_lookup.record(elapsed);
    }

    pub(crate) fn record_receive_signature_verify(&self, elapsed: std::time::Duration) {
        self.receive_signature_verify.record(elapsed);
    }

    pub(crate) fn record_receive_signature_segments(
        &self,
        timings: ramflux_node_core::FederatedEnvelopeForwardVerifyTimings,
    ) {
        self.receive_signature_body.record(timings.signing_body);
        self.receive_signature_signature_parse.record(timings.signature_parse);
        self.receive_signature_key_parse.record(timings.public_key_parse);
        self.receive_signature_ed25519_verify.record(timings.verify);
    }

    pub(crate) fn record_receive_router_post(&self, elapsed: std::time::Duration) {
        self.receive_router_post.record(elapsed);
    }

    pub(crate) fn snapshot(&self) -> FederationMeshObservabilitySnapshot {
        FederationMeshObservabilitySnapshot {
            quic_listener_ready: self.quic_listener_ready.load(Ordering::Acquire),
            quic_listener_local_addr: self
                .quic_listener_local_addr
                .lock()
                .ok()
                .and_then(|addr| addr.clone()),
            quic_listener_last_error: self
                .quic_listener_last_error
                .lock()
                .ok()
                .and_then(|error| error.clone()),
            tcp_inbound_s8_envelopes: self.tcp_inbound_s8_envelopes.load(Ordering::Acquire),
            quic_inbound_s8_envelopes: self.quic_inbound_s8_envelopes.load(Ordering::Acquire),
            receive_perf: FederationReceivePerfSnapshot {
                total: self.receive_total.snapshot(),
                target_check: self.receive_target_check.snapshot(),
                trust_snapshot: self.receive_trust_snapshot.snapshot(),
                policy_check: self.receive_policy_check.snapshot(),
                pin_lookup: self.receive_pin_lookup.snapshot(),
                signature_verify: self.receive_signature_verify.snapshot(),
                signature_body: self.receive_signature_body.snapshot(),
                signature_signature_parse: self.receive_signature_signature_parse.snapshot(),
                signature_key_parse: self.receive_signature_key_parse.snapshot(),
                signature_ed25519_verify: self.receive_signature_ed25519_verify.snapshot(),
                router_post: self.receive_router_post.snapshot(),
            },
            transport_perf: ramflux_transport::mesh_perf_snapshot(),
        }
    }
}

pub(crate) type SharedMeshObservability = Arc<FederationMeshObservability>;

#[cfg(feature = "itest-http")]
#[derive(serde::Deserialize)]
pub(crate) struct ItestMvp4TrustStatusRequest {
    pub(crate) node_id: String,
    pub(crate) trust_status: ramflux_node_core::FederationTrustStatus,
    pub(crate) updated_at: u64,
}

#[derive(serde::Deserialize)]
pub(crate) struct S12DiscoveryResolveRequest {
    pub(crate) request: ramflux_node_core::FederationDiscoveryRequest,
    #[serde(default)]
    pub(crate) well_known_record: Option<ramflux_node_core::FederationServerRecord>,
    #[serde(default)]
    pub(crate) rotation: Option<ramflux_node_core::FederationNodeKeyRotation>,
}

#[derive(serde::Deserialize)]
pub(crate) struct FederationAdminDiscoverRequest {
    pub(crate) admin_token: String,
    pub(crate) discovery: S12DiscoveryResolveRequest,
}

#[derive(serde::Deserialize)]
pub(crate) struct FederationAdminPeerRequest {
    pub(crate) admin_token: String,
    pub(crate) peer_node_id: String,
    #[serde(default)]
    pub(crate) peer_well_known_url: Option<String>,
    #[serde(default)]
    pub(crate) invite_endpoint: Option<String>,
    #[serde(default)]
    pub(crate) dns_srv_records: Vec<ramflux_node_core::FederationSrvRecord>,
    #[serde(default)]
    pub(crate) address_records: Vec<String>,
    #[serde(default)]
    pub(crate) directory_endpoint: Option<String>,
    #[serde(default)]
    pub(crate) capabilities: Vec<String>,
    #[serde(default)]
    pub(crate) now: Option<u64>,
}

#[derive(serde::Serialize)]
pub(crate) struct FederationAdminPeerResponse {
    pub(crate) discovered: ramflux_node_core::FederationDiscoveryResult,
    pub(crate) admitted: ramflux_node_core::FederationHandshakeAdmissionResponse,
    pub(crate) can_deliver: bool,
}

#[cfg(feature = "itest-http")]
#[derive(serde::Serialize)]
pub(crate) struct ItestMvp4CanDeliverResponse {
    pub(crate) node_id: String,
    pub(crate) can_deliver: bool,
}
