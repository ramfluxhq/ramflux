// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native custody admission; no legacy proof can enter this service.
use crate::{CustodyPublication, RouterCore, RouterRedbStore, custody_sessions::CustodyLeases};
use ramflux_crypto::{
    RootQualifiedDeviceRef,
    custody::{
        ProofChannel, VerifiedNodeRecord, VerifiedRecord, verify_branch_proof_v3,
        verify_node_identity_record,
    },
};
use ramflux_protocol::custody::{
    BindingMode, BranchProofV3, CUSTODY_REQUEST_PATH, CustodyClientFrame, CustodyMeshRequest,
    CustodyPeer, CustodyProofAction, CustodyRefusal, CustodyServerFrame, CustodySession,
    CustodySessionAction, DeviceRef, Envelope, Publication, RelayAcceptance, custody_action_hash,
    custody_session_action_hash, decode, object_hash,
};
use std::{sync::Mutex, time::Instant};

/// Actual client-facing connection evidence, supplied only by the TLS listener.
/// No deserializer or forwarded-header constructor exists.
#[derive(Clone, Copy)]
pub struct CustodyTlsContext<'a> {
    pub connection_id: &'a str,
    pub remote_ip: &'a str,
    pub mode: BindingMode,
    pub exporter: Option<[u8; 32]>,
}
enum Origin {
    Proxy,
    ClientTls(Option<String>),
}

mod admission;
use admission::{ProofAttempt, SessionRequest};
#[derive(Clone, Copy)]
struct Scope<'a> {
    router: &'a RouterCore,
    store: &'a RouterRedbStore,
    peer: &'a str,
    now: u64,
    tick: Instant,
    origin: &'a Origin,
    permit: Option<&'a crate::CustodyIngressPermit>,
}

pub struct CustodyService {
    node: VerifiedNodeRecord,
    audience: String,
    allow_unbound: bool,
    leases: Mutex<CustodyLeases>,
    admission: Mutex<()>,
}
fn invalid(_: impl std::fmt::Display) -> CustodyRefusal {
    CustodyRefusal::InvalidInput
}
fn persistence(_: impl std::fmt::Display) -> CustodyRefusal {
    CustodyRefusal::PersistenceUnavailable
}
fn target(reference: &DeviceRef) -> Result<String, CustodyRefusal> {
    ramflux_protocol::qualified_device_id(&reference.account_anchor, &reference.device_id)
        .map_err(invalid)
}
impl CustodyService {
    /// Enable only after authenticating the receiving node against an independent pin.
    /// # Errors
    /// Rejects unadvertised no-binding mode and persistence/continuity failures.
    pub fn new(
        node: VerifiedNodeRecord,
        allow_unbound: bool,
        store: &RouterRedbStore,
        now: u64,
    ) -> Result<Self, CustodyRefusal> {
        if allow_unbound
            && !node.envelope().body.channel_binding_modes.contains(&BindingMode::NoChannelBinding)
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        store.observe_custody_node(&node, now).map_err(persistence)?;
        let audience = node.envelope().body.node_id.clone();
        Ok(Self {
            node,
            audience,
            allow_unbound,
            leases: Mutex::new(CustodyLeases::default()),
            admission: Mutex::new(()),
        })
    }
    /// Compare a separately provisioned public listener certificate with signed metadata.
    #[must_use]
    pub fn accepts_public_certificate(&self, hash: &str) -> bool {
        self.node.envelope().body.client_tls_certificate_sha256.as_deref() == Some(hash)
    }
    /// Release disconnected grants without removing consumed nonce/proof markers.
    pub fn disconnect(&self, peer: &str, connection: &str) {
        let _admission = self.admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Ok(holder) = holder(peer, connection) {
            self.leases().disconnect(&holder);
        }
    }
    fn leases(&self) -> std::sync::MutexGuard<'_, CustodyLeases> {
        self.leases.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Authenticated mesh ingress. `peer` comes from mTLS identity, never request JSON.
    /// # Errors
    /// Failure is represented as a typed refusal frame; no legacy fallback is attempted.
    pub fn mesh(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        request: CustodyMeshRequest,
        peer: &str,
        now: u64,
    ) -> CustodyServerFrame {
        if peer != "ramflux-gateway" {
            return CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused };
        }
        match self.dispatch(
            request,
            Scope {
                router,
                store,
                peer,
                now,
                tick: Instant::now(),
                origin: &Origin::Proxy,
                permit: None,
            },
        ) {
            Ok(frame) => frame,
            Err(code) => CustodyServerFrame::Refused { code },
        }
    }
    fn dispatch(
        &self,
        request: CustodyMeshRequest,
        scope: Scope<'_>,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let _admission = self.admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Queueing behind another writer must never extend authentication deadlines.
        let scope = Scope {
            now: scope.now.saturating_add(scope.tick.elapsed().as_secs()),
            tick: Instant::now(),
            ..scope
        };
        match request {
            CustodyMeshRequest::Disconnect { connection_id } => {
                self.leases().disconnect(&holder(scope.peer, &connection_id)?);
                Ok(CustodyServerFrame::Closed)
            }
            CustodyMeshRequest::NodeIdentity { record_hash } => {
                let store = scope.store;
                let record = if let Some(hash) = record_hash {
                    store
                        .custody_node_history(&hash)
                        .map_err(persistence)?
                        .ok_or(CustodyRefusal::AuthorityUnavailable)?
                } else {
                    self.node.envelope().clone()
                };
                Ok(CustodyServerFrame::NodeIdentity {
                    record: Box::new(record),
                    audience: self.audience.clone(),
                    binding_mode: BindingMode::HomeRelayReceipt,
                    proxy_key_custody: Some("software".into()),
                })
            }
            request @ CustodyMeshRequest::Challenge { .. } => self.challenge(scope, request),
            CustodyMeshRequest::Prove { action, proof, receipt, connection_id } => {
                self.prove(scope, ProofAttempt { action, proof, receipt, connection_id })
            }
            CustodyMeshRequest::Request { session_id, request, action, connection_id } => {
                self.request(scope, SessionRequest { session_id, request, action, connection_id })
            }
        }
    }
}

fn holder(peer: &str, connection: &str) -> Result<String, CustodyRefusal> {
    let bytes = ramflux_protocol::decode_base64url(connection).map_err(invalid)?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != connection {
        return Err(CustodyRefusal::BindingRefused);
    }
    Ok(format!("{peer}/{connection}"))
}
pub(crate) fn validate_bundle(
    authority: &VerifiedRecord,
    reference: &DeviceRef,
    value: &serde_json::Value,
    capability: &str,
    now: u64,
) -> Result<(), CustodyRefusal> {
    let cert = authority.authorize(reference, capability, now).map_err(invalid)?;
    let bytes = ramflux_protocol::canonical_json_bytes(value).map_err(invalid)?;
    let bundle: ramflux_crypto::PrekeyBundle = decode(&bytes, 64 * 1024).map_err(invalid)?;
    let key = ramflux_crypto::verifying_key_from_base64url(&cert.branch_signing_public_key)
        .map_err(invalid)?;
    if bundle.device_id != reference.device_id
        || bundle.device_epoch != reference.device_epoch
        || bundle.identity_commitment != authority.envelope().body.principal_id
        || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
        || ramflux_protocol::encode_base64url(bundle.device_agreement_x25519_public)
            != cert.agreement_identity_public_key
        || bundle.identity_key != bundle.device_agreement_x25519_public
    {
        return Err(CustodyRefusal::InvalidInput);
    }
    ramflux_crypto::verify_prekey_bundle(&key, &bundle).map_err(invalid)
}

impl CustodyService {
    /// Client-facing TLS ingress. The listener obtains exporter material on the actual stream.
    /// No mesh caller can supply this evidence; no weaker binding fallback is attempted.
    #[must_use]
    pub fn tls(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        frame: CustodyClientFrame,
        context: CustodyTlsContext<'_>,
        now: u64,
    ) -> CustodyServerFrame {
        self.tls_with_permit(router, store, frame, context, (now, None))
    }
    /// Direct ingress with a listener-owned grant fence.
    #[must_use]
    pub fn tls_with_permit(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        frame: CustodyClientFrame,
        context: CustodyTlsContext<'_>,
        grant: (u64, Option<&crate::CustodyIngressPermit>),
    ) -> CustodyServerFrame {
        let (now, permit) = grant;
        let result = (|| {
            if context.mode == BindingMode::HomeRelayReceipt
                || !self.node.envelope().body.channel_binding_modes.contains(&context.mode)
                || (context.mode == BindingMode::NoChannelBinding && !self.allow_unbound)
            {
                return Err(CustodyRefusal::BindingRefused);
            }
            let observed =
                context.exporter.as_ref().map(ramflux_crypto::custody::branch_exporter_hash);
            let request = match frame {
                CustodyClientFrame::CustodyOpen { binding_mode } => {
                    if binding_mode != context.mode {
                        return Err(CustodyRefusal::BindingRefused);
                    }
                    if binding_mode == BindingMode::NoChannelBinding {
                        tracing::warn!(
                            peer = context.remote_ip,
                            "custody direct TLS explicitly uses no_channel_binding"
                        );
                    }
                    return Ok(CustodyServerFrame::NodeIdentity {
                        record: Box::new(self.node.envelope().clone()),
                        audience: self.audience.clone(),
                        binding_mode,
                        proxy_key_custody: None,
                    });
                }
                CustodyClientFrame::NodeIdentity { record_hash } => {
                    CustodyMeshRequest::NodeIdentity { record_hash }
                }
                CustodyClientFrame::Challenge { device_ref, action } => {
                    CustodyMeshRequest::Challenge {
                        device_ref,
                        action,
                        binding_mode: context.mode,
                        client_source: context.remote_ip.into(),
                        connection_id: context.connection_id.into(),
                    }
                }
                CustodyClientFrame::Prove { action, proof } => {
                    if proof.body.binding_mode != context.mode || observed.is_none() {
                        return Err(CustodyRefusal::BindingRefused);
                    }
                    CustodyMeshRequest::Prove {
                        action,
                        proof,
                        receipt: None,
                        connection_id: context.connection_id.into(),
                    }
                }
                CustodyClientFrame::Request { session_id, request, action } => {
                    CustodyMeshRequest::Request {
                        session_id,
                        request,
                        action,
                        connection_id: context.connection_id.into(),
                    }
                }
            };
            self.dispatch(
                request,
                Scope {
                    router,
                    store,
                    peer: "direct-tls",
                    now,
                    tick: Instant::now(),
                    origin: &Origin::ClientTls(observed),
                    permit,
                },
            )
        })();
        match result {
            Ok(frame) => frame,
            Err(code) => CustodyServerFrame::Refused { code },
        }
    }
}
