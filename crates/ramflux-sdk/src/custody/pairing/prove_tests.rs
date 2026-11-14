// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production `ProofPairingNative::from_connection` drives `CustodyConnection::prove`.
use super::{PairingNative, ProofPairingNative};
use crate::SdkError;
use crate::custody::{CustodyConnection, CustodyNetworkConfig, memory_vault::MemoryPrimaryVault};
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, CreateTicket};
use ramflux_protocol::custody::{
    BindingMode, BranchChallenge, CustodyClientFrame, CustodyProofAction, CustodyRefusal,
    CustodyServerFrame, CustodySession, Envelope, NodeIdentityRecord, object_hash,
};
use ramflux_protocol::encode_base64url;
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct MockGateway {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    replies: VecDeque<Vec<u8>>,
    node: Envelope<NodeIdentityRecord>,
    accept_pairing: bool,
    _lifetime: Arc<()>,
}

impl GatewaySessionFrameSink for MockGateway {
    fn verify_custody_certificate_pin(&self, _: &str) -> Result<(), TransportError> {
        Ok(())
    }

    fn custody_exporter(&self, _: &[u8; 32]) -> Result<[u8; 32], TransportError> {
        Ok([5; 32])
    }

    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.sent.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(frame.to_vec());
        let reply = reply_for(frame, &self.node, self.accept_pairing);
        self.replies.push_back(reply);
        Box::pin(async { Ok(()) })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for MockGateway {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        let frame = self.replies.pop_front();
        Box::pin(async move { frame.ok_or(TransportError::ShutdownDraining) })
    }
}

fn reply_for(frame: &[u8], node: &Envelope<NodeIdentityRecord>, accept_pairing: bool) -> Vec<u8> {
    let parsed: CustodyClientFrame = match serde_json::from_slice(frame) {
        Ok(parsed) => parsed,
        Err(_) => return refused(CustodyRefusal::InvalidInput),
    };
    let response = match parsed {
        CustodyClientFrame::CustodyOpen { binding_mode } => CustodyServerFrame::NodeIdentity {
            record: Box::new(node.clone()),
            audience: "node".into(),
            binding_mode,
            proxy_key_custody: None,
        },
        CustodyClientFrame::Challenge { action, .. } => match challenge_reply(&action) {
            Ok(frame) => frame,
            Err(_) => return refused(CustodyRefusal::InvalidInput),
        },
        CustodyClientFrame::Prove { action, proof } => {
            match prove_reply(&action, &proof, accept_pairing) {
                Ok(frame) => frame,
                Err(_) => return refused(CustodyRefusal::InvalidInput),
            }
        }
        _ => return refused(CustodyRefusal::Unsupported),
    };
    serde_json::to_vec(&response).unwrap_or_else(|_| refused(CustodyRefusal::InvalidInput))
}

fn challenge_reply(action: &CustodyProofAction) -> TestResult<CustodyServerFrame> {
    let now = crate::custody::network_now()?;
    Ok(CustodyServerFrame::Challenge {
        challenge: BranchChallenge {
            challenge_nonce: encode_base64url([9; 32]),
            action_hash: ramflux_protocol::custody::custody_action_hash(action)?,
            audience: "node".into(),
            binding_mode: BindingMode::DirectExporter,
            issued_at: now,
            expires_at: now.saturating_add(300),
        },
    })
}

fn prove_reply(
    action: &CustodyProofAction,
    proof: &Envelope<ramflux_protocol::custody::BranchProofV3>,
    accept_pairing: bool,
) -> TestResult<CustodyServerFrame> {
    let device = &proof.body.device_ref;
    let delivery =
        ramflux_protocol::qualified_device_id(&device.account_anchor, &device.device_id)?;
    Ok(match action {
        CustodyProofAction::Publish { publication } => {
            CustodyServerFrame::Published { record_hash: object_hash(&publication.record)? }
        }
        CustodyProofAction::Register { .. } => CustodyServerFrame::Registered {
            device_ref: device.clone(),
            target_delivery_id: delivery,
        },
        CustodyProofAction::OpenSession => CustodyServerFrame::SessionEstablished {
            session: CustodySession {
                session_id: encode_base64url([8; 32]),
                device_ref: device.clone(),
                target_delivery_id: delivery,
                record_hash: proof.body.record_hash.clone(),
                proof_hash: encode_base64url([7; 32]),
                binding_mode: proof.body.binding_mode,
                expires_at: proof.body.expires_at,
            },
        },
        CustodyProofAction::PairingIssue { request } if accept_pairing => {
            use ramflux_protocol::custody::pairing::native::{Issued, NativeReply, PairingReply};
            CustodyServerFrame::Pairing {
                reply: Box::new(PairingReply {
                    schema: "ramflux.pairing.PairingReply.v2".into(),
                    version: 2,
                    reply: NativeReply::Issued(Box::new(Issued {
                        schema: "ramflux.pairing.Issued.v2".into(),
                        version: 2,
                        ticket: dummy_create(request.spec.clone()).ticket,
                    })),
                }),
            }
        }
        CustodyProofAction::PairingIssue { .. } | CustodyProofAction::PairingCreate { .. } => {
            CustodyServerFrame::Refused {
                code: CustodyRefusal::BindingRefused,
                capacity: None,
                retry: None,
            }
        }
        _ => CustodyServerFrame::Refused {
            code: CustodyRefusal::Unsupported,
            capacity: None,
            retry: None,
        },
    })
}

fn refused(code: CustodyRefusal) -> Vec<u8> {
    serde_json::to_vec(&CustodyServerFrame::Refused { code, capacity: None, retry: None })
        .unwrap_or_else(|_| b"{\"frame_type\":\"refused\",\"code\":\"invalid_input\"}".to_vec())
}

fn proof_operations(sent: &[Vec<u8>]) -> Vec<String> {
    sent.iter()
        .filter_map(|bytes| {
            let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
            if value.get("frame_type")?.as_str()? != "prove" {
                return None;
            }
            Some(value.get("action")?.get("operation")?.as_str()?.to_owned())
        })
        .collect()
}

fn dummy_spec(anchor: &str, device_id: &str, record_hash: String) -> CreateSpec {
    let now = 1_760_000_000_u64;
    CreateSpec {
        schema: "ramflux.pairing.CreateSpec.v2".into(),
        version: 2,
        account_anchor: anchor.into(),
        primary_ref: ramflux_protocol::custody::DeviceRef {
            account_anchor: anchor.into(),
            device_id: device_id.into(),
            device_epoch: 1,
        },
        base_record_hash: record_hash,
        base_epoch: 1,
        purpose: "enroll".into(),
        recipient_mode: "new".into(),
        destination_ref: None,
        capabilities: vec!["message".into(), "register".into()],
        lease_not_before: now,
        lease_expires_at: now + 86_400,
        data_selection: vec![],
        ttl_seconds: 300,
    }
}

fn dummy_create(spec: CreateSpec) -> Create {
    Create {
        schema: "ramflux.pairing.Create.v2".into(),
        version: 2,
        ticket: Envelope {
            body: CreateTicket {
                schema: "ramflux.pairing.CreateTicket.v2".into(),
                version: 2,
                node_key: encode_base64url([1; 32]),
                boot_id: encode_base64url([2; 32]),
                create_id: encode_base64url([3; 32]),
                issuer_seq: 1,
                account_anchor: spec.account_anchor.clone(),
                primary_ref: spec.primary_ref.clone(),
                spec_hash: encode_base64url([4; 32]),
                issued_at: spec.lease_not_before,
                expires_at: spec.lease_not_before.saturating_add(300),
            },
            signature: encode_base64url([0; 64]),
        },
        spec,
    }
}

struct Connected {
    _root: crate::custody::tests::Root,
    connection: CustodyConnection<MockGateway>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    lifetime: std::sync::Weak<()>,
}

async fn connect_mock() -> TestResult<Connected> {
    connect_mock_mode(false).await
}

async fn connect_mock_mode(proof_only: bool) -> TestResult<Connected> {
    let root = crate::custody::tests::Root::new()?;
    let vault = Arc::new(MemoryPrimaryVault::default());
    let now = crate::custody::network_now()?;
    crate::custody::tests::create(&root.0, "alice", vault.as_ref(), now)?;
    std::fs::write(root.0.join("ca.pem"), b"dummy-ca")?;
    let node = crate::custody::network_tests::node(now, encode_base64url([29; 32]))
        .map_err(|error| error.to_string())?;
    let sent = Arc::new(Mutex::new(Vec::new()));
    let config = CustodyNetworkConfig {
        pairing_admission: None,
        account_root: root.0.to_path_buf(),
        account_id: "alice".into(),
        device_id: "primary".into(),
        gateway_address: "127.0.0.1:1".parse()?,
        server_name: "localhost".into(),
        ca_certificate: root.0.join("ca.pem"),
        node_id: "node".into(),
        node_public_key: ramflux_crypto::fixture_public_key_base64url(),
        audience: "node".into(),
        binding_mode: BindingMode::DirectExporter,
        allow_no_channel_binding: false,
        timeout: Duration::from_secs(5),
    };
    let mut retry = crate::custody::retry::AdmissionRetry::default();
    let node_record = node.envelope().clone();
    let sent_open = Arc::clone(&sent);
    let lifetime = Arc::new(());
    let weak = Arc::downgrade(&lifetime);
    let ((), connection) = Box::pin(CustodyConnection::connect_with_mode(
        config,
        vault,
        &mut retry,
        proof_only,
        move || {
            let sent = Arc::clone(&sent_open);
            let node_record = node_record.clone();
            let lifetime = lifetime.clone();
            async move {
                Ok((
                    (),
                    MockGateway {
                        sent,
                        replies: VecDeque::new(),
                        node: node_record,
                        accept_pairing: proof_only,
                        _lifetime: lifetime,
                    },
                ))
            }
        },
    ))
    .await?;
    Ok(Connected { _root: root, connection, sent, lifetime: weak })
}

#[tokio::test]
async fn pairing_native_from_connection_sends_pairing_issue_and_create_proofs() -> TestResult {
    let connected = connect_mock().await?;
    let handshake =
        proof_operations(&connected.sent.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    let anchor = connected.connection.account().record().body.account_anchor.clone();
    let record_hash = object_hash(connected.connection.account().record())?;
    let native = ProofPairingNative::from_connection(Arc::new(tokio::sync::Mutex::new(
        connected.connection,
    )));
    let spec = dummy_spec(&anchor, "primary", record_hash);
    assert!(matches!(
        PairingNative::issue(&native, spec.clone()).await,
        Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused))
    ));
    assert!(matches!(
        PairingNative::create(&native, dummy_create(spec)).await,
        Err(SdkError::CustodyNetwork(CustodyRefusal::BindingRefused))
    ));
    let added: Vec<String> =
        proof_operations(&connected.sent.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
            .into_iter()
            .skip(handshake.len())
            .collect();
    if !added.iter().any(|op| op == "pairing_issue") {
        return Err(format!("missing pairing_issue in {added:?}").into());
    }
    if !added.iter().any(|op| op == "pairing_create") {
        return Err(format!("missing pairing_create in {added:?}").into());
    }
    Ok(())
}

#[tokio::test]
async fn pairing_fresh_proof_connection_closes_and_cannot_reappear_after_cancel() -> TestResult {
    let connected = connect_mock_mode(true).await?;
    assert!(
        proof_operations(&connected.sent.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
            .is_empty(),
        "proof-only open must not publish, register or create an ordinary session"
    );
    assert!(connected.connection.session().is_none());
    let spec = dummy_spec(
        &connected.connection.account().record().body.account_anchor,
        "primary",
        object_hash(connected.connection.account().record())?,
    );
    let slot = Arc::new(Mutex::new(Some(connected.connection)));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let native = Arc::new(super::FreshPairingNative::with_factory(Arc::new({
        let started = started.clone();
        let release = release.clone();
        move || {
            let started = started.clone();
            let release = release.clone();
            let slot = slot.clone();
            Box::pin(async move {
                started.notify_one();
                release.notified().await;
                slot.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .ok_or(SdkError::PairingCode("Busy"))
            })
        }
    })));
    let task = tokio::spawn({
        let native = native.clone();
        async move { native.issue(spec).await }
    });
    started.notified().await;
    native.close();
    release.notify_one();
    assert!(matches!(task.await?, Err(SdkError::PairingCode("WrongContext"))));
    assert!(connected.lifetime.upgrade().is_none(), "cancelled late connection must be dropped");
    Ok(())
}

#[tokio::test]
async fn pairing_full_node_record_comes_from_owned_proof_connection_and_does_not_reopen()
-> TestResult {
    let connected = connect_mock_mode(true).await?;
    let spec = dummy_spec(
        &connected.connection.account().record().body.account_anchor,
        "primary",
        object_hash(connected.connection.account().record())?,
    );
    let slot = Arc::new(Mutex::new(Some(connected.connection)));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let native = super::FreshPairingNative::with_factory(Arc::new({
        let calls = calls.clone();
        move || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let slot = slot.clone();
            Box::pin(async move {
                slot.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .ok_or(SdkError::PairingCode("Busy"))
            })
        }
    }));
    assert!(native.full_node().await.is_err(), "node read opened an unowned proof connection");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    native.issue(spec).await?;
    let node = native.full_node().await?;
    assert_eq!(node.envelope().body.node_id, "node");
    assert_eq!(
        node.envelope().body.node_signing_public_key,
        ramflux_crypto::fixture_public_key_base64url()
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    native.close();
    assert!(native.full_node().await.is_err(), "closed proof owner returned pinned node");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "node read re-opened retired connection"
    );
    assert!(connected.lifetime.upgrade().is_none(), "public node result retained proof connection");
    Ok(())
}
