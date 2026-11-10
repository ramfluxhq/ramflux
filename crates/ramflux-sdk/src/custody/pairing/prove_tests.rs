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
        let reply = reply_for(frame, &self.node);
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

fn reply_for(frame: &[u8], node: &Envelope<NodeIdentityRecord>) -> Vec<u8> {
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
        CustodyClientFrame::Prove { action, proof } => match prove_reply(&action, &proof) {
            Ok(frame) => frame,
            Err(_) => return refused(CustodyRefusal::InvalidInput),
        },
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
}

async fn connect_mock() -> TestResult<Connected> {
    let root = crate::custody::tests::Root::new()?;
    let vault = Arc::new(MemoryPrimaryVault::default());
    let now = crate::custody::network_now()?;
    crate::custody::tests::create(&root.0, "alice", vault.as_ref(), now)?;
    std::fs::write(root.0.join("ca.pem"), b"dummy-ca")?;
    let node = crate::custody::network_tests::node(now, encode_base64url([29; 32]))
        .map_err(|error| error.to_string())?;
    let sent = Arc::new(Mutex::new(Vec::new()));
    let config = CustodyNetworkConfig {
        account_root: root.0.clone(),
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
    let ((), connection) = Box::pin(CustodyConnection::connect_with(
        config,
        vault,
        &mut retry,
        move || {
            let sent = Arc::clone(&sent_open);
            let node_record = node_record.clone();
            async move {
                Ok(((), MockGateway { sent, replies: VecDeque::new(), node: node_record }))
            }
        },
    ))
    .await?;
    Ok(Connected { _root: root, connection, sent })
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
