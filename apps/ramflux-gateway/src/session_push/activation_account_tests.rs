// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual account writer, SDK resident host and gateway session loop joined by frame transport.

use crate::GatewayQuicContext;
use ramflux_sdk::EphemeralSendOutcome;
use ramflux_sdk::{
    AccountSessionFixture, AccountSessionHarness, GatewayQuicEndpointConfig, GatewaySessionConfig,
    GatewaySessionState,
};
use ramflux_storage::{AccountDb, AccountDbKey, AccountIndex};
use ramflux_transport::{
    GatewaySessionFrameFuture, GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError,
};
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

type Frames = Arc<Mutex<Vec<Value>>>;
#[derive(Clone)]
struct FrameSink {
    send: mpsc::UnboundedSender<Vec<u8>>,
    observed: Frames,
}
struct FrameSource(mpsc::UnboundedReceiver<Vec<u8>>);
struct FrameStream {
    sink: FrameSink,
    source: FrameSource,
}
impl GatewaySessionFrameSink for FrameSink {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            self.observed
                .lock()
                .map_err(|_| TransportError::ShutdownDraining)?
                .push(serde_json::from_slice(bytes)?);
            self.send.send(bytes.to_vec()).map_err(|_| TransportError::ShutdownDraining)
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for FrameSource {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async { self.0.recv().await.ok_or(TransportError::ShutdownDraining) })
    }
}
impl GatewaySessionFrameSink for FrameStream {
    fn send_frame<'a>(&'a mut self, bytes: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.sink.send_frame(bytes)
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        self.sink.finish()
    }
}
impl GatewaySessionFrameSource for FrameStream {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.source.recv_frame()
    }
}

pub(super) struct Account {
    pub host: AccountSessionHarness,
    registration_sink: FrameSink,
    pub writes: Frames,
    gateway_writes: Frames,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Account {
    pub async fn attach(
        root: &Path,
        context: &GatewayQuicContext,
        runtime: &crate::GatewaySessionRuntime,
        incarnation: &str,
    ) -> anyhow::Result<Self> {
        let index = AccountIndex::open(root)?;
        index.create_account("client", runtime.source_identity.root_commitment())?;
        let db = AccountDb::open(&index, "client", &AccountDbKey::from_bytes([12; 32]))?;
        let (to_gateway, gateway_input) = mpsc::unbounded_channel();
        let (to_client, client_input) = mpsc::unbounded_channel();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let gateway_writes = Arc::default();
        let registration_sink =
            FrameSink { send: to_client, observed: Arc::clone(&gateway_writes) };
        let gateway_send: crate::GatewaySendHandle =
            Arc::new(tokio::sync::Mutex::new(Box::new(registration_sink.clone())));
        let task = tokio::spawn(crate::session::run_gateway_session_loop_until_closed(
            gateway_send.clone(),
            Box::new(FrameSource(gateway_input)),
            context.clone(),
            runtime.clone(),
            None,
            None,
        ));
        let (root_seed, device_seed) =
            if runtime.principal_id == "agent" { (3, 4) } else { (6, 7) };
        let identity = ramflux_crypto::create_identity_root(&runtime.principal_id, [root_seed; 32]);
        let branch = ramflux_crypto::create_device_branch(
            &runtime.principal_id,
            &runtime.device_id,
            1,
            [device_seed; 32],
        );
        let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: "127.0.0.1:1".parse()?,
            server_name: "unused.fixture".into(),
            ca_cert: root.join("unused.pem"),
            principal_id: runtime.principal_id.clone(),
            device_id: runtime.device_id.clone(),
            target_delivery_id: runtime.target_delivery_id.clone(),
            prekey_http_url: None,
        })
        .with_owned_device(&identity, branch)?;
        let session = GatewaySessionState {
            call_session_generation: None,
            session_id: runtime.session_id.clone(),
            gateway_id: context.gateway_id.clone(),
            resume_token: runtime.resume_token.clone(),
            resume_window_seconds: 60,
            accepted_inbox_seq: 0,
        };
        let host = crate::ephemeral::tests::guard_10s(
            "SDK account writer and resident host ready",
            Box::pin(AccountSessionHarness::attach(AccountSessionFixture {
                index,
                db,
                identity,
                config,
                session,
                stream: Box::new(FrameStream {
                    sink: FrameSink { send: to_gateway, observed: writes.clone() },
                    source: FrameSource(client_input),
                }),
                incarnation: Some(incarnation.to_owned()),
                ephemeral: runtime.ephemeral,
            })),
        )
        .await
        .map_err(|error| anyhow::anyhow!("attached account startup: {error:?}"))?;
        Ok(Self { host, registration_sink, writes, gateway_writes, task })
    }
    // Each registration owns its retirement wrapper; the frame transport stays attached.
    pub fn push_sink(&self) -> crate::GatewaySendHandle {
        Arc::new(tokio::sync::Mutex::new(Box::new(self.registration_sink.clone())))
    }
    pub async fn submit(
        &mut self,
        runtime: &crate::GatewaySessionRuntime,
        id: &str,
        change: impl FnOnce(&mut ramflux_protocol::Envelope),
    ) -> anyhow::Result<EphemeralSendOutcome> {
        let ciphertext = presealed_ciphertext()?;
        let payload_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.encrypted_payload.v1",
            ciphertext.as_bytes(),
        );
        let submit = crate::ephemeral::handler_tests::submit(runtime, id, 5, |envelope| {
            envelope.encrypted_payload = ciphertext;
            envelope.payload_hash = payload_hash;
            change(envelope);
        })?;
        match self.host.submit(submit.envelope).await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let task = if self.task.is_finished() {
                    format!("{:?}", (&mut self.task).await)
                } else {
                    "running".into()
                };
                anyhow::bail!(
                    "SDK account submit {id}: {error:?}; gateway loop={task}; SDK writes={:?}; gateway writes={:?}",
                    self.writes.lock().map_err(|_| anyhow::anyhow!("writes"))?,
                    self.gateway_writes.lock().map_err(|_| anyhow::anyhow!("gateway writes"))?
                );
            }
        }
    }
    pub async fn submit_padded(
        &mut self,
        runtime: &crate::GatewaySessionRuntime,
        id: &str,
    ) -> anyhow::Result<EphemeralSendOutcome> {
        let mut envelope =
            crate::ephemeral::handler_tests::submit(runtime, id, 5, |_| {})?.envelope;
        envelope.encrypted_payload = presealed_ciphertext()?;
        envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.encrypted_payload.v1",
            envelope.encrypted_payload.as_bytes(),
        );
        envelope.ext.ext.insert("padding".into(), Value::String(String::new()));
        let expires_at_ms = u64::try_from(envelope.created_at + 5)? * 1000;
        let base = serde_json::to_vec(&ramflux_node_core::GatewayServerFrame::Ephemeral {
            envelope: envelope.clone(),
            expires_at_ms,
        })?
        .len();
        anyhow::ensure!(base <= 30_000, "presealed frame exceeds padding target");
        envelope.ext.ext.insert("padding".into(), Value::String("x".repeat(30_000 - base)));
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            [4; 32],
        );
        Ok(self.host.submit(envelope).await?)
    }

    pub async fn stop(&mut self) {
        self.host.stop().await;
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Account {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) fn source(runtime: &crate::GatewaySessionRuntime) -> ramflux_sdk::EphemeralSource {
    ramflux_sdk::EphemeralSource {
        principal_id: runtime.principal_id.clone(),
        device: runtime.source_identity.clone(),
        signing_public_key: runtime.branch_public_key.clone(),
    }
}

pub(super) fn recipient_runtime(
    source: &crate::GatewaySessionRuntime,
    incarnation: &str,
) -> anyhow::Result<crate::GatewaySessionRuntime> {
    let root = ramflux_crypto::create_identity_root("alice", [6; 32]);
    let branch = ramflux_crypto::create_device_branch("alice", "alice-device", 1, [7; 32]);
    let mut runtime = source.clone();
    runtime.session_push = Some(incarnation.into());
    runtime.principal_id = "alice".into();
    runtime.device_id = "alice-device".into();
    runtime.source_identity =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    runtime.branch_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    runtime.target_delivery_id = "alice-target".into();
    runtime.session_id = "alice-session".into();
    Ok(runtime)
}

/// Seal outside the measured SDK transport: endpoint ratchet state is not part of this oracle.
pub(super) fn presealed_ciphertext() -> anyhow::Result<String> {
    let mut endpoint =
        ramflux_crypto::DmSession::initiator([31; 32], [32; 32], [33; 32], [34; 32])?;
    let sealed =
        endpoint.encrypt(b"known transient ciphertext fixture", b"transport handoff fixture")?;
    Ok(ramflux_protocol::encode_base64url(serde_json::to_vec(&sealed)?))
}
