// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual account writer, SDK resident host and gateway session loop joined by frame transport.

use crate::GatewayQuicContext;
use ramflux_sdk::EphemeralSendOutcome;
use ramflux_sdk::{AccountSessionHarness, GatewaySessionState, NativeCallAccount};
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
        native: NativeCallAccount,
        context: &GatewayQuicContext,
        runtime: &crate::GatewaySessionRuntime,
        incarnation: &str,
    ) -> anyhow::Result<Self> {
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
            Box::pin(native.attach_negotiated(
                session,
                incarnation.to_owned(),
                runtime.ephemeral,
                Box::new(FrameStream {
                    sink: FrameSink { send: to_gateway, observed: writes.clone() },
                    source: FrameSource(client_input),
                }),
            )),
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
        let ciphertext = presealed_ciphertext();
        let payload_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            ciphertext.as_bytes(),
        );
        let submit = crate::ephemeral::handler_tests::submit(runtime, id, 5, |envelope| {
            envelope.target_delivery_id = target().into();
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
        let mut envelope = crate::ephemeral::handler_tests::submit(runtime, id, 5, |envelope| {
            envelope.target_delivery_id = target().into();
        })?
        .envelope;
        envelope.encrypted_payload = presealed_ciphertext();
        envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
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
            crate::ephemeral::handler_tests::signing_seed(runtime),
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

static TARGETS: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// Delivery target of the receiving native account (the fixture default before accounts exist).
pub(super) fn target() -> &'static str {
    TARGETS.get().map_or("alice-target", |targets| targets.1.as_str())
}

/// Delivery target of the sending native account.
pub(super) fn source_target() -> &'static str {
    TARGETS.get().map_or("agent-target", |targets| targets.0.as_str())
}

/// Phrase-created native accounts addressed by the strings the router fixture already uses for
/// principal and device; their delivery targets are the accounts' real device addresses.
pub(super) async fn native_pair(
    root: &Path,
) -> anyhow::Result<(NativeCallAccount, NativeCallAccount)> {
    let sender =
        NativeCallAccount::named(&root.join("sender"), "agent", "agent", "agent-device").await?;
    let receiver =
        NativeCallAccount::named(&root.join("receiver"), "alice", "alice", "alice-device").await?;
    let targets =
        (sender.identity.storage_key().to_owned(), receiver.identity.storage_key().to_owned());
    anyhow::ensure!(
        TARGETS.get_or_init(|| targets.clone()) == &targets,
        "one native account pair per process"
    );
    Ok((sender, receiver))
}

/// Make the gateway-side session identity the native account's real device and branch key.
pub(super) fn nativize(
    runtime: &mut crate::GatewaySessionRuntime,
    account: &NativeCallAccount,
) -> anyhow::Result<()> {
    let branch = account
        .config
        .device_branch
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("native account branch"))?;
    runtime.source_identity = account.identity.clone();
    runtime.target_delivery_id = account.config.target_delivery_id.clone();
    runtime.branch_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    crate::ephemeral::handler_tests::register_signing_seed(
        &runtime.branch_public_key,
        branch.signing_key.to_bytes(),
    );
    Ok(())
}

pub(super) fn recipient_runtime(
    source: &crate::GatewaySessionRuntime,
    receiver: &NativeCallAccount,
    incarnation: &str,
) -> anyhow::Result<crate::GatewaySessionRuntime> {
    let mut runtime = source.clone();
    runtime.session_push = Some(incarnation.into());
    runtime.principal_id = "alice".into();
    runtime.device_id = "alice-device".into();
    nativize(&mut runtime, receiver)?;
    runtime.session_id = "alice-session".into();
    Ok(runtime)
}

/// A valid compact generation-1 cryptobox, built outside the measured SDK transport: endpoint
/// ratchet state is not part of this oracle.
pub(super) fn presealed_ciphertext() -> String {
    "UkYxQwEAAAAQBwcHBwcHBwcHBwcHBwcHBwAAAAA".to_owned()
}
