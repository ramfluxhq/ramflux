// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public actor dispatch, certified native accounts and real SQLite/pair crypto.
use super::{
    actor::AccountCommand,
    state::{LocalBusAccountState, LocalBusDaemonState},
};
use crate::{
    GatewayClientFrame, GatewayServerFrame, GatewaySessionEngine, LocalBusConfig, LocalBusFrame,
    SdkError,
};
use ramflux_protocol::message as g;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Default)]
struct Capture {
    envelopes: Vec<ramflux_protocol::Envelope>,
    replies: VecDeque<Vec<u8>>,
}
struct Transport(Arc<Mutex<Capture>>);
impl ramflux_transport::GatewaySessionFrameSink for Transport {
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(bytes)
                .map_err(|error| ramflux_transport::TransportError::Quic(error.to_string()))?;
            let GatewayClientFrame::Submit { submit } = frame else {
                return Err(ramflux_transport::TransportError::Quic("unexpected frame".into()));
            };
            let reply = GatewayServerFrame::EphemeralResult {
                envelope_id: submit.envelope.envelope_id.clone(),
                result: ramflux_protocol::ephemeral::EphemeralSubmitResult::accepted(),
            };
            let mut capture = self
                .0
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("capture lock".into()))?;
            capture.envelopes.push(submit.envelope);
            capture.replies.push_back(
                serde_json::to_vec(&reply)
                    .map_err(|error| ramflux_transport::TransportError::Quic(error.to_string()))?,
            );
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Transport {
    fn recv_frame(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>>
    {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("capture lock".into()))?
                .replies
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("no reply".into()))
        })
    }
}
fn command(account: &str, method: &str, body: serde_json::Value) -> AccountCommand {
    let mut request =
        LocalBusFrame::request("correlation", Some(account.into()), "ramflux.sdk.v1", method, body);
    request.operation_id = Some("outer-operation-must-not-persist".into());
    let (outbound, _receiver) = tokio::sync::mpsc::channel(16);
    AccountCommand {
        admission: None,
        private: None,
        request,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}
fn request(
    account: &str,
    conversation: &str,
    active: bool,
    operation: Vec<u8>,
) -> g::MessageRequest {
    g::MessageRequest {
        request_id: "first".into(),
        account_id: account.into(),
        action: Some(g::message_request::Action::Send(g::SendMessage {
            conversation_id: conversation.into(),
            operation_id: operation,
            reply_to: None,
            content: Some(g::Content {
                value: Some(g::content::Value::Typing(g::Typing { active, expires_at: 0 })),
            }),
        })),
    }
}
fn account(state: &LocalBusDaemonState) -> Result<&LocalBusAccountState, SdkError> {
    state.accounts.get("ephemeral-source").ok_or_else(|| SdkError::LocalBus("account".into()))
}
async fn execute(
    state: &mut LocalBusDaemonState,
    request: &g::MessageRequest,
) -> Result<g::MessageUpdate, SdkError> {
    let body = serde_json::to_value(request)?;
    let reply = super::mutations::execute(
        state,
        "ephemeral-source",
        &command("ephemeral-source", "message.submit", body),
    )
    .await?;
    assert_eq!(reply.events.len(), 0, "Typing response entered event capture");
    crate::bindings::decode_message_update(&reply.body)
}
fn unchanged(
    state: &LocalBusDaemonState,
    allowed: &[String],
    expected: &BTreeMap<String, Vec<[u8; 32]>>,
) -> TestResult {
    let actual = account(state)?.client.account_db()?.test_table_fingerprints(allowed)?;
    let keys = actual.keys().chain(expected.keys()).collect::<BTreeSet<_>>();
    let changed =
        keys.into_iter().filter(|key| actual.get(*key) != expected.get(*key)).collect::<Vec<_>>();
    assert_eq!(changed, Vec::<&String>::new(), "Typing touched persistent artifacts");
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn typing_generated_send_bypasses_durable_operation_capture() -> TestResult {
    let _guard = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, b) = Box::pin(crate::client::routed::native_typing_pair_fixture()).await?;
    let conversation =
        g::dm_scope::derive(&a.client.own_account_anchor()?, &b.client.own_account_anchor()?)?;
    let local = a.client.owned_device_identity()?;
    let remote = b.client.owned_device_identity()?;
    let session = a.client.sendable_pair(&local, &remote)?.ok_or("pair")?.0;
    let allowed = vec![
        format!("dm-pair/session/{}", session.session_id),
        format!("dm-pair/ephemeral-seals/{}", session.session_id),
    ];
    let capture = Arc::new(Mutex::new(Capture::default()));
    let mut config = a.config.clone();
    config.capability_scope.extend([
        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.into(),
        ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.into(),
    ]);
    let mut engine =
        GatewaySessionEngine::with_test_transport(config, Box::new(Transport(capture.clone())));
    engine.ephemeral_negotiated = true;
    let root = a.root.0.clone();
    let source =
        LocalBusAccountState::new(a.client, engine, a.manifest.principal_commitment.clone());
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        accounts: BTreeMap::from([("ephemeral-source".into(), source)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let snapshot = account(&state)?.client.account_db()?.test_table_fingerprints(&allowed)?;
    let focus = command(
        "ephemeral-source",
        "message.focus",
        serde_json::json!({"conversation_id":conversation}),
    );
    let _ = super::mutations::execute(&mut state, "ephemeral-source", &focus).await?;
    unchanged(&state, &allowed, &snapshot)?;
    let mut send = request("ephemeral-source", &conversation, true, vec![1; 16]);
    let first = Box::pin(execute(&mut state, &send)).await?;
    assert_eq!(first.journal_sequence, 0);
    unchanged(&state, &allowed, &snapshot)?;
    send.request_id = "different-correlation".into();
    assert_eq!(Box::pin(execute(&mut state, &send)).await?, first);
    let mut conflict = request("ephemeral-source", &conversation, false, vec![1; 16]);
    let error =
        Box::pin(execute(&mut state, &conflict)).await.err().ok_or("conflicting id accepted")?;
    assert_eq!(crate::bindings::AdapterError::from_sdk(&error).code, 1);
    conflict.action = Some(g::message_request::Action::Send(g::SendMessage {
        operation_id: vec![3; 15],
        conversation_id: conversation.clone(),
        content: Some(g::Content {
            value: Some(g::content::Value::Typing(g::Typing { active: true, expires_at: 0 })),
        }),
        reply_to: None,
    }));
    assert!(Box::pin(execute(&mut state, &conflict)).await.is_err());
    unchanged(&state, &allowed, &snapshot)?;
    assert_eq!(capture.lock().map_err(|_| "capture")?.envelopes.len(), 1);
    let blur =
        command("ephemeral-source", "message.focus", serde_json::json!({"conversation_id":null}));
    let _ = super::mutations::execute(&mut state, "ephemeral-source", &blur).await?;
    assert_eq!(
        capture.lock().map_err(|_| "capture")?.envelopes.len(),
        2,
        "blur must send one clear"
    );
    unchanged(&state, &allowed, &snapshot)?;
    Box::pin(reopen_forgets_correlation(
        &mut state,
        &b,
        a.vault.clone(),
        &send,
        &capture,
        &allowed,
    ))
    .await?;
    Ok(())
}

async fn reopen_forgets_correlation(
    state: &mut LocalBusDaemonState,
    peer: &crate::client::native_test_support::Fixture,
    vault: Arc<crate::custody::tests::TestVault>,
    send: &g::MessageRequest,
    capture: &Arc<Mutex<Capture>>,
    allowed: &[String],
) -> TestResult {
    let source = state.accounts.get_mut("ephemeral-source").ok_or("account")?;
    source.client.active_account_db = None;
    source.client.unlock_account("ephemeral-source", b"native fixture data passphrase")?;
    Box::pin(source.client.initialize_born_v3_branch("primary", vault)).await?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    let Some(g::message_request::Action::Send(body)) = send.action.as_ref() else {
        return Err("send".into());
    };
    source.client.set_typing_focus(Some(&body.conversation_id))?;
    let snapshot = source.client.account_db()?.test_table_fingerprints(allowed)?;
    let _ = Box::pin(execute(state, send)).await?;
    assert_eq!(
        capture.lock().map_err(|_| "capture")?.envelopes.len(),
        3,
        "reopen must forget volatile operation ids"
    );
    unchanged(state, allowed, &snapshot)?;
    Ok(())
}

#[test]
fn typing_never_prepares_network_or_durable_intent() {
    let body = serde_json::json!({"send":{"content":{"typing":{"active":true}}}});
    assert!(super::generated_typing::is_request("message.submit", &body));
    assert!(!super::method_table::requires_network("message.submit", &body, true, None));
    assert!(!super::method_table::requires_network(
        "message.submit",
        &serde_json::json!({"typing":{}}),
        true,
        None
    ));
    assert!(super::method_table::requires_network(
        "message.submit",
        &serde_json::json!({}),
        true,
        None
    ));
    assert!(super::generated_typing::is_transient("message.focus", &serde_json::Value::Null));
}
