// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary gateway sessions share bounded native retries over real proxy-bound TLS.
use super::*;
use crate::{GatewayClientFrame, GatewayServerFrame, GatewaySessionEstablishedFrame};
use ramflux_crypto::custody::{
    VerifiedNodeRecord, sign_node_identity_record, sign_proxy_acceptance,
};

pub(super) fn node(original: &VerifiedNodeRecord, now: u64) -> Result<VerifiedNodeRecord> {
    let proxy = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let mut body = original.envelope().body.clone();
    body.channel_binding_modes = vec![BindingMode::HomeRelayReceipt];
    body.proxy_keys = vec![ProxyKey {
        key_id: ramflux_protocol::encode_base64url([79; 32]),
        public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
        not_before: now - 1,
        sign_until: now + 600,
        overlap_until: now + 605_400,
        status: ReceiptKeyStatus::Active,
        proxy_id: "ramflux-gateway".into(),
        audiences: vec!["node".into()],
    }];
    let record = sign_node_identity_record(&ramflux_crypto::fixture_signing_key(), body)?;
    Ok(ramflux_crypto::custody::verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}

pub(super) async fn public_lookup(
    bytes: &[u8],
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    script: &Arc<Mutex<Script>>,
) -> Result<bool> {
    let Ok(request) = serde_json::from_slice::<ramflux_transport::GatewayQuicRequest>(bytes) else {
        return Ok(false);
    };
    assert_eq!(request.method, "GET");
    assert!(request.path.starts_with("/mvp1/device-manifest/"));
    let body = script
        .lock()
        .map_err(|_| "script lock")?
        .ordinary
        .as_ref()
        .and_then(|session| {
            session.manifests.get(request.path.trim_start_matches("/mvp1/device-manifest/"))
        })
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(serde_json::Value::Null);
    ramflux_transport::write_gateway_session_json(
        stream,
        &ramflux_transport::GatewayQuicResponse { status: 200, body },
    )
    .await?;
    Ok(true)
}

pub(super) fn dispatch(
    context: &Context,
    stream: &ramflux_transport::GatewayTcpTlsStream,
    connection: &str,
    frame: CustodyClientFrame,
) -> Result<CustodyServerFrame> {
    let now = crate::custody::network_now()?;
    let request = match frame {
        CustodyClientFrame::CustodyOpen { binding_mode } => {
            assert_eq!(binding_mode, BindingMode::HomeRelayReceipt);
            let CustodyServerFrame::NodeIdentity { record, audience, .. } = context.service.mesh(
                &context.router,
                &context.store,
                CustodyMeshRequest::NodeIdentity { record_hash: None },
                "ramflux-gateway",
                now,
            ) else {
                return Err("missing node identity".into());
            };
            return Ok(CustodyServerFrame::NodeIdentity {
                record,
                audience,
                binding_mode,
                proxy_key_custody: Some("software".into()),
            });
        }
        CustodyClientFrame::Challenge { device_ref, action } => CustodyMeshRequest::Challenge {
            device_ref,
            action,
            binding_mode: BindingMode::HomeRelayReceipt,
            client_source: "127.0.0.1".into(),
            connection_id: connection.into(),
        },
        CustodyClientFrame::Prove { action, proof } => {
            let nonce = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| "nonce")?;
            let material = ramflux_transport::custody_tcp_exporter(stream, &nonce)?;
            let observed = ramflux_crypto::custody::branch_exporter_hash(&material);
            assert_eq!(proof.body.transport_binding, observed);
            let receipt = sign_proxy_acceptance(
                &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                context.node.as_ref().ok_or("proxy node")?,
                &proof,
                &observed,
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                now,
            )?;
            CustodyMeshRequest::Prove {
                action,
                proof,
                receipt: Some(Box::new(receipt)),
                connection_id: connection.into(),
            }
        }
        _ => return Err("unexpected native frame".into()),
    };
    Ok(context.service.mesh(&context.router, &context.store, request, "ramflux-gateway", now))
}

pub(super) async fn ordinary(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    session: &str,
    script: &Arc<Mutex<Script>>,
) -> Result {
    let open: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    let GatewayClientFrame::Open { open } = open else { return Err("ordinary open".into()) };
    assert_eq!(open.device_id, "primary");
    let auth: GatewayClientFrame = ramflux_transport::read_gateway_session_json(stream).await?;
    assert!(matches!(auth, GatewayClientFrame::Auth { .. }));
    let held = script.lock().map_err(|_| "script lock")?.hold_established.clone();
    if let Some(entered) = held {
        entered.notify_one();
        let release = script.lock().map_err(|_| "script lock")?.release_established.clone();
        if let Some(release) = release {
            release.notified().await;
        } else {
            return std::future::pending().await;
        }
    }
    let persistent = script.lock().map_err(|_| "script lock")?.ordinary.is_some();
    if persistent {
        // The account advertises session push. Echo the capability so the handshake
        // is the negotiated push session this server then speaks.
        ramflux_transport::write_gateway_session_json(stream, &negotiated_established(session))
            .await?;
        serve_session(stream, script, &open.target_delivery_id).await?;
    } else {
        ramflux_transport::write_gateway_session_json(
            stream,
            &GatewayServerFrame::SessionEstablished {
                session: GatewaySessionEstablishedFrame {
                    call_session_generation: None,
                    session_id: session.into(),
                    gateway_id: "ordinary-test".into(),
                    accepted_cursor: None,
                    resume_token: "test-resume".into(),
                    resume_window_seconds: 60,
                },
            },
        )
        .await?;
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct SessionScript {
    pub inbox: Vec<crate::GatewayInboxEntry>,
    pub manifests: std::collections::BTreeMap<String, crate::prekey::SdkDeviceManifestResponse>,
    pub resumes: usize,
    pub acknowledgements: usize,
    pub held_ack: Option<Arc<HeldAck>>,
}
pub(super) struct HeldAck {
    pub id: String,
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

const PUSH_EPOCH: &str = "0123456789abcdef0123456789abcdef";
const RETAIN_UNTIL: i64 = 4_102_444_800;

fn negotiated_established(session: &str) -> ramflux_node_core::SessionPushServerFrame {
    ramflux_node_core::SessionPushServerFrame::SessionEstablished {
        session: ramflux_node_core::SessionPushEstablishedFrame {
            session: ramflux_node_core::GatewaySessionEstablishedFrame {
                call_session_generation: None,
                session_id: session.to_owned(),
                gateway_id: "ordinary-test".into(),
                accepted_cursor: None,
                resume_token: "test-resume".into(),
                resume_window_seconds: 60,
            },
            capabilities: vec![ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.to_owned()],
            inbox_incarnation_id: PUSH_EPOCH.to_owned(),
        },
    }
}

fn page_record(entry: &crate::GatewayInboxEntry) -> ramflux_node_core::PageEntryRecord {
    ramflux_node_core::PageEntryRecord {
        entry: ramflux_node_core::InboxEntry {
            inbox_seq: entry.inbox_seq,
            target_delivery_id: entry.target_delivery_id.clone(),
            envelope: entry.envelope.clone(),
        },
        retain_until: RETAIN_UNTIL,
    }
}

fn resume_page(
    target: &str,
    after: u64,
    limit: usize,
    inbox: &[crate::GatewayInboxEntry],
) -> Result<ramflux_node_core::SessionPushServerFrame> {
    if limit == 0 {
        return Err("resume limit".into());
    }
    let mut pending: Vec<_> = inbox.iter().filter(|entry| entry.inbox_seq > after).collect();
    pending.sort_by_key(|entry| entry.inbox_seq);
    let issued = inbox.iter().map(|entry| entry.inbox_seq).max().unwrap_or(after);
    let chosen: Vec<_> = pending.into_iter().take(limit).collect();
    let covered = chosen.last().map_or(after, |entry| entry.inbox_seq);
    Ok(ramflux_node_core::SessionPushServerFrame::ResumePage {
        target_delivery_id: target.to_owned(),
        incarnation_id: PUSH_EPOCH.to_owned(),
        after_inbox_seq: after,
        covered_through_seq: covered,
        issued_inbox_seq: issued,
        settled_through_seq: after.min(issued),
        entries: chosen.into_iter().map(page_record).collect(),
        known_losses: Vec::new(),
        oversize_next: None,
        more: covered < issued,
    })
}

fn push_cursor(target: &str, inbox_seq: u64) -> ramflux_node_core::InboxCursorResponse {
    ramflux_node_core::InboxCursorResponse {
        target_delivery_id: target.to_owned(),
        inbox_seq,
        last_envelope_id: None,
        acked_envelope_ids: Vec::new(),
        nacked_envelope_ids: std::collections::BTreeMap::new(),
    }
}

fn number_at(frame: &serde_json::Value, key: &str) -> Result<u64> {
    frame
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("missing {key}").into())
}

async fn next_frame(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
) -> Result<Option<serde_json::Value>> {
    use ramflux_transport::GatewaySessionFrameSource;
    match stream.recv_frame().await {
        Ok(bytes) => Ok(Some(ramflux_protocol::parse_i_json(&bytes)?)),
        Err(ramflux_transport::TransportError::Io(error))
            if error.kind() == std::io::ErrorKind::UnexpectedEof =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn note_frame(session: &mut SessionScript, kind: &str) {
    match kind {
        "resume" => session.resumes += 1,
        "ack" | "ack_batch" => session.acknowledgements += 1,
        _ => {}
    }
}

async fn write_push(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    frame: &ramflux_node_core::SessionPushServerFrame,
) -> Result {
    ramflux_transport::write_gateway_session_json(stream, frame).await?;
    Ok(())
}

async fn serve_session(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    script: &Arc<Mutex<Script>>,
    target: &str,
) -> Result {
    loop {
        let Some(frame) = next_frame(stream).await? else { return Ok(()) };
        let kind = frame.get("frame_type").and_then(serde_json::Value::as_str).unwrap_or("");
        let hold = {
            let locked = script.lock().map_err(|_| "script lock")?;
            let envelope = frame
                .get("ack")
                .and_then(|ack| ack.get("envelope_id"))
                .and_then(serde_json::Value::as_str);
            locked
                .ordinary
                .as_ref()
                .and_then(|session| session.held_ack.as_ref())
                .filter(|held| envelope == Some(held.id.as_str()))
                .cloned()
        };
        if let Some(held) = hold {
            held.entered.notify_one();
            held.release.notified().await;
        }
        reply_frame(stream, script, target, kind, &frame).await?;
    }
}

async fn reply_frame(
    stream: &mut ramflux_transport::GatewayTcpTlsStream,
    script: &Arc<Mutex<Script>>,
    target: &str,
    kind: &str,
    frame: &serde_json::Value,
) -> Result {
    let inbox = {
        let mut locked = script.lock().map_err(|_| "script lock")?;
        let session = locked.ordinary.as_mut().ok_or("session script")?;
        note_frame(session, kind);
        session.inbox.clone()
    };
    match kind {
        "resume" => {
            let resume = frame.get("resume").ok_or("resume body")?;
            let after = number_at(resume, "after_inbox_seq")?;
            let limit = usize::try_from(number_at(resume, "limit")?)?;
            write_push(stream, &resume_page(target, after, limit, &inbox)?).await
        }
        "ack_batch" => {
            let seqs =
                frame.get("inbox_seqs").and_then(serde_json::Value::as_array).ok_or("ack batch")?;
            let seqs: Vec<u64> = seqs
                .iter()
                .map(|seq| seq.as_u64().ok_or_else(|| "ack seq".into()))
                .collect::<Result<_>>()?;
            let inbox_seq = seqs.last().copied().unwrap_or(0);
            write_push(
                stream,
                &ramflux_node_core::SessionPushServerFrame::AckBatch {
                    incarnation_id: PUSH_EPOCH.to_owned(),
                    cursor: push_cursor(target, inbox_seq),
                    results: seqs
                        .into_iter()
                        .map(|inbox_seq| ramflux_node_core::SessionAckResult {
                            inbox_seq,
                            outcome: ramflux_node_core::SessionAckOutcome::Acked,
                            reason: None,
                        })
                        .collect(),
                },
            )
            .await
        }
        "ack" => {
            write_push(
                stream,
                &ramflux_node_core::SessionPushServerFrame::Ack {
                    incarnation_id: PUSH_EPOCH.to_owned(),
                    cursor: push_cursor(target, 0),
                },
            )
            .await
        }
        "fetch_entry" => {
            let seq = number_at(frame, "inbox_seq")?;
            let reply = if let Some(entry) = inbox.iter().find(|entry| entry.inbox_seq == seq) {
                ramflux_node_core::SessionPushServerFrame::Entry {
                    incarnation_id: PUSH_EPOCH.to_owned(),
                    record: Box::new(page_record(entry)),
                }
            } else {
                ramflux_node_core::SessionPushServerFrame::EntryGone {
                    incarnation_id: PUSH_EPOCH.to_owned(),
                    inbox_seq: seq,
                    observed_issued_inbox_seq: inbox
                        .iter()
                        .map(|entry| entry.inbox_seq)
                        .max()
                        .unwrap_or(seq),
                    reason: ramflux_node_core::EntryGoneReason::Unknown,
                }
            };
            write_push(stream, &reply).await
        }
        "submit" => {
            let submit: crate::GatewaySubmitFrame =
                serde_json::from_value(frame.get("submit").ok_or("submit body")?.clone())?;
            ramflux_transport::write_gateway_session_json(
                stream,
                &GatewayServerFrame::ForwardAck {
                    ack: crate::gateway::GatewayForwardAck {
                        envelope_id: submit.envelope.envelope_id,
                        target_delivery_id: submit.envelope.target_delivery_id,
                        inbox_seq: Some(1),
                    },
                },
            )
            .await?;
            Ok(())
        }
        "heartbeat" => {
            let now = number_at(frame, "now")?;
            ramflux_transport::write_gateway_session_json(
                stream,
                &GatewayServerFrame::Heartbeat { now },
            )
            .await?;
            Ok(())
        }
        other => Err(format!("unexpected scripted session frame {other}").into()),
    }
}

#[tokio::test]
async fn ordinary_native_gateway_busy_retries_outlive_the_legacy_timeout_with_fresh_proofs()
-> Result {
    tokio::time::timeout(Duration::from_secs(120), async {
        let points =
            [Point::Open, Point::Open, Point::Open, Point::RegisterChallenge, Point::RegisterProve];
        let fixture = Fixture::with_mode(&points, true).await?;
        let network = &fixture.config;
        let account = crate::custody::load_account(
            &network.account_root,
            &network.account_id,
            crate::custody::network_now()?,
        )?;
        let endpoint = crate::GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: network.gateway_address,
            server_name: network.server_name.clone(),
            ca_cert: network.ca_certificate.clone(),
            principal_id: account.record().body.principal_id.clone(),
            device_id: "primary".into(),
            target_delivery_id: ramflux_protocol::qualified_device_id(
                &account.record().body.account_anchor,
                "primary",
            )?,
            prekey_http_url: None,
        };
        let mut config = crate::GatewaySessionConfig::auto(endpoint).with_native_custody(
            crate::GatewayCustodyConfig {
                account_root: network.account_root.clone(),
                account_id: network.account_id.clone(),
                node_id: network.node_id.clone(),
                node_public_key: network.node_public_key.clone(),
                vault: fixture.vault.clone(),
            },
        );
        config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
        config.tcp_gateway_addr = Some(network.gateway_address);
        let started = std::time::Instant::now();
        let engine = crate::GatewaySessionEngine::connect(config).await?;
        assert!(started.elapsed() > Duration::from_secs(15));
        assert!(started.elapsed() <= Duration::from_secs(90));
        assert_eq!(engine.active_transport_kind(), crate::GatewaySessionTransportKind::TcpTls);
        assert_eq!(engine.session().gateway_id, "ordinary-test");
        assert_eq!(
            crate::custody::load_account(
                &network.account_root,
                &network.account_id,
                crate::custody::network_now()?,
            )?
            .state(),
            crate::custody::CreationState::Live
        );
        let script = fixture.script.lock().map_err(|_| "script lock")?;
        assert_eq!(script.busy_at, points);
        assert_eq!(script.accepted, 7);
        assert_eq!(script.publish_proofs, 1);
        assert_eq!(script.proofs.len(), 4);
        for column in 0..3 {
            let unique: std::collections::BTreeSet<_> = script
                .proofs
                .iter()
                .map(|proof| match column {
                    0 => &proof.0,
                    1 => &proof.1,
                    _ => &proof.2,
                })
                .collect();
            assert_eq!(unique.len(), script.proofs.len());
        }
        fixture.server.abort();
        Ok(())
    })
    .await?
}

#[tokio::test(start_paused = true)]
async fn legacy_connection_deadline_stays_fifteen_seconds() {
    let start = tokio::time::Instant::now();
    let legacy: std::result::Result<(), crate::SdkError> =
        crate::gateway::engine::connect_deadline(None, std::future::pending()).await;
    assert!(matches!(legacy, Err(crate::SdkError::GatewaySessionRejected(_))));
    assert_eq!(start.elapsed(), Duration::from_secs(15));
}
