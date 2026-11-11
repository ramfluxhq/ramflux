// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The same native federated contact intent remains retryable across a pre-effect refusal.

use super::*;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
type Case<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) struct Forwarder {
    endpoint: String,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}
impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
#[derive(Default)]
pub(super) struct ForwardHold {
    pub(super) entered: tokio::sync::Notify,
    pub(super) dropped: tokio::sync::Notify,
    pub(super) release: AtomicBool,
}
pub(super) fn forwarder(hold: Option<Arc<ForwardHold>>) -> Case<Forwarder> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !stopping.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = serve(stream, &count, hold.as_deref(), &stopping);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    });
    Ok(Forwarder { endpoint, calls, stop })
}
fn serve(
    stream: std::net::TcpStream,
    count: &AtomicUsize,
    hold: Option<&ForwardHold>,
    stop: &AtomicBool,
) -> Case {
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    assert_eq!(line, "POST /s8/federation/forward HTTP/1.1\r\n");
    let mut length = None;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let mut body = vec![0; length.ok_or("missing request length")?];
    reader.read_exact(&mut body)?;
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["envelope"]["envelope_id"], "keyed-contact-envelope");
    count.fetch_add(1, Ordering::AcqRel);
    if let Some(hold) = hold {
        hold.entered.notify_one();
        reader.get_mut().set_read_timeout(Some(Duration::from_millis(10)))?;
        let started = std::time::Instant::now();
        while !hold.release.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            match reader.get_mut().read(&mut [0]) {
                Ok(0) => {
                    hold.dropped.notify_one();
                    return Ok(());
                }
                Ok(_) => return Err("unexpected bytes after the federation request".into()),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            if started.elapsed() > Duration::from_secs(600) {
                return Err("held forwarder watchdog".into());
            }
        }
    }
    let response = serde_json::to_vec(
        &json!({"accepted":true,"source_node_id":"node-a","target_node_id":"node-b",
        "delivery":{"outcome":"forwarded","target_delivery_id":body["envelope"]["target_delivery_id"],"inbox_seq":1,"cursor":null}}),
    )?;
    let stream = reader.get_mut();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )?;
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}
pub(super) fn contact(
    own: &crate::prekey::SdkDeviceManifestResponse,
    peer: &crate::client::native_test_support::Fixture,
    forward: &Forwarder,
) -> Case<LocalBusFrame> {
    let target = peer.client.owned_device_identity()?;
    let body = crate::bus::protocol::LocalBusContactFederatedRequest {
        link_id: "keyed-contact-link".into(),
        requester_id: own.principal_commitment.clone(),
        target_id: target.root_commitment().into(),
        conversation_id: "keyed-contact-thread".into(),
        message_id: "keyed-contact-message".into(),
        envelope_id: "keyed-contact-envelope".into(),
        source_principal_id: own.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: target.device_id().into(),
        target_delivery_id: target.storage_key().into(),
        federation: LocalBusFederationRoute {
            federation_url: forward.endpoint.clone(),
            source_node_id: "node-a".into(),
            target_node_id: "node-b".into(),
            required_capability: "ramflux.federation.envelope_forward".into(),
            admin_token: None,
            recipient_prekey_url: None,
        },
    };
    let mut frame = LocalBusFrame::request(
        "contact-key",
        Some("alice".into()),
        "test",
        "contact.request",
        serde_json::to_value(body)?,
    );
    frame.operation_id = Some("native-contact-after-admit".into());
    Ok(frame)
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn keyed_contact_refusal_leaves_no_receipt_and_the_same_intent_succeeds_after_native_admission()
-> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let fixture = Box::pin(Fixture::with_mode(&[], true))
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;
    let (client, config) =
        Box::pin(budgets::native_config(&fixture, budgets::Origin::ExplicitEngine)).await?;
    let own = manifest(&client).map_err(|e| e as Box<dyn std::error::Error>)?;
    let peer = seed_peer(&client).await?;
    let reader = client.account_db()?.open_reader()?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    {
        let mut script = fixture.script.lock().map_err(|_| "script lock")?;
        script.hold_established = Some(Arc::clone(&entered));
        script.release_established = Some(Arc::clone(&release));
        script.ordinary = Some(ordinary::SessionScript {
            manifests: BTreeMap::from([
                (own.principal_commitment.clone(), own.clone()),
                (peer.manifest.principal_commitment.clone(), peer.manifest.clone()),
            ]),
            ..ordinary::SessionScript::default()
        });
    }
    let forward = forwarder(None)?;
    let request = contact(&own, &peer, &forward)?;
    let fingerprint = ramflux_crypto::blake3_256_base64url(
        "ramflux.operation.v1",
        &ramflux_protocol::canonical_json_bytes(&(&request.method, &request.body))?,
    );
    let limits = RuntimeTimeouts {
        network_wait: Duration::from_secs(5),
        ..RuntimeTimeouts::held_for_test()
    };
    let actor =
        Box::pin(NativeActor::start(client, config, b"native budget fixture".to_vec(), limits))
            .await?;
    entered.notified().await;
    let connection = actor.connection()?;
    let first = tokio::task::spawn_local(actor.request(request.clone()));
    while connection.test_live_waiters() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    let error = first.await?.err().ok_or("pre-admission contact request succeeded")?;
    assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
    assert!(matches!(
        reader.lookup_operation("native-contact-after-admit", &fingerprint)?,
        ramflux_storage::OperationLookup::Absent
    ));
    assert_eq!(forward.calls.load(Ordering::Acquire), 0);
    release.notify_one();
    connection.require_live(Duration::from_secs(600)).await?;
    tokio::time::resume();
    clock.abort();
    let response = actor.request(request.clone()).await?;
    assert_eq!(response["accepted"], true);
    assert_eq!(actor.request(request).await?, response);
    assert_eq!(forward.calls.load(Ordering::Acquire), 1, "same-key replay must not forward twice");
    assert!(matches!(
        reader.lookup_operation("native-contact-after-admit", &fingerprint)?,
        ramflux_storage::OperationLookup::Completed(_)
    ));
    actor.stop().await?;
    fixture.server.abort();
    Ok(())
}

pub(super) async fn seed_peer(
    client: &RamfluxClient,
) -> Case<crate::client::native_test_support::Fixture> {
    let peer = Box::pin(crate::client::native_test_support::Fixture::with_device(
        "keyed-contact-peer",
        "peer-device",
    ))
    .await?;
    client.persist_fetched_identity_directory(&peer.manifest)?;
    let local = client.owned_device_identity()?;
    let remote = peer.client.owned_device_identity()?;
    let pair = ramflux_crypto::DmSession::initiator(
        [17; 32],
        dm_device_id_hash(local.device_id()),
        dm_device_id_hash(remote.device_id()),
        [3; 32],
    )?;
    client.persist_pair(&local, &remote, &[4; 32], &pair)?;
    Ok(peer)
}

#[tokio::test(flavor = "current_thread")]
async fn lock_preempts_a_native_federation_http_wait_before_its_response() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            held_forward_case(),
        ))))
        .await
}
async fn held_forward_case() -> Case {
    let fixture = Box::pin(Fixture::with_mode(&[], true))
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;
    let (client, config) =
        Box::pin(budgets::native_config(&fixture, budgets::Origin::ExplicitEngine)).await?;
    let own = manifest(&client).map_err(|e| e as Box<dyn std::error::Error>)?;
    let peer = seed_peer(&client).await?;
    let reader = client.account_db()?.open_reader()?;
    fixture.script.lock().map_err(|_| "script lock")?.ordinary = Some(ordinary::SessionScript {
        manifests: BTreeMap::from([
            (own.principal_commitment.clone(), own.clone()),
            (peer.manifest.principal_commitment.clone(), peer.manifest.clone()),
        ]),
        ..ordinary::SessionScript::default()
    });
    let held = Arc::new(ForwardHold::default());
    let forward = forwarder(Some(Arc::clone(&held)))?;
    let request = contact(&own, &peer, &forward)?;
    let fingerprint = ramflux_crypto::blake3_256_base64url(
        "ramflux.operation.v1",
        &ramflux_protocol::canonical_json_bytes(&(&request.method, &request.body))?,
    );
    let actor = Box::pin(NativeActor::start(
        client,
        config,
        b"native budget fixture".to_vec(),
        RuntimeTimeouts::held_for_test(),
    ))
    .await?;
    let connection = actor.connection()?;
    connection.require_live(Duration::from_secs(600)).await?;
    let pending = tokio::task::spawn_local(actor.request(request));
    tokio::time::timeout(Duration::from_secs(10), held.entered.notified()).await?;
    assert_eq!(forward.calls.load(Ordering::Acquire), 1);
    let wall = std::time::Instant::now();
    let lock =
        LocalBusFrame::request("lock", Some("alice".into()), "test", "account.lock", json!({}));
    tokio::time::timeout(Duration::from_secs(1), actor.request(lock)).await??;
    assert!(wall.elapsed() < Duration::from_secs(1));
    assert!(pending.await?.is_err());
    tokio::time::timeout(Duration::from_secs(1), held.dropped.notified()).await?;
    assert!(connection.test_finished());
    assert!(matches!(
        reader.lookup_operation("native-contact-after-admit", &fingerprint)?,
        ramflux_storage::OperationLookup::Pending
    ));
    held.release.store(true, Ordering::Release);
    tokio::task::yield_now().await;
    assert!(matches!(
        reader.lookup_operation("native-contact-after-admit", &fingerprint)?,
        ramflux_storage::OperationLookup::Pending
    ));
    actor.stop().await?;
    fixture.server.abort();
    Ok(())
}
