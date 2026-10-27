// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::actor::AccountInitializer;
use super::supervisor::Supervisor;
use crate::prelude::*;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;

type GatewaySessionFrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

struct Gateway {
    last: Option<GatewayClientFrame>,
    pending_cursor: Option<GatewayCursor>,
    blocked: Option<GatewayBlock>,
    cancelled: Arc<AtomicBool>,
    submits: Arc<AtomicUsize>,
}
struct GatewayBlock {
    entered: oneshot::Sender<()>,
    submit_envelope: Option<String>,
}
struct Cancelled(Arc<AtomicBool>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl GatewaySessionFrameSink for Gateway {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        Box::pin(async move {
            let decoded = serde_json::from_slice(frame)
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            if matches!(decoded, GatewayClientFrame::Submit { .. }) {
                self.submits.fetch_add(1, Ordering::SeqCst);
            }
            self.last = Some(decoded);
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for Gateway {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let block = self.blocked.as_ref().and_then(|block| block.submit_envelope.as_deref()).is_none_or(|id| {
                matches!(&self.last, Some(GatewayClientFrame::Submit { submit }) if submit.envelope.envelope_id == id)
            });
            if block && let Some(blocked) = self.blocked.take() {
                let _guard = Cancelled(Arc::clone(&self.cancelled));
                let _ = blocked.entered.send(());
                return std::future::pending().await;
            }
            if let Some(cursor) = self.pending_cursor.take() {
                return serde_json::to_vec(&GatewayServerFrame::Cursor { cursor: Some(cursor) })
                    .map_err(|error| TransportError::Quic(error.to_string()));
            }
            let response = match self.last.take() {
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: Vec::new() }
                }
                Some(GatewayClientFrame::Ack { ack }) => {
                    let cursor = GatewayCursor {
                        target_delivery_id: "target".into(),
                        inbox_seq: 1,
                        last_envelope_id: Some(ack.envelope_id.clone()),
                        acked_envelope_ids: vec![ack.envelope_id],
                        nacked_envelope_ids: BTreeMap::new(),
                    };
                    self.pending_cursor = Some(cursor.clone());
                    GatewayServerFrame::Ack { cursor }
                }
                Some(GatewayClientFrame::Submit { submit }) => GatewayServerFrame::Deliver {
                    entry: GatewayInboxEntry {
                        inbox_seq: 1,
                        target_delivery_id: "target".to_owned(),
                        envelope: submit.envelope,
                    },
                },
                _ => {
                    GatewayServerFrame::Nack { reason: "unexpected test gateway frame".to_owned() }
                }
            };
            serde_json::to_vec(&response).map_err(|error| TransportError::Quic(error.to_string()))
        })
    }
}

pub(super) fn root(name: &str) -> PathBuf {
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    PathBuf::from("/tmp")
        .join(format!("ramflux-actor-{name}-{}-{sequence}-{unique}", std::process::id()))
}
pub(super) fn account(
    root: &Path,
    id: &str,
    blocked: Option<oneshot::Sender<()>>,
    cancelled: Arc<AtomicBool>,
) -> Result<LocalBusAccountState, SdkError> {
    account_with_setup(
        root,
        id,
        blocked,
        cancelled,
        Arc::new(AtomicUsize::new(0)),
        AccountSetup::default(),
    )
}
fn account_with_counter(
    root: &Path,
    id: &str,
    blocked: Option<oneshot::Sender<()>>,
    cancelled: Arc<AtomicBool>,
    submits: Arc<AtomicUsize>,
    index: Option<AccountIndex>,
) -> Result<LocalBusAccountState, SdkError> {
    account_with_setup(
        root,
        id,
        blocked,
        cancelled,
        submits,
        AccountSetup { index, ..AccountSetup::default() },
    )
}
#[derive(Default)]
struct AccountSetup {
    index: Option<AccountIndex>,
    blocked_submit_envelope: Option<String>,
}
fn account_with_setup(
    root: &Path,
    id: &str,
    blocked: Option<oneshot::Sender<()>>,
    cancelled: Arc<AtomicBool>,
    submits: Arc<AtomicUsize>,
    setup: AccountSetup,
) -> Result<LocalBusAccountState, SdkError> {
    let mut client = RamfluxClient::new();
    client.account_index = setup.index;
    let root_seed = ramflux_crypto::blake3_256("ramflux.test.account.root.v1", id.as_bytes());
    client.create_identity_root(id, root_seed);
    client.create_device_branch(id, &format!("device-{id}"), 1, [0x62; 32]);
    client.open_account_index(root)?;
    if matches!(client.account_index()?.account(id), Err(StorageError::AccountNotFound(_))) {
        client.create_account(id, &format!("commitment-{id}"))?;
    }
    client.unlock_account(id, b"actor-test-secret")?;
    client.account_db()?.establish_friend_link("friend", id, "alice")?;
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0"
            .parse()
            .map_err(|error| SdkError::LocalBus(format!("test addr: {error}")))?,
        gateway_addr: "127.0.0.1:1"
            .parse()
            .map_err(|error| SdkError::LocalBus(format!("test addr: {error}")))?,
        server_name: "test-gateway".to_owned(),
        ca_cert: root.join("ca.pem"),
        principal_id: id.to_owned(),
        device_id: format!("device-{id}"),
        target_delivery_id: "target".to_owned(),
        prekey_http_url: None,
    };
    write_local_bus_account_manifest(
        root,
        &LocalBusPersistedAccount {
            label: None,
            kind: None,
            activation_pending: false,
            node_id: None,
            node_tcp_addr: None,
            node_relay: None,
            schema: "ramflux.local_bus.account_manifest.v1".to_owned(),
            local_account_id: id.to_owned(),
            principal_id: id.to_owned(),
            principal_commitment: format!("commitment-{id}"),
            device_id: format!("device-{id}"),
            target_delivery_id: "target".to_owned(),
            account_secret: "actor-test-secret".to_owned(),
            root_seed,
            device_seed: [0x62; 32],
            client_mode: LocalBusClientMode::AttendedCli,
            gateway: endpoint.clone(),
            devices: Vec::new(),
        },
    )?;
    let config = GatewaySessionConfig::quic(endpoint).with_account_identity(&client)?;
    let engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(Gateway {
            last: None,
            pending_cursor: None,
            blocked: blocked.map(|entered| GatewayBlock {
                entered,
                submit_envelope: setup.blocked_submit_envelope,
            }),
            cancelled,
            submits,
        }),
    );
    Ok(LocalBusAccountState::new(client, engine, format!("commitment-{id}")))
}
fn actor_account(
    root: &Path,
    id: &str,
    blocked: Option<oneshot::Sender<()>>,
    cancelled: Arc<AtomicBool>,
) -> AccountInitializer {
    actor_account_with_counter(root, id, blocked, cancelled, Arc::new(AtomicUsize::new(0)))
}
fn actor_account_with_counter(
    root: &Path,
    id: &str,
    blocked: Option<oneshot::Sender<()>>,
    cancelled: Arc<AtomicBool>,
    submits: Arc<AtomicUsize>,
) -> AccountInitializer {
    let root = root.to_path_buf();
    let id = id.to_owned();
    Box::new(move |index| {
        account_with_setup(
            &root,
            &id,
            blocked,
            cancelled,
            submits,
            AccountSetup { index: Some(index), ..AccountSetup::default() },
        )
    })
}
fn supervisor(
    root: &Path,
    accounts: BTreeMap<String, AccountInitializer>,
) -> Result<Rc<Supervisor>, SdkError> {
    Supervisor::from_initializers(
        &LocalBusConfig::new(root.join("bus.sock"), root),
        accounts.into_iter().collect(),
        None,
    )
}
fn request(id: &str, account: &str, method: &str, body: serde_json::Value) -> LocalBusFrame {
    LocalBusFrame::request(id, Some(account.to_owned()), "test", method, body)
}
async fn client(
    supervisor: Rc<Supervisor>,
    id: u64,
) -> Result<(LocalBusClient, tokio::task::JoinHandle<Result<(), SdkError>>), SdkError> {
    let path = root("socket");
    std::fs::create_dir_all(&path)?;
    let socket = path.join("bus.sock");
    let listener = UnixListener::bind(&socket)
        .map_err(|error| failure(&format!("test socket bind {}: {error}", socket.display())))?;
    let client = LocalBusClient::connect(&socket).await?;
    let (stream, _) = listener.accept().await?;
    let task = tokio::task::spawn_local(super::connection::handle(stream, supervisor, id));
    std::fs::remove_file(socket)?;
    std::fs::remove_dir(path)?;
    Ok((client, task))
}

#[tokio::test(flavor = "current_thread")]
async fn slow_gateway_does_not_block_other_account_send_or_socket_reads() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("independent");
        let (entered, blocked) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let alice_root = root.clone();
        let alice_cancelled = Arc::clone(&cancelled);
        let alice: AccountInitializer = Box::new(move |index| account_with_setup(
            &alice_root,"alice",Some(entered),alice_cancelled,Arc::new(AtomicUsize::new(0)),
            AccountSetup{index:Some(index),blocked_submit_envelope:Some("slow-envelope".into())},
        ));
        let bob = actor_account(&root, "bob", None, Arc::new(AtomicBool::new(false)));
        let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), alice), ("bob".to_owned(), bob)]))?;
        let (one, server_one) = client(Rc::clone(&supervisor), 1).await?;
        let (two, server_two) = client(Rc::clone(&supervisor), 2).await?;
        // Warm the sending accounts before timing isolation from Alice's blocked gateway.
        // The checked send below keeps its original 500 ms deadline and unique response id.
        two.request_frame(request("warm-send", "bob", "message.submit", serde_json::json!({
            "conversation_id":"conversation", "message_id":"warm-message", "envelope_id":"warm-envelope",
            "source_principal_id":"bob", "sender_id":"device-bob", "recipient_principal_commitment":"alice",
            "target_delivery_id":"target", "encrypted_body_base64":ramflux_protocol::encode_base64url(b"warm opaque"), "created_at":1, "ttl":60
        }))).await?;
        one.request_frame(request("warm-alice", "alice", "message.submit", serde_json::json!({
            "conversation_id":"conversation", "message_id":"warm-alice-message", "envelope_id":"warm-alice-envelope",
            "source_principal_id":"alice", "sender_id":"device-alice", "recipient_principal_commitment":"alice",
            "target_delivery_id":"target", "encrypted_body_base64":ramflux_protocol::encode_base64url(b"warm opaque"), "created_at":1, "ttl":60
        }))).await?;
        // Background receive polls cannot consume this foreground submit's blocking signal.
        let slow_client = one.clone();
        let slow = tokio::task::spawn_local(async move {
            slow_client.request_frame(request("slow", "alice", "message.submit", serde_json::json!({
                "conversation_id":"conversation", "message_id":"slow-message", "envelope_id":"slow-envelope",
                "source_principal_id":"alice", "sender_id":"device-alice", "recipient_principal_commitment":"alice",
                "target_delivery_id":"target", "encrypted_body_base64":ramflux_protocol::encode_base64url(b"opaque"), "created_at":1, "ttl":60
            }))).await
        });
        tokio::time::timeout(Duration::from_secs(2), blocked).await.map_err(|_| failure("gateway not entered"))?.map_err(|_| failure("gateway dropped"))?;
        let sent = tokio::time::timeout(Duration::from_millis(500), two.request_frame(request("send", "bob", "message.submit", serde_json::json!({
            "conversation_id":"conversation", "message_id":"message", "envelope_id":"envelope",
            "source_principal_id":"bob", "sender_id":"device-bob", "recipient_principal_commitment":"alice",
            "target_delivery_id":"target", "encrypted_body_base64":ramflux_protocol::encode_base64url(b"opaque"), "created_at":1, "ttl":60
        })))).await.map_err(|_| failure("other account send blocked"))??;
        assert_eq!(sent["envelope"]["envelope_id"], "envelope");
        let read = tokio::time::timeout(Duration::from_millis(500), one.request_frame(request("read", "alice", "message.list", serde_json::json!({"conversation_id":"conversation"})))).await.map_err(|_| failure("same socket read blocked"))??;
        assert!(read["messages"].is_array());
        let other_read = tokio::time::timeout(Duration::from_millis(500), two.request_frame(request("list", "bob", "conversation.list", serde_json::json!({})))).await.map_err(|_| failure("second socket read blocked"))??;
        assert_eq!(other_read["conversations"].as_array().map(Vec::len), Some(1));
        slow.abort();
        let _ = slow.await;
        drop(one);
        drop(two);
        let _ = server_one.await;
        let _ = server_two.await;
        tokio::time::timeout(Duration::from_millis(500), async {
            while !cancelled.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
        }).await.map_err(|_| failure("gateway call not cancelled on disconnect"))?;
        supervisor.shutdown().await?;
        drop(supervisor);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }).await
}

fn failure(message: &str) -> SdkError {
    SdkError::LocalBus(message.to_owned())
}

#[tokio::test(flavor = "current_thread")]
async fn object_upload_keeps_same_account_reads_live_and_disconnect_cancels_network()
-> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("object");
        let (entered, blocked) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let account = actor_account(&root, "alice", Some(entered), Arc::clone(&cancelled));
        let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), account)]))?;
        let (one, server) = client(Rc::clone(&supervisor), 1).await?;
        let upload_client = one.clone();
        let upload = tokio::task::spawn_local(async move {
            upload_client.request_frame(request("upload", "alice", "object.put", serde_json::json!({
                "object_id":"object", "operation_id":"upload-operation", "plaintext_base64":ramflux_protocol::encode_base64url(b"object contents"),
                "chunk_size":4096, "relay_endpoint":"https://relay.invalid"
            }))).await
        });
        tokio::time::timeout(Duration::from_secs(2), blocked).await.map_err(|_| failure("upload did not reach gateway"))?.map_err(|_| failure("upload gateway closed"))?;
        for (id, method, body) in [
            ("messages", "message.list", serde_json::json!({"conversation_id":"conversation"})),
            ("conversations", "conversation.list", serde_json::json!({})),
        ] {
            tokio::time::timeout(Duration::from_millis(500), one.request_frame(request(id, "alice", method, body))).await.map_err(|_| failure("upload blocked read"))??;
        }
        drop(one);
        // The upload clone keeps the socket alive until the caller cancels it too.
        upload.abort();
        let _ = upload.await;
        let _ = server.await;
        tokio::time::timeout(Duration::from_millis(500), async {
            while !cancelled.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
        }).await.map_err(|_| failure("upload network was not cancelled"))?;
        supervisor.shutdown().await?;
        drop(supervisor);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn mutation_key_applies_once_and_survives_account_actor_restart() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("idempotency");
        let submits = Arc::new(AtomicUsize::new(0));
        let body = serde_json::json!({
            "conversation_id":"conversation", "message_id":"message", "envelope_id":"envelope",
            "source_principal_id":"bob", "sender_id":"device-bob", "recipient_principal_commitment":"alice",
            "target_delivery_id":"target", "encrypted_body_base64":ramflux_protocol::encode_base64url(b"opaque"), "created_at":1, "ttl":60
        });
        let mut expected = None;
        for round in 0..2 {
            let bob = actor_account_with_counter(&root, "bob", None, Arc::new(AtomicBool::new(false)), Arc::clone(&submits));
            let supervisor = supervisor(&root, BTreeMap::from([("bob".to_owned(), bob)]))?;
            let (client, server) = client(Rc::clone(&supervisor), 1).await?;
            for retry in 0..2 {
                let mut frame = request(&format!("send-{round}-{retry}"), "bob", "message.submit", body.clone());
                frame.operation_id = Some("send-operation".to_owned());
                let result = client.request_frame(frame).await?;
                if let Some(expected) = &expected { assert_eq!(&result, expected); }
                else { expected = Some(result); }
            }
            let mut conflict = request("conflict", "bob", "message.submit", serde_json::json!({"different":"intent"}));
            conflict.operation_id = Some("send-operation".to_owned());
            assert!(client.request_frame(conflict).await.is_err());
            let messages = client.request_frame(request("messages", "bob", "message.list", serde_json::json!({"conversation_id":"conversation"}))).await?;
            assert_eq!(messages["messages"].as_array().map(Vec::len), Some(1));
            drop(client);
            let _ = server.await;
            supervisor.shutdown().await?;
        }
        assert_eq!(submits.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn lock_waits_for_writer_and_readers_to_stop_and_unlock_starts_new_actor()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("lifecycle");
            let account = actor_account(&root, "alice", None, Arc::new(AtomicBool::new(false)));
            let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), account)]))?;
            let (client, server) = client(Rc::clone(&supervisor), 1).await?;
            let old = supervisor.account_actor("alice").ok_or_else(|| failure("missing actor"))?;
            let locked = client
                .request_frame(request("lock", "alice", "account.lock", serde_json::json!({})))
                .await?;
            assert_eq!(locked["locked"], true);
            assert!(old.has_stopped(), "lock ACK follows the actor/DB-thread teardown");
            assert!(!old.is_open());
            assert!(
                client
                    .request_frame(request(
                        "locked-read",
                        "alice",
                        "conversation.list",
                        serde_json::json!({})
                    ))
                    .await
                    .is_err()
            );
            let unlocked = client
                .request_frame(request(
                    "unlock",
                    "alice",
                    "account.unlock",
                    serde_json::json!({"passphrase":"actor-test-secret"}),
                ))
                .await?;
            assert_eq!(unlocked["local_account_id"], "alice");
            assert!(
                supervisor
                    .account_actor("alice")
                    .is_some_and(|actor| actor.is_open() && !actor.has_stopped())
            );
            client
                .request_frame(request("read", "alice", "conversation.list", serde_json::json!({})))
                .await?;
            drop(client);
            let _ = server.await;
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn expired_or_queued_deadlines_do_not_apply_mutations() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("deadline");
        let (entered, blocked) = oneshot::channel();
        let account = actor_account(&root, "alice", Some(entered), Arc::new(AtomicBool::new(false)));
        let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), account)]))?;
        let (client, server) = client(Rc::clone(&supervisor), 1).await?;
        let mut expired = request("expired", "alice", "contact.add", serde_json::json!({"link_id":"expired", "requester_id":"alice", "target_id":"target"}));
        expired.deadline_ms = Some(1);
        assert!(client.request_frame(expired).await.is_err());
        let held = client.clone();
        let slow = tokio::task::spawn_local(async move { held.request_frame(request("hold", "alice", "message.receive", serde_json::json!({"limit":1}))).await });
        tokio::time::timeout(Duration::from_secs(2), blocked).await.map_err(|_| failure("gateway not entered"))?.map_err(|_| failure("gateway dropped"))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| u64::try_from(time.as_millis()).unwrap_or(u64::MAX));
        let mut queued = request("queued", "alice", "contact.add", serde_json::json!({"link_id":"queued", "requester_id":"alice", "target_id":"target"}));
        queued.deadline_ms = Some(now.saturating_add(100));
        let rejected = client.request_frame(queued).await;
        assert!(rejected.is_err());
        slow.abort();
        let _ = slow.await;
        drop(client);
        let _ = server.await;
        supervisor.shutdown().await?;
        drop(supervisor);
        let index = AccountIndex::open(&root)?;
        // Reopen through the public SDK so the wrapped random account key is respected.
        let mut verifier = RamfluxClient::new();
        verifier.open_account_index(&root)?;
        verifier.unlock_account("alice", b"actor-test-secret")?;
        assert!(verifier.account_db()?.friend_link("expired").is_err());
        assert!(verifier.account_db()?.friend_link("queued").is_err());
        drop(index);
        drop(verifier);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn committed_unpublished_outbox_is_routed_when_account_starts() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("outbox-replay");
            let initialize = actor_account(&root, "alice", None, Arc::new(AtomicBool::new(false)));
            let account: AccountInitializer = Box::new(move |index| {
                let account = initialize(index)?;
                account.client.append_event("before-publish", "test", b"durable domain change")?;
                Ok(account)
            });
            let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), account)]))?;
            let (mut client, server) = client(Rc::clone(&supervisor), 1).await?;
            client
                .request_frame(request(
                    "subscribe",
                    "alice",
                    "subscription.open",
                    serde_json::json!({"topics":["state.changed"]}),
                ))
                .await?;
            client
                .request_frame(request("read", "alice", "conversation.list", serde_json::json!({})))
                .await?;
            let mut found = false;
            let mut migration = false;
            let mut friend = false;
            let mut sequence = 0;
            // Startup replays the migration marker as well as the friend and domain changes.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
            for _ in 0..3 {
                let event = tokio::time::timeout_at(
                    deadline.min(tokio::time::Instant::now() + Duration::from_secs(2)),
                    client.next_event(),
                )
                .await
                .map_err(|_| failure("outbox replay timed out"))??;
                assert_eq!(event.method, "state.changed");
                assert_eq!(event.account_id.as_deref(), Some("alice"));
                let next = event.body["sequence"].as_i64().ok_or_else(|| failure("sequence"))?;
                assert!(next > sequence);
                sequence = next;
                match event.body["table_name"].as_str() {
                    Some("runtime_actor_state") => {
                        assert_eq!(
                            event.body["keys"]["state_kind"],
                            crate::client::contact_verification::MIGRATION_MARKER
                        );
                        migration = true;
                    }
                    Some("friend_link_projection") => {
                        assert_eq!(event.body["keys"]["link_id"], "friend");
                        friend = true;
                    }
                    Some("local_event_log") => found = true,
                    _ => return Err(failure("unexpected startup outbox change")),
                }
            }
            assert!(found && migration && friend);
            drop(client);
            let _ = server.await;
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[test]
fn evicted_object_cache_entries_reload_from_encrypted_db() -> Result<(), SdkError> {
    let root = root("object-cache");
    let mut account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    account.client.object_store.set_cache_capacity(2);
    for id in ["one", "two", "three", "four"] {
        account.client.put_encrypted_object(id, id.as_bytes())?;
    }
    assert_eq!(account.client.object_store.objects().len(), 2);
    assert!(account.client.object_store.cached_object("one").is_none());
    assert_eq!(account.client.decrypt_object("one")?, b"one");
    account.client.tombstone_object("one")?;
    assert!(account.client.decrypt_object("one").is_err());
    assert_eq!(account.client.persisted_objects()?.len(), 4);
    assert!(account.client.object_store.objects().len() <= 2);
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pipelined_mutations_keep_mailbox_order_and_control_state_survives_restart()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("control-order");
            for round in 0..2 {
                let account_root = root.clone();
                let initialize: AccountInitializer = Box::new(move |index| {
                    let account = account_with_setup(
                        &account_root,
                        "alice",
                        None,
                        Arc::new(AtomicBool::new(false)),
                        Arc::new(AtomicUsize::new(0)),
                        AccountSetup { index: Some(index), ..AccountSetup::default() },
                    )?;
                    account.client.initialize_and_publish_prekey_bundle(
                        "alice",
                        "device-alice",
                        "target",
                        [0x62; 32],
                        None,
                    )?;
                    let authority =
                        crate::client::identity_authority::test_support::manifest(&account.client)?;
                    account.client.persist_identity_directory(&authority)?;
                    account.client.record_owned_proof_published(now_unix_timestamp())?;
                    if round == 0 {
                        let event = A2iControlEvent {
                            event_id: "ordered-control".into(),
                            event_type: "request".into(),
                            source_device_id: "device-alice".into(),
                            source_principal_id: Some("alice".into()),
                            source_principal_commitment: Some(
                                account.client.surface_local_root_commitment()?,
                            ),
                            target_device_id: "device-alice".into(),
                            control_domain: "automation".into(),
                            action: "notify".into(),
                            subject_base64: ramflux_protocol::encode_base64url(b"control"),
                            created_at: 1,
                            acknowledged: false,
                        };
                        account.client.account_db()?.persist_actor_state(
                            &crate::client::routed::control::a2i_key(
                                &account.client.local_device_identity(&event.source_device_id)?,
                                &event.event_id,
                            )?,
                            &event,
                        )?;
                    }
                    Ok(account)
                });
                let supervisor =
                    supervisor(&root, BTreeMap::from([("alice".to_owned(), initialize)]))?;
                let (client, server) = client(Rc::clone(&supervisor), 1).await?;
                if round == 0 {
                    // Use durable controls rather than the removed local-only call stub. Both requests
                    // use the mutation mailbox: the pending list must observe the earlier ACK.
                    let ack = client.request_frame(request(
                        "ack",
                        "alice",
                        "a2i.acknowledge",
                        serde_json::json!({"event_id":"ordered-control"}),
                    ));
                    let list = client.request_frame(request(
                        "list",
                        "alice",
                        "a2i.list_pending",
                        serde_json::json!({}),
                    ));
                    let (acknowledged, pending) = tokio::join!(ack, list);
                    assert_eq!(acknowledged?["acknowledged"], true);
                    assert_eq!(pending?["events"].as_array().map(Vec::len), Some(0));
                } else {
                    let events = client
                        .request_frame(request(
                            "restored",
                            "alice",
                            "a2i.list",
                            serde_json::json!({}),
                        ))
                        .await?;
                    assert_eq!(events["events"].as_array().map(Vec::len), Some(1));
                    assert_eq!(events["events"][0]["event_id"], "ordered-control");
                    assert_eq!(events["events"][0]["acknowledged"], true);
                }
                drop(client);
                let _ = server.await;
                supervisor.shutdown().await?;
            }
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test]
async fn client_rejects_wrong_response_kinds_and_fails_later_requests_without_hanging()
-> Result<(), SdkError> {
    let root = root("client-protocol");
    std::fs::create_dir_all(&root)?;
    let socket = root.join("bus.sock");
    let listener = UnixListener::bind(&socket)?;
    let client = LocalBusClient::connect(&socket).await?;
    let (mut stream, _) = listener.accept().await?;
    let server = tokio::spawn(async move {
        let frame = read_local_bus_frame(&mut stream).await?;
        write_local_bus_frame(&mut stream, &frame).await?;
        std::future::pending::<Result<(), SdkError>>().await
    });
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        client.request_frame(request(
            "wrong-kind",
            "alice",
            "conversation.list",
            serde_json::json!({}),
        )),
    )
    .await
    .map_err(|_| failure("malformed response hung client"))?;
    assert!(response.is_err());
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        client.request_frame(request(
            "after-close",
            "alice",
            "conversation.list",
            serde_json::json!({}),
        )),
    )
    .await
    .map_err(|_| failure("closed connection accepted hanging request"))?;
    assert!(response.is_err());
    server.abort();
    let _ = server.await;
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_keys_remain_idempotent_after_lock_and_process_supervisor_restart()
-> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("lifecycle-keys");
            let initialize = actor_account(&root, "alice", None, Arc::new(AtomicBool::new(false)));
            let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), initialize)]))?;
            let (client, server) = client(Rc::clone(&supervisor), 1).await?;
            let mut lock = request("lock", "alice", "account.lock", serde_json::json!({}));
            lock.operation_id = Some("lock-once".to_owned());
            let first = client.request_frame(lock.clone()).await?;
            lock.request_id = "lock-retry".to_owned();
            lock.frame_id = "frame_lock-retry".to_owned();
            assert_eq!(client.request_frame(lock).await?, first);
            let mut unlock = request(
                "unlock",
                "alice",
                "account.unlock",
                serde_json::json!({"passphrase":"actor-test-secret"}),
            );
            unlock.operation_id = Some("unlock-once".to_owned());
            let opened = client.request_frame(unlock.clone()).await?;
            client
                .request_frame(request(
                    "lock-again",
                    "alice",
                    "account.lock",
                    serde_json::json!({}),
                ))
                .await?;
            assert_eq!(client.request_frame(unlock.clone()).await?, opened);
            assert!(
                supervisor.account_actor("alice").is_none(),
                "a cached unlock receipt must not reopen a subsequently locked account"
            );
            drop(client);
            let _ = server.await;
            supervisor.shutdown().await?;
            drop(supervisor);
            let config = LocalBusConfig::new(root.join("bus.sock"), &root);
            let restarted = Supervisor::from_initializers(&config, Vec::new(), None)?;
            let (client, server) = self::client(Rc::clone(&restarted), 2).await?;
            assert_eq!(client.request_frame(unlock).await?, opened);
            assert!(restarted.account_actor("alice").is_none());
            let index = AccountIndex::open(&root)?;
            assert_eq!(index.account("alice")?.account_state, "locked");
            drop(index);
            drop(client);
            let _ = server.await;
            restarted.shutdown().await?;
            drop(restarted);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_stop_cancels_network_flushes_outbox_and_removes_socket() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("stop-drain");
        let (entered,blocked) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let initialize = actor_account(&root,"alice",Some(entered),Arc::clone(&cancelled));
        let supervisor = supervisor(&root,BTreeMap::from([("alice".to_owned(),initialize)]))?;
        let actor = supervisor.account_actor("alice").ok_or_else(|| failure("missing actor"))?;
        let socket = root.join("daemon.sock"); let listener = UnixListener::bind(&socket)?;
        let uid = std::fs::metadata(&socket)?.uid(); let (_shutdown,receiver) = watch::channel(false);
        let server = tokio::task::spawn_local(super::connection::accept(listener,uid,Rc::clone(&supervisor),receiver));
        let client = LocalBusClient::connect(&socket).await?;
        let upload_client = client.clone();
        let upload = tokio::task::spawn_local(async move { upload_client.request_frame(request("upload","alice","object.put",serde_json::json!({"object_id":"object","operation_id":"upload-operation","plaintext_base64":ramflux_protocol::encode_base64url(b"durable upload"),"chunk_size":4096,"relay_endpoint":"https://relay.invalid"}))).await });
        tokio::time::timeout(Duration::from_secs(2),blocked).await.map_err(|_| failure("upload did not reach gateway"))?.map_err(|_| failure("gateway dropped"))?;
        let stop_client = LocalBusClient::connect(&socket).await?;
        let response = tokio::time::timeout(Duration::from_secs(2),stop_client.request_frame(LocalBusFrame::request("stop",None,"daemon","daemon.stop",serde_json::json!({})))).await.map_err(|_| failure("daemon stop timed out"))??;
        assert_eq!(response["stopping"],true);
        tokio::time::timeout(Duration::from_secs(2),server).await.map_err(|_| failure("daemon listener did not stop"))?.map_err(|error| failure(&error.to_string()))??;
        assert!(!socket.exists()); assert!(actor.has_stopped()); assert!(cancelled.load(Ordering::SeqCst));
        let _ = upload.await; drop(client); drop(stop_client); drop(supervisor);
        let mut verifier = RamfluxClient::new(); verifier.open_account_index(&root)?; verifier.unlock_account("alice",b"actor-test-secret")?;
        assert_eq!(verifier.account_db()?.pending_outbox(256)?,Vec::new());
        assert_eq!(verifier.object_operation("object")?.map(|operation| operation.state),Some(OBJECT_OPERATION_LOCAL_COMMITTED.to_owned()));
        drop(verifier); std::fs::remove_dir_all(root)?;
        Ok(())
    }).await
}

#[tokio::test]
async fn daemon_stop_works_through_the_public_embedded_entrypoint() -> Result<(), SdkError> {
    let root = root("public-stop");
    let socket = root.join("daemon.sock");
    let (_shutdown, receiver) = watch::channel(false);
    let config = LocalBusConfig::new(&socket, &root);
    let server = tokio::spawn(async move { serve_local_bus_until(config, receiver).await });
    let mut client = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match LocalBusClient::connect(&socket).await {
                Ok(client) => break client,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await
    .map_err(|_| failure("public daemon did not start"))?;
    let response = client.request(None, "daemon", "daemon.stop", serde_json::json!({})).await?;
    assert_eq!(response["stopping"], true);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .map_err(|_| failure("public daemon did not stop"))?
        .map_err(|error| failure(&error.to_string()))??;
    assert!(!socket.exists());
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn account_credentials_are_durable_before_activation_can_fail_or_be_cancelled()
-> Result<(), SdkError> {
    let root = root("activation");
    let gateway = GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|error| failure(&format!("{error}")))?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|error| failure(&format!("{error}")))?,
        server_name: "missing-gateway".to_owned(),
        ca_cert: root.join("missing-ca.pem"),
        principal_id: "alice".to_owned(),
        device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        prekey_http_url: None,
    };
    let mut state = LocalBusDaemonState {
        account_index: Some(AccountIndex::open(&root)?),
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let body = LocalBusAccountCreateRequest {
        label: None,
        kind: None,
        node_id: None,
        local_account_id: "alice".to_owned(),
        principal_id: "alice".to_owned(),
        principal_commitment: String::new(),
        device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        account_secret: "activation-secret".to_owned(),
        root_seed: [0x71; 32],
        device_seed: [0x72; 32],
        client_mode: LocalBusClientMode::AttendedCli,
        gateway,
    };
    assert!(local_bus_account_create(&mut state, body).await.is_err());
    let manifest =
        read_local_bus_account_manifest(&local_bus_account_manifest_path(&root, "alice"))?;
    assert!(manifest.activation_pending);
    assert_eq!(manifest.root_seed, [0x71; 32]);
    assert_eq!(manifest.device_seed, [0x72; 32]);
    assert!(
        state.accounts.contains_key("alice"),
        "the actor retains its writer for cancellation cleanup and outbox publication"
    );
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn client_directories_progress_while_gateway_is_blocked() -> Result<(), SdkError> {
    LocalSet::new()
        .run_until(async {
            let root = root("directories-progress");
            let (entered, blocked) = oneshot::channel();
            let initialize =
                actor_account(&root, "alice", Some(entered), Arc::new(AtomicBool::new(false)));
            let supervisor = supervisor(&root, BTreeMap::from([("alice".to_owned(), initialize)]))?;
            let (one, server) = client(Rc::clone(&supervisor), 1).await?;
            let slow_client = one.clone();
            let slow = tokio::task::spawn_local(async move {
                slow_client
                    .request_frame(request(
                        "slow",
                        "alice",
                        "message.receive",
                        serde_json::json!({"limit":1}),
                    ))
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), blocked)
                .await
                .map_err(|_| failure("gateway not entered"))?
                .map_err(|_| failure("gateway dropped"))?;
            for method in [
                "conversation.directory",
                "identity.directory",
                "object.directory",
                "group.list",
                "mcp.server.list",
                "mcp.approval.list",
            ] {
                let result = tokio::time::timeout(
                    Duration::from_millis(500),
                    one.request_frame(request(
                        method,
                        "alice",
                        method,
                        serde_json::json!({"limit":5}),
                    )),
                )
                .await
                .map_err(|_| failure("directory blocked behind gateway"))??;
                assert!(result.get("next_cursor").is_some());
            }
            slow.abort();
            let _ = slow.await;
            drop(one);
            let _ = server.await;
            supervisor.shutdown().await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn account_read_model_retains_locked_manifest_profiles_after_restart() -> Result<(), SdkError>
{
    LocalSet::new()
        .run_until(async {
            let root = root("locked-directory");
            let initialize = actor_account(&root, "alice", None, Arc::new(AtomicBool::new(false)));
            let profile_root = root.clone();
            let initialize: AccountInitializer = Box::new(move |index| {
                let account = initialize(index)?;
                let path = local_bus_account_manifest_path(&profile_root, "alice");
                let mut manifest = read_local_bus_account_manifest(&path)?;
                manifest.label = Some("Work".to_owned());
                manifest.kind = Some("headless_ai".to_owned());
                write_local_bus_account_manifest(&profile_root, &manifest)?;
                Ok(account)
            });
            let first = supervisor(&root, BTreeMap::from([("alice".to_owned(), initialize)]))?;
            let (socket, server) = client(Rc::clone(&first), 1).await?;
            let list = socket
                .request_frame(request("list", "alice", "account.list", serde_json::json!({})))
                .await?;
            assert_eq!(list["account_details"][0]["state"], "unlocked");
            assert_eq!(list["account_details"][0]["label"], "Work");
            socket
                .request_frame(request("lock", "alice", "account.lock", serde_json::json!({})))
                .await?;
            drop(socket);
            let _ = server.await;
            first.shutdown().await?;
            drop(first);
            let restarted = supervisor(&root, BTreeMap::new())?;
            let (socket, server) = client(Rc::clone(&restarted), 2).await?;
            let list = socket
                .request_frame(request(
                    "list-again",
                    "alice",
                    "account.list",
                    serde_json::json!({}),
                ))
                .await?;
            assert_eq!(list["accounts"], serde_json::json!([]));
            assert_eq!(list["account_details"][0]["state"], "locked");
            assert_eq!(list["account_details"][0]["kind"], "headless_ai");
            drop(socket);
            let _ = server.await;
            restarted.shutdown().await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn approval_directory_and_events_preserve_origin_context() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root=root("approval-context");let initialize=actor_account(&root,"alice",None,Arc::new(AtomicBool::new(false)));
        let supervisor=supervisor(&root,BTreeMap::from([("alice".to_owned(),initialize)]))?;
        let (mut socket,server)=client(Rc::clone(&supervisor),1).await?;
        socket.request_frame(request("subscribe","alice","subscription.open",serde_json::json!({"topics":["mcp.approval.request"]}))).await?;
        socket.request_frame(request("server","alice","mcp.server.add",serde_json::json!({"server_id":"server","command":"stdio-echo","tool_name":"echo","capability":"read_conversation","risk_level":"low"}))).await?;
        socket.request_frame(request("tool","alice","mcp.tool.started",serde_json::json!({"server_id":"server","tool_name":"echo","arguments":{"text":"context"},"conversation_id":"thread","context_id":"context"}))).await?;
        let event=tokio::time::timeout(Duration::from_secs(2),socket.next_event()).await.map_err(|_|failure("approval event missing"))??;
        assert_eq!(event.body["conversation_id"],"thread");
        let approvals=socket.request_frame(request("approvals","alice","mcp.approval.list",serde_json::json!({"limit":10}))).await?;
        assert_eq!(approvals["approvals"][0]["conversation_id"],"thread");assert_eq!(approvals["approvals"][0]["context_id"],"context");
        drop(socket);let _=server.await;supervisor.shutdown().await?;std::fs::remove_dir_all(root)?;Ok(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn group_send_lists_every_missing_member_before_writing_a_message() -> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root=root("group-routes");let initialize=actor_account(&root,"alice",None,Arc::new(AtomicBool::new(false)));
        let initialize:AccountInitializer=Box::new(move |index| {
            let account=initialize(index)?;account.client.create_group("group","device-alice")?;
            account.client.account_db()?.add_group_member("group","device-bob","member")?;account.client.account_db()?.add_group_member("group","device-charlie","member")?;Ok(account)
        });
        let supervisor=supervisor(&root,BTreeMap::from([("alice".to_owned(),initialize)]))?;let (socket,server)=client(Rc::clone(&supervisor),1).await?;
        let response=socket.request_frame(request("send","alice","group.send",serde_json::json!({"group_id":"group","conversation_id":"thread","message_id":"message","sender_id":"device-alice","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"group message")}))).await;
        let error=response.err().ok_or_else(||failure("group send silently omitted members"))?.to_string();
        assert!(error.contains("device-bob"));assert!(error.contains("device-charlie"));assert!(error.contains("unreachable_members"));
        let messages=socket.request_frame(request("read","alice","message.list",serde_json::json!({"conversation_id":"thread"}))).await?;assert_eq!(messages["messages"],serde_json::json!([]));
        drop(socket);let _=server.await;supervisor.shutdown().await?;std::fs::remove_dir_all(root)?;Ok(())
    }).await
}

#[test]
fn group_routes_resolve_from_verified_directory_for_all_current_members() -> Result<(), SdkError> {
    let root = root("group-directory-routes");
    let account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    account.client.create_group("group", "device-alice")?;
    account.client.account_db()?.add_group_member("group", "device-bob", "member")?;
    let mut manifest = crate::client::identity_authority::test_support::remote_manifest(
        "bob",
        "device-bob",
        [81; 32],
    )?;
    manifest.devices[0].target_delivery_id = "delivery-bob".into();
    account.client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    account.client.persist_group_member_route(
        "group",
        &LocalBusGroupMemberRoute {
            member_id: "device-bob".into(),
            member_principal_commitment: Some(manifest.principal_commitment.clone()),
            device_signing_public_key: None,
            target_delivery_id: None,
            federation: None,
        },
    )?;
    let body: LocalBusGroupSendRequest = serde_json::from_value(
        serde_json::json!({"group_id":"group","conversation_id":"thread","message_id":"message","sender_id":"device-alice","encrypted_body_base64":""}),
    )?;
    let routes = super::group_delivery::resolve(&account, &body)?;
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].target_delivery_id.as_deref(), Some("delivery-bob"));
    assert_eq!(
        routes[0].member_principal_commitment.as_deref(),
        Some(manifest.principal_commitment.as_str())
    );
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

mod metadata;
mod push_clear;
mod restore;
mod stream;

#[tokio::test]
async fn inbound_resume_ignores_obsolete_surface_delivery_rows() -> Result<(), SdkError> {
    let root = root("surface-outbound-isolation");
    let mut account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    account.client.account_db()?.persist_actor_state(
        "surface/transport/00000000000000000001",
        &serde_json::json!({"corrupt":true}),
    )?;
    account
        .client
        .account_db()?
        .persist_actor_state("surface/forward_job/corrupt", &serde_json::json!({"corrupt":true}))?;
    // Obsolete surface-specific queues are never decoded or scheduled.
    assert_eq!(super::sync_driver::run(&mut account).await?, 0);
    assert!(account.take_live_engine().await.is_ok());
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn own_authorization_refresh_failure_has_a_distinct_error_code() -> Result<(), SdkError> {
    let root = root("proof-refresh-status");
    let mut account = account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    account.gateway_config.timeout = Duration::from_millis(20);
    account.gateway_config.quic_fallback_timeout = Duration::from_millis(20);
    account.client.record_owned_proof_published(now_unix_timestamp() - 3600)?;
    let error = account
        .ensure_gateway_live()
        .await
        .err()
        .ok_or_else(|| SdkError::LocalBus("expected refresh failure".into()))?;
    assert!(matches!(error, SdkError::OwnDeviceAuthorizationRefreshFailed(_)));
    assert_eq!(local_bus_error_code(&error), "OwnDeviceAuthorizationRefreshFailed");
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
mod contact_state;
mod group_legacy;

mod status_snapshot;

mod group_actor;
