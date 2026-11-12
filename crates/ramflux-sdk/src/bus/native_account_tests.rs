// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary account actor lifecycle without access to the primary credential provider.
use crate::custody::tests::{Root, TestVault, input, words};
#[cfg(unix)]
use crate::platform::listener::BusListener;
use crate::{LocalBusClient, LocalBusConfig, LocalBusFrame, custody::CreationCeremony};
use ramflux_protocol::custody::CustodyRefusal;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

pub(crate) mod local_first;
mod session_events;

#[tokio::test]
async fn admitted_account_disconnect_and_reconnect_publish_session_events() -> Result {
    session_events::disconnect_and_reconnect().await
}

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Stop(watch::Sender<bool>);
impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

fn node_profile(id: &str, gateway_addr: &str, seed: u8) -> crate::NodeProfile {
    node_profile_with_ca(id, gateway_addr, seed, "test CA")
}

fn node_profile_with_ca(
    id: &str,
    gateway_addr: &str,
    seed: u8,
    ca_cert_pem: &str,
) -> crate::NodeProfile {
    crate::NodeProfile {
        discovery_url: format!("https://{id}"),
        node_id: id.to_owned(),
        node_public_key: ramflux_protocol::encode_base64url([seed; 32]),
        pin_source: crate::NodePinSource::Operator,
        ca_cert_pem: ca_cert_pem.to_owned(),
        gateway: crate::NodeGateway {
            quic_addr: gateway_addr.to_owned(),
            tcp_addr: gateway_addr.to_owned(),
            server_name: id.to_owned(),
        },
        relay: crate::NodeRelay { quic_addr: "127.0.0.1:1".to_owned(), server_name: id.to_owned() },
        prekey_http_url: format!("https://{id}"),
        signaling_turn_addr: String::new(),
        protocol_versions: Vec::new(),
        client_capabilities: Vec::new(),
        discovered_at: 1,
        expires_at: u64::MAX,
        enabled: true,
        builtin: false,
        safety_warnings: std::collections::BTreeSet::new(),
    }
}

#[derive(Clone)]
pub(super) enum GatewayCause {
    BlackHole,
    NoCustody,
    PoolBusy,
    Refused(CustodyRefusal),
    DailyQuota(ramflux_protocol::custody::CapacityHint),
    Admission(CustodyRefusal, ramflux_protocol::custody::RetryHint),
    ShortExpiry,
}

pub(super) struct CauseGateway {
    pub(super) address: std::net::SocketAddr,
    pub(super) ca_pem: String,
    admission_entered: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CauseGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CauseGateway {
    pub(super) async fn start(root: &std::path::Path, cause: GatewayCause) -> Result<Self> {
        Self::start_held(root, cause, None).await
    }

    async fn start_held(
        root: &std::path::Path,
        cause: GatewayCause,
        hold: Option<Arc<tokio::sync::Semaphore>>,
    ) -> Result<Self> {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca_pem = certificate.cert.pem();
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: root.join("cause-ca.pem"),
            service_cert: root.join("cause-server.pem"),
            service_key: root.join("cause-server.key"),
        };
        std::fs::write(&tls.ca_cert, &ca_pem)?;
        std::fs::write(&tls.service_cert, &ca_pem)?;
        std::fs::write(&tls.service_key, certificate.signing_key.serialize_pem())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            ramflux_transport::tcp_gateway_server_config(&tls)?,
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let limiter = matches!(cause, GatewayCause::PoolBusy).then(|| {
            ramflux_node_core::CustodyIngressLimiter::with_pools(
                1,
                Some(1),
                1,
                Duration::from_secs(300),
            )
        });
        let pool_permit = limiter.as_ref().and_then(|pool| {
            pool.acquire("127.0.0.1".parse().ok()?, None, std::time::Instant::now()).ok()
        });
        let admission_entered = Arc::new(tokio::sync::Notify::new());
        let entered = admission_entered.clone();
        let task = tokio::spawn(async move {
            let _pool_permit = pool_permit;
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let cause = cause.clone();
                let limiter = limiter.clone();
                let hold = hold.clone();
                let entered = entered.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(socket).await else { return };
                    let _ = serve_cause(stream, cause, limiter, hold, entered).await;
                });
            }
        });
        Ok(Self { address, ca_pem, admission_entered, task })
    }
}

async fn serve_cause(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    cause: GatewayCause,
    limiter: Option<Arc<ramflux_node_core::CustodyIngressLimiter>>,
    hold: Option<Arc<tokio::sync::Semaphore>>,
    entered: Arc<tokio::sync::Notify>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let bytes = ramflux_transport::read_custody_tcp_frame(&mut stream).await?;
    if serde_json::from_slice::<ramflux_transport::GatewayQuicRequest>(&bytes).is_ok() {
        ramflux_transport::write_gateway_session_json(
            &mut stream,
            &ramflux_transport::GatewayQuicResponse { status: 200, body: serde_json::Value::Null },
        )
        .await?;
        return Ok(());
    }
    let _: ramflux_protocol::custody::CustodyClientFrame = serde_json::from_slice(&bytes)?;
    entered.notify_one();
    if let Some(hold) = hold {
        hold.acquire().await?.forget();
    }
    let capacity = if let GatewayCause::DailyQuota(hint) = &cause { Some(*hint) } else { None };
    let retry = if let GatewayCause::Admission(_, retry) = &cause { Some(*retry) } else { None };
    let code = match cause {
        GatewayCause::BlackHole => return std::future::pending().await,
        GatewayCause::NoCustody => CustodyRefusal::Unsupported,
        GatewayCause::PoolBusy => {
            let pool = limiter.ok_or("missing test pool")?;
            if pool.acquire("127.0.0.1".parse()?, None, std::time::Instant::now()).is_ok() {
                return Err("test custody pool was not saturated".into());
            }
            CustodyRefusal::Busy
        }
        GatewayCause::Refused(code) | GatewayCause::Admission(code, _) => code,
        GatewayCause::DailyQuota(_) => CustodyRefusal::Capacity,
        GatewayCause::ShortExpiry => {
            let valid_until = tokio::time::Instant::now() + Duration::from_millis(1);
            tokio::time::sleep_until(valid_until).await;
            debug_assert!(tokio::time::Instant::now() >= valid_until);
            CustodyRefusal::SessionExpired
        }
    };
    ramflux_transport::write_custody_tcp_frame(
        &mut stream,
        &serde_json::to_vec(&ramflux_protocol::custody::CustodyServerFrame::Refused {
            code,
            capacity,
            retry,
        })?,
    )
    .await?;
    Ok(())
}

async fn connect(path: &std::path::Path) -> Result<LocalBusClient> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match LocalBusClient::connect(path).await {
                Ok(bus) => return Ok::<_, crate::SdkError>(bus),
                Err(crate::SdkError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??)
}

async fn next_networking_event(
    socket: &std::path::Path,
    account_id: &str,
    since_seq: u64,
) -> Result<LocalBusFrame> {
    let mut events = connect(socket).await?;
    events
        .request(
            Some(account_id.to_owned()),
            "stream",
            "bus.subscribe",
            json!({"topics":["account.networking.changed"],"since_seq":since_seq}),
        )
        .await?;
    let mut batch = networking_batch(&mut events, 3).await?;
    assert_eq!(batch.first().ok_or("initial event")?.body["session"]["phase"], "connecting");
    let event = batch.pop().ok_or("settled event")?;
    assert_eq!(event.body["session"]["phase"], "backoff");
    Ok(event)
}

async fn networking_batch(events: &mut LocalBusClient, count: usize) -> Result<Vec<LocalBusFrame>> {
    let mut batch = Vec::new();
    for _ in 0..count {
        let event = tokio::time::timeout(Duration::from_secs(2), events.next_event()).await??;
        assert_eq!(event.method, "account.networking.changed");
        batch.push(event);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(150), events.next_event()).await.is_err(),
        "unexpected duplicate networking event"
    );
    Ok(batch)
}

async fn connect_creation(path: &std::path::Path) -> Result<crate::LocalBusCreationClient> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match crate::LocalBusCreationClient::connect(path).await {
                Ok(bus) => return Ok::<_, crate::SdkError>(bus),
                Err(crate::SdkError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??)
}

async fn connect_custody(path: &std::path::Path) -> Result<crate::custody::CustodyBusClient> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match crate::custody::CustodyBusClient::connect(path).await {
                Ok(bus) => return Ok::<_, crate::SdkError>(bus),
                Err(crate::SdkError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??)
}

#[cfg(unix)]
#[tokio::test]
async fn disconnected_peer_never_stops_the_daemon_accept_loop() -> Result {
    let root = Root::new()?;
    let socket = root.0.join("disconnected-peer.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let listener = crate::platform::listener::UnixBusListener::from_bound(listener, &socket);
    let peer = listener.owner()?;
    // Queue a closed peer before accept can query its credentials. On macOS this
    // makes peer_cred return NotConnected; Linux may retain the credentials.
    drop(std::os::unix::net::UnixStream::connect(&socket)?);
    let supervisor = super::supervisor::Supervisor::new(LocalBusConfig::new(&socket, &root.0))?;
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&socket).await?;
        let response = bus.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(response["account_details"], json!([]));
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = Box::pin(tokio::task::LocalSet::new().run_until(async {
        tokio::join!(super::connection::accept(listener, peer, supervisor, receiver), flow,)
    }))
    .await;
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn ordinary_native_unlock_lock_restart_needs_only_data_passphrase() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let mut ceremony = CreationCeremony::begin(&root.0, input("ordinary"), now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let born = ceremony.confirm_with_passphrase(
        &words(&phrase, positions)?,
        &vault,
        now,
        b"ordinary data passphrase",
    )?;
    let anchor = born.record().body.account_anchor.clone();
    drop(born);
    drop(vault);
    drop(phrase);
    let socket = root.0.join("ordinary.sock");
    // Restart with creation disabled and no test provider, node, legacy manifest or seeds.
    for passphrase in ["ordinary data passphrase", "rotated data passphrase"] {
        let (stop, receiver) = watch::channel(false);
        let flow = async {
            let _stop = Stop(stop);
            let mut bus = connect(&socket).await?;
            let listed = bus.request(None, "account", "account.list", json!({})).await?;
            assert_eq!(listed["account_details"][0]["state"], "locked");
            assert_eq!(listed["account_details"][0]["networking"], "networking_pending");
            let wrong = bus
                .request_frame_response(LocalBusFrame::request(
                    "wrong",
                    Some("ordinary".into()),
                    "account",
                    "account.unlock",
                    json!({"passphrase":"wrong data passphrase"}),
                ))
                .await?;
            assert!(wrong.error.is_some());
            let unlocked = bus
                .request(
                    Some("ordinary".into()),
                    "account",
                    "account.unlock",
                    json!({"passphrase":passphrase}),
                )
                .await?;
            assert_eq!(unlocked["state"], "unlocked");
            assert_eq!(unlocked["networking"], "networking_pending");
            assert_eq!(unlocked["display_name"], "Example Human");
            let status = bus
                .request(Some("ordinary".into()), "account", "account.status", json!({}))
                .await?;
            assert_eq!(status["principal_commitment"], anchor);
            assert_eq!(status["networking"], "networking_pending");
            assert_eq!(status["state"], "unlocked");
            let directory = bus
                .request(Some("ordinary".into()), "identity", "identity.directory", json!({}))
                .await?;
            assert_eq!(directory["identities"][0]["contact_identity_commitment"], anchor);
            assert_eq!(directory["identities"][0]["display_name"], "Example Human");
            let listed = bus.request(None, "account", "account.list", json!({})).await?;
            assert_eq!(listed["account_details"][0]["state"], "unlocked");
            assert_eq!(listed["accounts"], json!(["ordinary"]));
            bus.request(
                Some("ordinary".into()),
                "account",
                "account.passphrase.rotate",
                json!({"old_passphrase":passphrase,"new_passphrase":"rotated data passphrase"}),
            )
            .await?;
            bus.request(Some("ordinary".into()), "account", "account.lock", json!({})).await?;
            let listed = bus.request(None, "account", "account.list", json!({})).await?;
            assert_eq!(listed["account_details"][0]["state"], "locked");
            assert_eq!(listed["accounts"], json!([]));
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (server, flow) = tokio::join!(
            crate::serve_local_bus_until(LocalBusConfig::new(&socket, &root.0), receiver),
            flow
        );
        server?;
        flow?;
    }
    assert!(!root.0.join("local_bus_accounts/ordinary.json").exists());
    Ok(())
}

#[tokio::test]
async fn native_status_reads_persisted_revocation_while_the_actor_is_still_unlocked() -> Result {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let mut ceremony = CreationCeremony::begin(&root.0, input("revoked-status"), now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    let born =
        ceremony.confirm_with_passphrase(&words(&phrase, positions)?, &vault, now, b"data")?;
    let primary = vault.primary_for_public_key(
        &born.record().body.master_certificate.body.self_signing_public_key,
    )?;
    let revoked = primary.revoke_device(born.verified(), "primary", now)?;
    let socket = root.0.join("revoked.sock");
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&socket).await?;
        bus.request(
            Some("revoked-status".into()),
            "account",
            "account.unlock",
            json!({"passphrase":"data"}),
        )
        .await?;
        let before = bus
            .request(Some("revoked-status".into()), "account", "account.status", json!({}))
            .await?;
        assert_eq!(before["local_device_authorized"], true);
        crate::custody::accept_publication(
            &root.0,
            "revoked-status",
            &ramflux_protocol::custody::CustodyAuthority {
                publication: ramflux_protocol::custody::Publication {
                    record: revoked,
                    compacted_ids: None,
                },
                custodian_publication: None,
            },
            now,
        )?;
        let after = bus
            .request(Some("revoked-status".into()), "account", "account.status", json!({}))
            .await?;
        assert_eq!(after["state"], "unlocked");
        assert_eq!(after["local_device_authorized"], false);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&socket, &root.0), receiver),
        flow
    );
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn ordinary_creation_confirms_into_unlocked_actor_and_cancels_failed_attempts() -> Result {
    use crate::{LocalBusCreatedAccountState, LocalBusCreationClient, custody::CreationState};
    use std::sync::Arc;
    use zeroize::Zeroizing;
    let root = Root::new()?;
    let socket = root.0.join("create.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);

    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut ordinary = connect(&socket).await?;
        let mut ceremony = LocalBusCreationClient::connect(&socket).await?;
        let pending =
            ceremony.begin("New Ordinary Human", ramflux_protocol::PrincipalKind::Human).await?;
        assert!(pending.ceremony_id.starts_with("ceremony-"));
        assert!((1..=300_000).contains(&pending.expires_in_ms));
        let phrase = ceremony.show_once().await?;
        let challenge = ceremony.hidden_challenge().await?;
        let answers = words(&phrase, challenge)?;
        drop(phrase);
        // Ceremonies belong to their connection, never to another same-user client.
        let mut other = LocalBusCreationClient::connect(&socket).await?;
        assert!(other.hidden_challenge().await.is_err());
        let account =
            ceremony.confirm(&answers, &Zeroizing::new("creation data secret".into())).await?;
        assert_eq!(account.state, LocalBusCreatedAccountState::Unlocked);
        assert_eq!(account.networking, CreationState::NetworkingPending);
        assert_eq!(account.display_name, "New Ordinary Human");
        ceremony.cancel().await?;
        local_first::wait_for_reason(&socket, &account.account_id, "no_node_selected").await?;
        let status = ordinary
            .request(Some(account.account_id.clone()), "account", "account.status", json!({}))
            .await?;
        assert_eq!(status["state"], "unlocked");
        assert_eq!(status["networking"], "networking_pending");
        assert_eq!(status["networking_reason"]["kind"], "no_node_selected");
        let listed = ordinary.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["account_details"][0]["networking_reason"]["kind"], "no_node_selected");
        let account_id = account.account_id.clone();
        ordinary.request(Some(account_id.clone()), "account", "account.lock", json!({})).await?;
        ordinary
            .request(
                Some(account_id.clone()),
                "account",
                "account.unlock",
                json!({"passphrase":"creation data secret"}),
            )
            .await?;
        ordinary
            .request(
                Some(account_id),
                "stream",
                "bus.subscribe",
                json!({"topics":["account.networking.changed"],"since_seq":0}),
            )
            .await?;
        let mut replay = networking_batch(&mut ordinary, 5).await?;
        assert_eq!(replay[0].body["session"]["phase"], "connecting");
        assert!(replay[0].body["networking_reason"].is_null());
        assert_eq!(replay[3].body["session"]["phase"], "connecting");
        let networking = replay.pop().ok_or("settled networking event")?;
        assert_eq!(networking.body["state"], "networking_pending");
        assert_eq!(networking.body["networking_reason"]["kind"], "no_node_selected");
        assert_eq!(networking.body["session"]["phase"], "backoff");
        ceremony.begin("Failed Human", ramflux_protocol::PrincipalKind::Human).await?;
        drop(ceremony.show_once().await?);
        ceremony.hidden_challenge().await?;
        let wrong = std::array::from_fn(|_| Zeroizing::new("invalid".into()));
        assert!(matches!(
            ceremony.confirm(&wrong, &Zeroizing::new("discard secret".into())).await,
            Err(crate::SdkError::CustodyConfirmationFailed)
        ));
        ceremony.cancel().await?;
        ceremony.cancel().await?;
        let listed = ordinary.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["account_details"].as_array().ok_or("accounts")?.len(), 1);
        assert!(matches!(
            ceremony
                .begin("AI without custodian", ramflux_protocol::PrincipalKind::HeadlessAi)
                .await,
            Err(crate::SdkError::CustodySetupInvalid)
        ));
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn networking_events_cover_change_live_and_restart_without_duplicates() -> Result {
    use crate::LocalBusCreationClient;
    use zeroize::Zeroizing;

    let root = Root::new()?;
    let socket = root.0.join("networking-events.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let phase_one = async {
        let _stop = Stop(stop);
        let mut ordinary = connect(&socket).await?;
        let mut ceremony = LocalBusCreationClient::connect(&socket).await?;
        ceremony.begin("Event Human", ramflux_protocol::PrincipalKind::Human).await?;
        let phrase = ceremony.show_once().await?;
        let challenge = ceremony.hidden_challenge().await?;
        let answers = words(&phrase, challenge)?;
        drop(phrase);
        let account =
            ceremony.confirm(&answers, &Zeroizing::new("event data secret".into())).await?;
        let id = account.account_id;

        let first = next_networking_event(&socket, &id, 0).await?;
        assert_eq!(first.body["networking_reason"]["kind"], "no_node_selected");
        let first_seq = first.seq.ok_or("missing first networking sequence")?;

        let profile = node_profile("changed.example", "invalid node address", 9);
        let mut nodes = crate::node::NodeStore::default();
        nodes.profiles.insert(profile.node_id.clone(), profile.clone());
        nodes.default_node_id = Some(profile.node_id);
        nodes.save(&root.0)?;
        ordinary.request(Some(id.clone()), "account", "account.lock", json!({})).await?;
        ordinary
            .request(
                Some(id.clone()),
                "account",
                "account.unlock",
                json!({"passphrase":"event data secret"}),
            )
            .await?;
        let changed = next_networking_event(&socket, &id, first_seq).await?;
        assert_eq!(changed.body["networking_reason"]["kind"], "node_unreachable");
        let changed_seq = changed.seq.ok_or("missing changed networking sequence")?;

        ordinary.request(Some(id.clone()), "account", "account.lock", json!({})).await?;
        let now = crate::custody::network_now()?;
        let mut native = crate::custody::load_account(&root.0, &id, now)?;
        native.mark_live_for_test(&root.0)?;
        ordinary
            .request(
                Some(id.clone()),
                "account",
                "account.unlock",
                json!({"passphrase":"event data secret"}),
            )
            .await?;
        let live = next_networking_event(&socket, &id, changed_seq).await?;
        assert_eq!(live.body["state"], "live");
        assert!(live.body["networking_reason"].is_null());
        let live_seq = live.seq.ok_or("missing live networking sequence")?;
        let status =
            ordinary.request(Some(id.clone()), "account", "account.status", json!({})).await?;
        assert_eq!(status["networking"], "live");
        assert!(status["networking_reason"].is_null());
        ordinary.request(Some(id.clone()), "account", "account.lock", json!({})).await?;
        Ok::<_, Box<dyn std::error::Error>>((id, live_seq))
    };
    let (server, phase_one) =
        tokio::join!(crate::serve_local_bus_until(config, receiver), phase_one);
    server?;
    let (id, live_seq) = phase_one?;

    let (stop, receiver) = watch::channel(false);
    let phase_two = async {
        let _stop = Stop(stop);
        let mut ordinary = connect(&socket).await?;
        ordinary
            .request(
                Some(id.clone()),
                "account",
                "account.unlock",
                json!({"passphrase":"event data secret"}),
            )
            .await?;
        let mut events = connect(&socket).await?;
        events
            .request(
                Some(id.clone()),
                "stream",
                "bus.subscribe",
                json!({"topics":["account.networking.changed"],"since_seq":live_seq}),
            )
            .await?;
        assert_restarted_networking(&mut events).await?;
        ordinary.request(Some(id), "account", "account.lock", json!({})).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, phase_two) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&socket, &root.0), receiver),
        phase_two,
    );
    server?;
    phase_two?;
    Ok(())
}

#[tokio::test]
async fn per_account_home_node_does_not_change_daemon_default() -> Result {
    use crate::{LocalBusCreationClient, custody::CreationState};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    let root = Root::new()?;
    let mut nodes = crate::node::NodeStore::default();
    let default = node_profile("default.example", "127.0.0.1:1", 4);
    let selected = node_profile("selected.example", "invalid node address", 5);
    nodes.profiles.insert(default.node_id.clone(), default.clone());
    nodes.profiles.insert(selected.node_id.clone(), selected.clone());
    nodes.default_node_id = Some(default.node_id.clone());
    nodes.save(&root.0)?;

    let socket = root.0.join("per-account-node.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(Arc::new(TestVault::default()));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut ordinary = connect(&socket).await?;
        let mut ceremony = LocalBusCreationClient::connect(&socket).await?;
        ceremony
            .begin_with_node(
                "Selected Home Node",
                ramflux_protocol::PrincipalKind::Human,
                &selected.node_id,
            )
            .await?;
        let phrase = ceremony.show_once().await?;
        let challenge = ceremony.hidden_challenge().await?;
        let answers = words(&phrase, challenge)?;
        drop(phrase);
        let account =
            ceremony.confirm(&answers, &Zeroizing::new("selected node data secret".into())).await?;
        assert_eq!(account.networking, CreationState::NetworkingPending);
        local_first::wait_for_reason(&socket, &account.account_id, "node_unreachable").await?;
        let status = ordinary
            .request(Some(account.account_id), "account", "account.status", json!({}))
            .await?;
        assert_eq!(status["node_id"], selected.node_id);
        assert_eq!(status["networking_reason"]["kind"], "node_unreachable");
        let saved = crate::node::NodeStore::load(&root.0, &[])?;
        assert_eq!(saved.default_node_id.as_deref(), Some(default.node_id.as_str()));
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow?;
    Ok(())
}

async fn status_from_gateway_cause(cause: GatewayCause) -> Result<serde_json::Value> {
    use crate::LocalBusCreationClient;
    use zeroize::Zeroizing;

    // Bound both the silent endpoint and the endlessly Busy pool below the event wait.
    // Preserve exhausted-budget mapping (node_busy with the 16 s ceiling for Busy,
    // node_unreachable for silence) without waiting out the production 90 s budget.
    let test_retry_budget = matches!(cause, GatewayCause::PoolBusy | GatewayCause::BlackHole)
        .then(|| Duration::from_secs(4));
    let expected_kind = match &cause {
        GatewayCause::BlackHole => "node_unreachable",
        GatewayCause::NoCustody => "node_custody_unavailable",
        GatewayCause::ShortExpiry => "custody_expired",
        GatewayCause::Refused(_) => "registration_refused",
        GatewayCause::PoolBusy | GatewayCause::DailyQuota(_) | GatewayCause::Admission(_, _) => {
            "node_busy"
        }
    };
    let root = Root::new()?;
    let gateway = CauseGateway::start(&root.0, cause).await?;
    let profile =
        node_profile_with_ca("localhost", &gateway.address.to_string(), 8, &gateway.ca_pem);
    let mut nodes = crate::node::NodeStore::default();
    nodes.profiles.insert(profile.node_id.clone(), profile.clone());
    nodes.save(&root.0)?;
    let socket = root.0.join("typed-gateway-cause.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(Arc::new(TestVault::default()));
    config.test_retry_budget = test_retry_budget;
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut ordinary = connect(&socket).await?;
        let mut ceremony = LocalBusCreationClient::connect(&socket).await?;
        ceremony
            .begin_with_node(
                "Typed Gateway Cause",
                ramflux_protocol::PrincipalKind::Human,
                &profile.node_id,
            )
            .await?;
        let phrase = ceremony.show_once().await?;
        let challenge = ceremony.hidden_challenge().await?;
        let answers = words(&phrase, challenge)?;
        drop(phrase);
        let account =
            ceremony.confirm(&answers, &Zeroizing::new("gateway cause secret".into())).await?;
        local_first::wait_for_reason(&socket, &account.account_id, expected_kind).await?;
        let status = ordinary
            .request(Some(account.account_id), "account", "account.status", json!({}))
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(status)
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    let reason = flow?;
    drop(gateway);
    Ok(reason)
}

async fn reason_from_gateway_cause(cause: GatewayCause) -> Result<serde_json::Value> {
    Ok(status_from_gateway_cause(cause).await?["networking_reason"].clone())
}

#[tokio::test]
async fn custody_capacity_hint_round_trips_through_tls_and_account_status() -> Result {
    use ramflux_protocol::custody::{CapacityHint, CapacityScope};
    for scope in [CapacityScope::PrefixDaily, CapacityScope::GlobalDaily] {
        let capacity =
            CapacityHint { scope, resets_at_unix: crate::custody::network_now()? + 3600 };
        let status = status_from_gateway_cause(GatewayCause::DailyQuota(capacity)).await?;
        assert_eq!(status["networking_reason"]["kind"], "node_busy");
        assert_eq!(status["networking_reason"]["capacity"], serde_json::to_value(capacity)?);
        let message = status["networking_hint"].as_str().ok_or("hint text missing")?;
        assert!(message.contains(if scope == CapacityScope::PrefixDaily {
            "for your network"
        } else {
            "for the whole network"
        }));
        assert_eq!(message, crate::custody::capacity_hint::message(&capacity));
        assert!(
            status["networking_reason"]["retry_after_ms"]
                .as_u64()
                .is_some_and(|delay| delay >= 300_000)
        );
    }
    Ok(())
}

#[tokio::test]
async fn custody_out_of_range_and_past_resets_show_only_the_remaining_floor() -> Result {
    use ramflux_protocol::custody::{CapacityHint, CapacityScope};
    let now = crate::custody::network_now()?;
    for reset in [ramflux_protocol::MAX_SAFE_JSON_INTEGER, now + 3 * 86_400, now.saturating_sub(1)]
    {
        let capacity = CapacityHint { scope: CapacityScope::PrefixDaily, resets_at_unix: reset };
        let status = status_from_gateway_cause(GatewayCause::DailyQuota(capacity)).await?;
        assert_eq!(
            status["networking_reason"]["kind"], "node_busy",
            "reset={reset} status={status}"
        );
        assert!(status["networking_reason"]["capacity"].is_null(), "{status}");
        assert!(status["networking_hint"].is_null(), "an unusable reset must not be displayed");
        assert!(
            status["networking_reason"]["retry_after_ms"]
                .as_u64()
                .is_some_and(|delay| delay > 0 && delay <= 300_000),
            "{status}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn silent_tcp_gateway_reports_node_unreachable() -> Result {
    let reason = reason_from_gateway_cause(GatewayCause::BlackHole).await?;
    assert_eq!(reason["kind"], "node_unreachable");
    assert_eq!(reason["retry_after_ms"], crate::node::NODE_RETRY_AFTER_MS);
    Ok(())
}

#[tokio::test]
async fn gateway_without_custody_configuration_reports_unavailable() -> Result {
    let reason = reason_from_gateway_cause(GatewayCause::NoCustody).await?;
    assert_eq!(reason, json!({"kind":"node_custody_unavailable"}));
    Ok(())
}

#[tokio::test]
async fn saturated_custody_pool_reports_node_busy() -> Result {
    let reason = reason_from_gateway_cause(GatewayCause::PoolBusy).await?;
    assert_eq!(reason, json!({"kind":"node_busy","retry_after_ms":16000}));
    Ok(())
}

#[tokio::test]
async fn gateway_registration_refusal_preserves_typed_code() -> Result {
    let reason =
        reason_from_gateway_cause(GatewayCause::Refused(CustodyRefusal::PrincipalIdTaken)).await?;
    assert_eq!(reason, json!({"kind":"registration_refused","code":"principal_id_taken"}));
    Ok(())
}

#[tokio::test]
async fn short_gateway_session_expiry_reports_custody_expired() -> Result {
    let reason = reason_from_gateway_cause(GatewayCause::ShortExpiry).await?;
    assert_eq!(reason, json!({"kind":"custody_expired"}));
    Ok(())
}

#[test]
fn capacity_refusal_uses_the_node_busy_reason() {
    let error = crate::SdkError::CustodyNetwork(CustodyRefusal::Capacity);
    let body = super::io::local_bus_error_body(&error);
    assert_eq!(body.retry_after_ms, Some(300_000));
    assert_eq!(body.code, "ValidationFailed");
    assert_eq!(
        super::native_account::networking_reason(&crate::SdkError::CustodyNetwork(
            CustodyRefusal::Capacity,
        )),
        Some(crate::AccountNetworkingReason::NodeBusy { retry_after_ms: 300_000, capacity: None })
    );
}

fn create_refusal_account(
    root: &std::path::Path,
    vault: &dyn crate::custody::PrimaryVault,
    now: u64,
    id: &str,
    kind: ramflux_protocol::PrincipalKind,
    custodian: Option<&str>,
) -> Result {
    let mut input = input(id);
    input.principal_kind = kind;
    input.custodian_account_id = custodian.map(str::to_owned);
    let mut ceremony = CreationCeremony::begin(root, input, now)?;
    let phrase = ceremony.show_once()?;
    let positions = ceremony.hidden_challenge()?;
    ceremony.confirm_with_passphrase(
        &words(&phrase, positions)?,
        vault,
        now,
        format!("{id}-secret").as_bytes(),
    )?;
    Ok(())
}

async fn refuse_untrusted_custodians(socket: &std::path::Path) -> Result {
    let mut locked = connect_creation(socket)
        .await
        .map_err(|error| format!("locked creation connect: {error}"))?;
    assert!(locked.begin_headless("Locked owner", "owner").await.is_err());
    assert!(locked.begin_headless_with_envelope("No owner envelope", "owner", None).await.is_err());
    Ok(())
}

async fn refuse_open_custodians(root: &std::path::Path, socket: &std::path::Path) -> Result {
    let mut bus = connect(socket).await.map_err(|error| format!("unlock connect: {error}"))?;
    bus.request(
        Some("owner".into()),
        "stream",
        "subscription.open",
        json!({"topics":[],"attended_frontend":true}),
    )
    .await?;
    let locked_export = bus
        .request_frame_response(LocalBusFrame::request(
            "locked-export",
            Some("owner".into()),
            "account",
            "account.export_agent_credentials",
            json!({"account":"agent","path":root.join("locked.bundle")}),
        ))
        .await?;
    assert!(locked_export.error.is_some());
    for id in ["owner", "other", "pending", "agent"] {
        bus.request(
            Some(id.into()),
            "account",
            "account.unlock",
            json!({"passphrase":format!("{id}-secret")}),
        )
        .await?;
    }
    let mut creation = connect_creation(socket)
        .await
        .map_err(|error| format!("untrusted owner creation connect: {error}"))?;
    assert!(
        creation
            .begin_headless_with_envelope("Non-owner session", "owner", Some("other"))
            .await
            .is_err()
    );
    assert!(creation.begin_headless("Pending owner", "pending").await.is_err());
    assert!(creation.begin_headless("Non-human owner", "agent").await.is_err());
    refuse_untrusted_exports(root, &mut bus).await?;
    let mut legacy = connect_custody(socket)
        .await
        .map_err(|error| format!("legacy custody connect: {error}"))?;
    let mut legacy_input = input("legacy-headless");
    legacy_input.principal_kind = ramflux_protocol::PrincipalKind::HeadlessAi;
    legacy_input.custodian_account_id = Some("owner".into());
    assert!(matches!(legacy.begin(&legacy_input).await, Err(crate::SdkError::CustodySetupInvalid)));
    Ok(())
}

async fn refuse_untrusted_exports(root: &std::path::Path, bus: &mut LocalBusClient) -> Result {
    for owner in ["other", "pending", "agent"] {
        bus.request(
            Some(owner.into()),
            "stream",
            "subscription.open",
            json!({"topics":[],"attended_frontend":true}),
        )
        .await?;
        let refused = bus
            .request_frame_response(LocalBusFrame::request(
                format!("{owner}-export"),
                Some(owner.into()),
                "account",
                "account.export_agent_credentials",
                json!({"account":"agent","path":root.join(format!("{owner}.bundle"))}),
            ))
            .await?;
        assert!(refused.error.is_some(), "export unexpectedly accepted for {owner}");
    }
    Ok(())
}

fn accept_refusal_server(
    result: std::result::Result<(), crate::SdkError>,
    context: &str,
) -> Result {
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(format!("{context}: {error}").into()),
    }
}

async fn refuse_wrong_daemon_creation(root: &Root, socket: &std::path::Path) -> Result {
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        drop(connect(socket).await.map_err(|error| format!("wrong-daemon probe: {error}"))?);
        let mut ceremony = connect_creation(socket)
            .await
            .map_err(|error| format!("wrong-daemon creation connect: {error}"))?;
        assert!(ceremony.begin_headless("Wrong daemon", "owner").await.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(socket, &root.0), receiver),
        flow
    );
    accept_refusal_server(server, "wrong-daemon creation server failed")?;
    flow.map_err(|error| format!("wrong daemon creation flow failed: {error}"))?;
    Ok(())
}

async fn refuse_wrong_daemon_export(root: &Root, socket: &std::path::Path) -> Result {
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(socket).await?;
        bus.request(
            Some("owner".into()),
            "stream",
            "subscription.open",
            json!({"topics":[],"attended_frontend":true}),
        )
        .await?;
        let refused = bus
            .request_frame_response(LocalBusFrame::request(
                "wrong-daemon-export",
                Some("owner".into()),
                "account",
                "account.export_agent_credentials",
                json!({"account":"agent","path":root.0.join("agent.bundle")}),
            ))
            .await?;
        assert!(refused.error.is_some());
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(socket, &root.0), receiver),
        flow
    );
    accept_refusal_server(server, "wrong-daemon export server failed")?;
    flow.map_err(|error| format!("wrong daemon export flow failed: {error}"))?;
    Ok(())
}

#[tokio::test]
async fn headless_creation_refuses_every_untrusted_custodian_entry() -> Result {
    use std::sync::Arc;
    let root = Root::new()?;
    let vault: Arc<dyn crate::custody::PrimaryVault + Send + Sync> = Arc::new(TestVault::default());
    let now = crate::custody::network_now()?;
    for (id, kind, custodian, live) in [
        ("owner", ramflux_protocol::PrincipalKind::Human, None, true),
        ("other", ramflux_protocol::PrincipalKind::Human, None, true),
        ("pending", ramflux_protocol::PrincipalKind::Human, None, false),
        ("agent", ramflux_protocol::PrincipalKind::HeadlessAi, Some("owner"), true),
    ] {
        create_refusal_account(&root.0, vault.as_ref(), now, id, kind, custodian)
            .map_err(|error| format!("create {id}: {error}"))?;
        if live {
            crate::custody::tests::mark_live(&root.0, id, now)
                .map_err(|error| format!("mark {id} live: {error}"))?;
        }
    }
    let socket = root.0.join("headless-refusals.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(Arc::clone(&vault));
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        refuse_untrusted_custodians(&socket).await
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    accept_refusal_server(server, "headless refusal server failed")?;
    flow.map_err(|error| format!("headless refusal flow failed: {error}"))?;
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(vault);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        refuse_open_custodians(&root.0, &socket).await
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    accept_refusal_server(server, "open custodian refusal server failed")?;
    flow.map_err(|error| format!("open custodian refusal flow failed: {error}"))?;
    let wrong_root = Root::new()?;
    let wrong_socket = wrong_root.0.join("wrong-daemon.sock");
    refuse_wrong_daemon_creation(&wrong_root, &wrong_socket).await?;
    refuse_wrong_daemon_export(&wrong_root, &wrong_socket).await
}

#[tokio::test]
async fn native_fenced_account_opens_data_actor_and_refuses_legacy_proof_after_restart() -> Result {
    let fixture = crate::client::native_test_support::Fixture::new("native-fenced-actor").await?;
    let id = fixture.client.account_db()?.local_account_id.clone();
    let mut native = fixture.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.profile.display_name = "Conflicting actor name".into();
    native.publication.record = primary.sign_record(body)?;
    assert!(
        fixture
            .client
            .observe_custody_manifest(
                &native,
                &fixture.manifest.principal_commitment,
                crate::custody::network_now()?,
            )
            .is_err()
    );
    drop(fixture.client);
    let socket = fixture.root.0.join("fenced-actor.sock");
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&socket).await?;
        let listed = bus.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["account_details"][0]["authority_blocked"], true);
        let unlocked = bus
            .request(
                Some(id.clone()),
                "account",
                "account.unlock",
                json!({"passphrase":"native fixture data passphrase"}),
            )
            .await?;
        assert_eq!(unlocked["state"], "unlocked");
        assert_eq!(unlocked["networking"], "networking_pending");
        let status = bus.request(Some(id.clone()), "account", "account.status", json!({})).await?;
        assert_eq!(status["authority_blocked"], true);
        let proof = bus
            .request_frame_response(LocalBusFrame::request(
                "fenced-proof",
                Some(id.clone()),
                "account",
                "device.authorize",
                json!({}),
            ))
            .await?;
        assert_eq!(proof.error.ok_or("legacy proof was granted")?.code, "NetworkingPending");
        bus.request(Some(id.clone()), "account", "account.lock", json!({})).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&socket, &fixture.root.0), receiver),
        flow,
    );
    server?;
    flow?;
    Ok(())
}

#[tokio::test]
async fn custody_agent_export_uses_recorded_owner_while_agent_is_active() -> Result {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let vault: Arc<dyn crate::custody::PrimaryVault + Send + Sync> = Arc::new(TestVault::default());
    for (id, kind, owner) in [
        ("owner", ramflux_protocol::PrincipalKind::Human, None),
        ("agent", ramflux_protocol::PrincipalKind::HeadlessAi, Some("owner")),
    ] {
        create_refusal_account(&root.0, vault.as_ref(), now, id, kind, owner)?;
        crate::custody::tests::mark_live(&root.0, id, now)?;
    }
    let socket = root.0.join("agent-export.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(vault);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&socket).await?;
        for id in ["owner", "agent"] {
            bus.request(
                Some(id.into()),
                "account",
                "account.unlock",
                json!({"passphrase":format!("{id}-secret")}),
            )
            .await?;
        }
        bus.request(Some("agent".into()), "account", "account.switch", json!({})).await?;
        let listed = bus.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["active_account_id"], "agent");
        let agent = listed["account_details"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == "agent"))
            .ok_or("agent record missing")?;
        let owner = agent["custodian_account_id"].as_str().ok_or("custodian record missing")?;
        bus.request(
            Some(owner.into()),
            "stream",
            "subscription.open",
            json!({"topics":[],"attended_frontend":true}),
        )
        .await?;
        let path = root.0.join("export.bundle");
        let result = bus
            .request(
                Some(owner.into()),
                "account",
                "account.export_agent_credentials",
                json!({"account":"agent","path":path}),
            )
            .await?;
        assert_eq!(result["exported"], true);
        let bundle: crate::custody::AgentProvisioningBundle =
            serde_json::from_slice(&std::fs::read(path)?)?;
        assert_eq!(bundle.account_id, "agent");
        assert_eq!(bundle.data_passphrase, "agent-secret");
        let listed = bus.request(None, "account", "account.list", json!({})).await?;
        assert_eq!(listed["active_account_id"], "agent", "export must not switch accounts");
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    accept_refusal_server(server, "agent export server failed")?;
    flow
}

// Mutation: serialize native.networking_reason() instead of networking_view(now) in the event writer.
#[tokio::test(start_paused = true)]
async fn custody_networking_event_status_and_list_share_the_same_derived_view() -> Result {
    use crate::client::native_test_support::Fixture;
    let fixture = Fixture::new("capacity-view").await?;
    let now = crate::custody::network_now()?;
    let config = fixture.config.custody.as_ref().ok_or("custody config")?;
    let mut native = crate::custody::load_account(&fixture.root.0, "capacity-view", now)?;
    native.bind_capacity_node(&fixture.root.0, &config.node_id, &config.node_public_key, now)?;
    native.set_networking_reason(
        &fixture.root.0,
        Some(crate::AccountNetworkingReason::NodeBusy {
            retry_after_ms: 300_000,
            capacity: Some(ramflux_protocol::custody::CapacityHint {
                scope: ramflux_protocol::custody::CapacityScope::PrefixDaily,
                resets_at_unix: now + 3600,
            }),
        }),
    )?;
    let mut account = super::state::LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    for captured in [now + 100, now + 3600] {
        super::native_account::record_networking_at(&mut account, None, captured)?;
        let event = account
            .client
            .account_db()?
            .load_actor_state::<serde_json::Value>("account/networking")?
            .ok_or("networking event missing")?;
        let status = super::native_account::status_at(&account, "capacity-view", captured)?;
        let listed = crate::custody::list_accounts(&fixture.root.0, captured)?;
        assert_eq!(event["networking_reason"], status["networking_reason"]);
        assert_eq!(event["networking_reason"], listed[0]["networking_reason"]);
        if captured == now + 100 {
            assert_eq!(event["networking_reason"]["remaining_ms"], 3_500_000);
            assert_eq!(event["networking_reason"]["retry_after_ms"], 3_500_000);
        } else {
            assert!(event["networking_reason"].is_null());
        }
    }
    // Error ingestion must use the same captured wall time as its derived event.
    let captured = now + 7200;
    let hint = ramflux_protocol::custody::CapacityHint {
        scope: ramflux_protocol::custody::CapacityScope::PrefixDaily,
        resets_at_unix: captured - 1,
    };
    super::native_account::record_networking_at(
        &mut account,
        Some(&crate::SdkError::CustodyCapacity { capacity: hint }),
        captured,
    )?;
    let event = account
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>("account/networking")?
        .ok_or("networking event missing")?;
    let status = super::native_account::status_at(&account, "capacity-view", captured)?;
    assert_eq!(event["networking_reason"], status["networking_reason"]);
    assert_eq!(event["networking_reason"]["remaining_ms"], 300_000);
    assert!(event["networking_reason"].get("capacity").is_none());
    assert!(event["networking_reason"].get("resets_at").is_none());
    Ok(())
}

#[tokio::test]
async fn networking_view_and_bus_error_report_server_retry_after() -> Result {
    use ramflux_protocol::custody::{RetryHint, RetryScope};
    for code in [CustodyRefusal::Busy, CustodyRefusal::Capacity] {
        let retry = RetryHint::new(RetryScope::NodeCapacity, 120_000);
        let started = std::time::Instant::now();
        let status =
            status_from_gateway_cause(GatewayCause::Admission(code.clone(), retry)).await?;
        assert_eq!(status["networking_reason"]["kind"], "node_busy");
        let remaining =
            status["networking_reason"]["retry_after_ms"].as_u64().ok_or("missing server wait")?;
        assert!(remaining <= 120_000);
        assert!(
            remaining.saturating_add(u64::try_from(started.elapsed().as_millis())?) >= 120_000,
            "status must count down from the server hint: remaining={remaining}"
        );
        let hinted = crate::SdkError::CustodyAdmission { code: code.clone(), retry };
        assert_eq!(
            super::native_account::networking_reason(&hinted),
            Some(crate::AccountNetworkingReason::NodeBusy {
                retry_after_ms: 120_000,
                capacity: None
            })
        );
        let body = super::io::local_bus_error_body(&hinted);
        assert_eq!(body.retry_after_ms, Some(120_000));
        assert_eq!(serde_json::to_value(&body)?["details"]["retry"], serde_json::to_value(retry)?);
        assert_eq!(
            body.code,
            super::io::local_bus_error_code(&crate::SdkError::CustodyNetwork(code))
        );
    }
    Ok(())
}

async fn assert_restarted_networking(events: &mut LocalBusClient) -> Result {
    let restarted = networking_batch(events, 2).await?;
    assert_eq!(restarted[0].body["session"]["phase"], "connecting");
    assert_eq!(restarted[1].body["session"]["phase"], "backoff");
    for event in &restarted {
        assert_eq!(event.body["state"], "live");
        assert!(event.body["networking_reason"].is_null());
    }
    Ok(())
}
