// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary account actor lifecycle without access to the primary credential provider.
use crate::custody::tests::{Root, TestVault, input, words};
use crate::{LocalBusClient, LocalBusConfig, LocalBusFrame, custody::CreationCeremony};
use ramflux_protocol::custody::CustodyRefusal;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

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
enum GatewayCause {
    BlackHole,
    NoCustody,
    PoolBusy,
    Refused(CustodyRefusal),
    ShortExpiry,
}

struct CauseGateway {
    address: std::net::SocketAddr,
    ca_pem: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CauseGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CauseGateway {
    async fn start(root: &std::path::Path, cause: GatewayCause) -> Result<Self> {
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
            ramflux_node_core::CustodyIngressLimiter::with_pools(1, 1, 1, Duration::from_secs(300))
        });
        let held = limiter.as_ref().and_then(|pool| {
            pool.acquire("127.0.0.1".parse().ok()?, None, std::time::Instant::now())
        });
        let task = tokio::spawn(async move {
            let _held = held;
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let cause = cause.clone();
                let limiter = limiter.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(socket).await else { return };
                    let _ = serve_cause(stream, cause, limiter).await;
                });
            }
        });
        Ok(Self { address, ca_pem, task })
    }
}

async fn serve_cause(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    cause: GatewayCause,
    limiter: Option<Arc<ramflux_node_core::CustodyIngressLimiter>>,
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
    let code = match cause {
        GatewayCause::BlackHole => return std::future::pending().await,
        GatewayCause::NoCustody => CustodyRefusal::Unsupported,
        GatewayCause::PoolBusy => {
            let pool = limiter.ok_or("missing test pool")?;
            if pool.acquire("127.0.0.1".parse()?, None, std::time::Instant::now()).is_some() {
                return Err("test custody pool was not saturated".into());
            }
            CustodyRefusal::Busy
        }
        GatewayCause::Refused(code) => code,
        GatewayCause::ShortExpiry => {
            let valid_until = tokio::time::Instant::now() + Duration::from_millis(1);
            tokio::time::sleep_until(valid_until).await;
            debug_assert!(tokio::time::Instant::now() >= valid_until);
            CustodyRefusal::SessionExpired
        }
    };
    ramflux_transport::write_custody_tcp_frame(
        &mut stream,
        &serde_json::to_vec(&ramflux_protocol::custody::CustodyServerFrame::Refused { code })?,
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
    let event = tokio::time::timeout(Duration::from_secs(2), events.next_event()).await??;
    assert_eq!(event.method, "account.networking.changed");
    assert!(tokio::time::timeout(Duration::from_millis(150), events.next_event()).await.is_err());
    Ok(event)
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
        let networking =
            tokio::time::timeout(Duration::from_secs(2), ordinary.next_event()).await??;
        assert_eq!(networking.method, "account.networking.changed");
        assert_eq!(networking.body["state"], "networking_pending");
        assert_eq!(networking.body["networking_reason"]["kind"], "no_node_selected");
        assert!(
            tokio::time::timeout(Duration::from_millis(150), ordinary.next_event()).await.is_err()
        );
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
    flow?;
    server?;
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
        assert!(
            tokio::time::timeout(Duration::from_millis(200), events.next_event()).await.is_err()
        );
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

async fn reason_from_gateway_cause(cause: GatewayCause) -> Result<serde_json::Value> {
    use crate::LocalBusCreationClient;
    use zeroize::Zeroizing;

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
        let status = ordinary
            .request(Some(account.account_id), "account", "account.status", json!({}))
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(status["networking_reason"].clone())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    let reason = flow?;
    drop(gateway);
    Ok(reason)
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
    assert_eq!(
        super::native_account::networking_reason(&crate::SdkError::CustodyNetwork(
            CustodyRefusal::Capacity,
        )),
        Some(crate::AccountNetworkingReason::NodeBusy { retry_after_ms: 16_000 })
    );
}

#[tokio::test]
async fn headless_creation_refuses_every_untrusted_custodian_entry() -> Result {
    use crate::{LocalBusCreationClient, custody::CustodyBusClient};
    use std::sync::Arc;
    let root = Root::new()?;
    let vault = Arc::new(TestVault::default());
    let now = crate::custody::network_now()?;
    let create = |id: &str, kind: ramflux_protocol::PrincipalKind, custodian: Option<&str>| {
        let mut input = input(id);
        input.principal_kind = kind;
        input.custodian_account_id = custodian.map(str::to_owned);
        let mut ceremony = CreationCeremony::begin(&root.0, input, now)?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        ceremony.confirm_with_passphrase(
            &words(&phrase, positions)?,
            vault.as_ref(),
            now,
            format!("{id}-secret").as_bytes(),
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    create("owner", ramflux_protocol::PrincipalKind::Human, None)
        .map_err(|error| format!("create owner: {error}"))?;
    crate::custody::tests::mark_live(&root.0, "owner", now)
        .map_err(|error| format!("mark owner live: {error}"))?;
    create("other", ramflux_protocol::PrincipalKind::Human, None)
        .map_err(|error| format!("create other: {error}"))?;
    crate::custody::tests::mark_live(&root.0, "other", now)
        .map_err(|error| format!("mark other live: {error}"))?;
    create("pending", ramflux_protocol::PrincipalKind::Human, None)
        .map_err(|error| format!("create pending: {error}"))?;
    create("agent", ramflux_protocol::PrincipalKind::HeadlessAi, Some("owner"))
        .map_err(|error| format!("create agent: {error}"))?;
    crate::custody::tests::mark_live(&root.0, "agent", now)
        .map_err(|error| format!("mark agent live: {error}"))?;

    let socket = root.0.join("headless-refusals.sock");
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(vault);
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        drop(connect(&socket).await?);
        let mut locked = LocalBusCreationClient::connect(&socket).await?;
        assert!(locked.begin_headless("Locked owner", "owner").await.is_err());
        let mut missing = LocalBusCreationClient::connect(&socket).await?;
        assert!(
            missing.begin_headless_with_envelope("No owner envelope", "owner", None).await.is_err()
        );
        let mut locked_bus = connect(&socket).await?;
        locked_bus
            .request(
                Some("owner".into()),
                "stream",
                "subscription.open",
                json!({"topics":[],"attended_frontend":true}),
            )
            .await?;
        let locked_export = locked_bus
            .request_frame_response(LocalBusFrame::request(
                "locked-export",
                Some("owner".into()),
                "account",
                "account.export_agent_credentials",
                json!({"account":"agent","path":root.0.join("locked.bundle")}),
            ))
            .await?;
        assert!(locked_export.error.is_some());
        drop(locked_bus);
        let mut bus = connect(&socket).await?;
        for id in ["owner", "other", "pending", "agent"] {
            bus.request(
                Some(id.into()),
                "account",
                "account.unlock",
                json!({"passphrase":format!("{id}-secret")}),
            )
            .await?;
        }
        let mut non_owner = LocalBusCreationClient::connect(&socket).await?;
        assert!(
            non_owner
                .begin_headless_with_envelope("Non-owner session", "owner", Some("other"))
                .await
                .is_err()
        );
        let mut pending = LocalBusCreationClient::connect(&socket).await?;
        assert!(pending.begin_headless("Pending owner", "pending").await.is_err());
        let mut non_human = LocalBusCreationClient::connect(&socket).await?;
        assert!(non_human.begin_headless("Non-human owner", "agent").await.is_err());
        drop(bus);
        for owner in ["other", "pending", "agent"] {
            let mut export_bus = connect(&socket).await?;
            export_bus
                .request(
                    Some(owner.into()),
                    "stream",
                    "subscription.open",
                    json!({"topics":[],"attended_frontend":true}),
                )
                .await?;
            let refused = export_bus
                .request_frame_response(LocalBusFrame::request(
                    format!("{owner}-export"),
                    Some(owner.into()),
                    "account",
                    "account.export_agent_credentials",
                    json!({"account":"agent","path":root.0.join(format!("{owner}.bundle"))}),
                ))
                .await?;
            assert!(refused.error.is_some(), "export unexpectedly accepted for {owner}");
        }

        let mut legacy = CustodyBusClient::connect(&socket).await?;
        let mut legacy_input = input("legacy-headless");
        legacy_input.principal_kind = ramflux_protocol::PrincipalKind::HeadlessAi;
        legacy_input.custodian_account_id = Some("owner".into());
        assert!(matches!(
            legacy.begin(&legacy_input).await,
            Err(crate::SdkError::CustodySetupInvalid)
        ));
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server.map_err(|error| format!("headless refusal server failed: {error}"))?;
    flow.map_err(|error| format!("headless refusal flow failed: {error}"))?;

    let wrong_root = Root::new()?;
    let wrong_socket = wrong_root.0.join("wrong-daemon.sock");
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        drop(connect(&wrong_socket).await?);
        let mut ceremony = LocalBusCreationClient::connect(&wrong_socket).await?;
        assert!(ceremony.begin_headless("Wrong daemon", "owner").await.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&wrong_socket, &wrong_root.0), receiver),
        flow
    );
    if let Err(error) = server {
        assert!(
            matches!(&error, crate::SdkError::Io(io) if io.kind() == std::io::ErrorKind::NotConnected),
            "unexpected wrong-daemon creation server failure: {error}"
        );
    }
    flow.map_err(|error| format!("wrong daemon creation flow failed: {error}"))?;

    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&wrong_socket).await?;
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
                json!({"account":"agent","path":wrong_root.0.join("agent.bundle")}),
            ))
            .await?;
        assert!(refused.error.is_some());
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(
        crate::serve_local_bus_until(LocalBusConfig::new(&wrong_socket, &wrong_root.0), receiver),
        flow
    );
    if let Err(error) = server {
        assert!(
            matches!(&error, crate::SdkError::Io(io) if io.kind() == std::io::ErrorKind::NotConnected),
            "unexpected wrong-daemon export server failure: {error}"
        );
    }
    flow.map_err(|error| format!("wrong daemon export flow failed: {error}"))?;
    Ok(())
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
