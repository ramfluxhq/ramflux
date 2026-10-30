// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary account actor lifecycle without access to the primary credential provider.
use crate::custody::tests::{Root, TestVault, input, words};
use crate::{LocalBusClient, LocalBusConfig, LocalBusFrame, custody::CreationCeremony};
use ramflux_protocol::custody::CustodyRefusal;
use serde_json::json;
use std::time::Duration;
use tokio::sync::watch;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Stop(watch::Sender<bool>);
impl Drop for Stop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

fn node_profile(id: &str, gateway_addr: &str, seed: u8) -> crate::NodeProfile {
    crate::NodeProfile {
        discovery_url: format!("https://{id}"),
        node_id: id.to_owned(),
        node_public_key: ramflux_protocol::encode_base64url([seed; 32]),
        pin_source: crate::NodePinSource::Operator,
        ca_cert_pem: "test CA".to_owned(),
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
        let pending = ceremony
            .begin("New Ordinary Human", ramflux_protocol::PrincipalKind::Human, None)
            .await?;
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
        ceremony.begin("Failed Human", ramflux_protocol::PrincipalKind::Human, None).await?;
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
                .begin("AI without custodian", ramflux_protocol::PrincipalKind::HeadlessAi, None)
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
            .begin(
                "Selected Home Node",
                ramflux_protocol::PrincipalKind::Human,
                Some(&selected.node_id),
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

#[test]
fn node_unreachable_reason_comes_from_typed_transport_failure() {
    let error = crate::SdkError::NodeUnreachable {
        retry_after_ms: 7_500,
        source: Box::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()),
    };
    assert_eq!(
        super::native_account::networking_reason(&error),
        Some(crate::AccountNetworkingReason::NodeUnreachable { retry_after_ms: 7_500 })
    );
}

#[test]
fn gateway_without_custody_configuration_has_typed_reason() {
    let error = crate::SdkError::CustodyNetwork(CustodyRefusal::Unsupported);
    assert_eq!(
        super::native_account::networking_reason(&error),
        Some(crate::AccountNetworkingReason::NodeCustodyUnavailable)
    );
}

#[test]
fn pool_busy_refusal_has_retryable_typed_reason() {
    let error = crate::SdkError::CustodyNetwork(CustodyRefusal::Busy);
    assert_eq!(
        super::native_account::networking_reason(&error),
        Some(crate::AccountNetworkingReason::NodeBusy { retry_after_ms: 16_000 })
    );
}

#[test]
fn registration_refusal_preserves_typed_code() {
    let error = crate::SdkError::CustodyNetwork(CustodyRefusal::PrincipalIdTaken);
    assert_eq!(
        super::native_account::networking_reason(&error),
        Some(crate::AccountNetworkingReason::RegistrationRefused {
            code: CustodyRefusal::PrincipalIdTaken,
        })
    );
}

#[test]
fn expired_custody_session_has_typed_reason() {
    let error = crate::SdkError::CustodyNetwork(CustodyRefusal::SessionExpired);
    assert_eq!(
        super::native_account::networking_reason(&error),
        Some(crate::AccountNetworkingReason::CustodyExpired)
    );
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
