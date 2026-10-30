// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary account actor lifecycle without access to the primary credential provider.
use crate::custody::tests::{Root, TestVault, input, words};
use crate::{LocalBusClient, LocalBusConfig, LocalBusFrame, custody::CreationCeremony};
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
        ordinary
            .request(Some(account.account_id.clone()), "account", "account.lock", json!({}))
            .await?;
        ordinary
            .request(
                Some(account.account_id),
                "account",
                "account.unlock",
                json!({"passphrase":"creation data secret"}),
            )
            .await?;
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
    if let Err(error) = server {
        assert!(
            matches!(&error, crate::SdkError::Io(io) if io.kind() == std::io::ErrorKind::NotConnected),
            "unexpected headless refusal server failure: {error}"
        );
    }
    flow.map_err(|error| format!("headless refusal flow failed: {error}"))?;
    Ok(())
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
        Err(crate::SdkError::Io(error)) if error.kind() == std::io::ErrorKind::NotConnected => {
            Ok(())
        }
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
