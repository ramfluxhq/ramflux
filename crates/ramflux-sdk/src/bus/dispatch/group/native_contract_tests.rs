// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group refusal contracts through the production bus dispatcher.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;

fn daemon(account: LocalBusAccountState, root: &std::path::Path) -> LocalBusDaemonState {
    LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root.join("bus-data")),
        accounts: BTreeMap::from([("owner".into(), account)]),
        active_account_id: Some("owner".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

async fn request(
    state: &mut LocalBusDaemonState,
    body: serde_json::Value,
) -> Result<LocalBusDispatchResult, SdkError> {
    let frame = LocalBusFrame::request(
        "rename",
        Some("owner".into()),
        "ramflux.sdk.v1",
        "group.name.set",
        body,
    );
    let (outbound, _receiver) = mpsc::channel(8);
    let mut connection = LocalBusConnectionState::new(1, outbound);
    crate::bus::daemon::dispatch_local_bus_request(&frame, state, &mut connection).await
}

fn install_lease(
    account: &mut LocalBusAccountState,
    root: &std::path::Path,
    primary: &ramflux_crypto::custody::SelfSigningKey,
    expired: bool,
) -> TestResult {
    let now = crate::custody::network_now()?;
    let native = account.client.born_v3_account.as_ref().ok_or("native account")?;
    let id = native.local_account_id().to_owned();
    let mut body = native.record().body.clone();
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(native.record())?);
    body.device_set_epoch += 1;
    let mut cert = body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
    cert.not_before = now - 1000;
    cert.expires_at = if expired { now - 301 } else { now + 3600 };
    cert.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    body.devices[0].branch_certificate = Some(primary.certify_branch(cert)?);
    let authority = ramflux_protocol::custody::CustodyAuthority {
        publication: ramflux_protocol::custody::Publication {
            record: primary.sign_record(body)?,
            compacted_ids: None,
        },
        custodian_publication: None,
    };
    crate::custody::accept_publication(root, &id, &authority, now)?;
    account.client.born_v3_account = Some(Box::new(crate::custody::load_account(root, &id, now)?));
    Ok(())
}

#[tokio::test]
async fn native_group_lease_refusal_is_typed_over_bus_and_fresh_authority_clears_it() -> TestResult
{
    let fixture = Fixture::with_device("lease-owner", "owner-device").await?;
    let primary = fixture.vault.primary_for_public_key(
        &fixture
            .manifest
            .custody
            .as_ref()
            .ok_or("custody")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    fixture.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &fixture.config.target_delivery_id,
        Some(&primary),
    )?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let mut setup = LocalBusConfig::new(fixture.root.0.join("bus.sock"), fixture.root.0.clone());
    setup.custody_vault = Some(fixture.vault);
    account.native_setup = Some(setup);
    let mut state = daemon(account, &fixture.root.0);
    install_lease(
        state.accounts.get_mut("owner").ok_or("owner")?,
        &fixture.root.0,
        &primary,
        true,
    )?;
    let result = Box::pin(request(&mut state, json!({"group_id":"group","name":"Renewed"}))).await;
    let error = result.err().ok_or("expired lease accepted")?;
    assert!(matches!(error, SdkError::Crypto(CryptoError::GroupLeaseUnavailable)));
    let wire = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(wire.code, "GroupLeaseUnavailable");
    assert!(wire.message.contains("refresh branch authority"));
    install_lease(
        state.accounts.get_mut("owner").ok_or("owner")?,
        &fixture.root.0,
        &primary,
        false,
    )?;
    assert_eq!(
        Box::pin(request(&mut state, json!({"group_id":"group","name":"Renewed"})))
            .await?
            .response_body["name"],
        "Renewed"
    );
    Ok(())
}

#[tokio::test]
async fn group_bus_generic_refusals_preserve_legacy_codes_and_type_only_native_accounts()
-> TestResult {
    let fixture = Fixture::new("native-refusal").await?;
    let root = fixture.root.0.clone();
    let primary = fixture.vault.primary_for_public_key(
        &fixture
            .manifest
            .custody
            .as_ref()
            .ok_or("custody")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    fixture.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &fixture.config.target_delivery_id,
        Some(&primary),
    )?;
    let native = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let legacy = super::tests::account_state(
        "legacy-refusal",
        "legacy",
        "legacy-owner",
        "legacy-device",
        [81; 32],
    )?;
    legacy.client.shared_group_create(
        "group",
        "thread",
        None,
        &legacy.gateway_config.target_delivery_id,
    )?;
    for (account, expected) in [(legacy, "ValidationFailed"), (native, "GroupRenameRefused")] {
        let mut state = daemon(account, &root);
        let error = Box::pin(request(
            &mut state,
            json!({"group_id":"group","name":"Denied","actor_id":"foreign-device"}),
        ))
        .await
        .err()
        .ok_or("invalid group rename accepted")?;
        assert_eq!(crate::bus::io::local_bus_error_body(&error).code, expected);
    }
    Ok(())
}

async fn read_group(
    state: &mut LocalBusDaemonState,
    method: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let frame = LocalBusFrame::request(
        method,
        Some("owner".into()),
        "ramflux.sdk.v1",
        method,
        json!({"group_id":"group","conversation_id":"thread","limit":32}),
    );
    let (outbound, _receiver) = mpsc::channel(8);
    let mut connection = LocalBusConnectionState::new(1, outbound);
    Box::pin(crate::bus::daemon::dispatch_local_bus_request(&frame, state, &mut connection)).await
}

pub(crate) async fn renamed_group_fixture() -> TestResult<(Fixture, Fixture, GatewayInboxEntry)> {
    use ramflux_protocol::group_state::GroupStateChange;
    let alice = Fixture::with_device("freshness-alice", "alice-device").await?;
    let bob = Fixture::with_device("freshness-bob", "bob-device").await?;
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    bob.client.persist_fetched_identity_directory(&alice.manifest)?;
    let primary = bob
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native Bob")?
        .group_primary(bob.vault.as_ref())?;
    bob.client.shared_group_create_with_primary(
        "group",
        "thread",
        Some("Before".into()),
        &bob.config.target_delivery_id,
        Some(&primary),
    )?;
    let joined = bob.client.shared_group_change_with_primary(
        "group",
        &bob.config.target_delivery_id,
        GroupStateChange::Add {
            member: alice.client.owned_group_actor(&alice.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    alice.client.accept_shared_group_state(&joined, &alice.config.target_delivery_id)?;
    let renamed = bob.client.shared_group_change_with_primary(
        "group",
        &bob.config.target_delivery_id,
        GroupStateChange::SetName { name: "After".into() },
        Some(&primary),
    )?;
    alice.client.accept_shared_group_state(&renamed, &alice.config.target_delivery_id)?;
    let distribution = bob.client.export_group_sender_key_distribution("group", "bob-device")?;
    alice.client.import_group_sender_key_distribution(&distribution)?;
    let entry = group_entry(&alice, &bob, "after-rename", 1)?;
    Ok((alice, bob, entry))
}

fn group_entry(
    alice: &Fixture,
    bob: &Fixture,
    id: &str,
    sequence: u64,
) -> TestResult<GatewayInboxEntry> {
    routed_entry(alice, bob, id, sequence, crate::client::routed::Route::group_message("group"))
}

fn routed_entry(
    alice: &Fixture,
    bob: &Fixture,
    id: &str,
    sequence: u64,
    route: crate::client::routed::Route,
) -> TestResult<GatewayInboxEntry> {
    let mut message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: bob.config.principal_id.clone(),
        sender_id: "bob-device".into(),
        recipient_device_id: Some("alice-device".into()),
        recipient_principal_commitment: Some(alice.manifest.principal_commitment.clone()),
        target_delivery_id: alice.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let body = bob.client.encrypt_group_message("group", "bob-device", b"after rename")?;
    let sealed = bob.client.seal_routed_prepared(
        &bob.config,
        &message,
        &body,
        route,
        crate::client::routed::SendMaterial {
            manifest: None,
            bundle: Some(
                alice
                    .client
                    .load_x3dh_private_state(&alice.client.owned_device_identity()?)?
                    .bundle,
            ),
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: sequence,
        target_delivery_id: alice.config.target_delivery_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&bob.config, &message, None)?,
    };
    Ok(entry)
}

fn assert_freshness_refusal<T>(result: &Result<T, SdkError>) {
    assert!(
        matches!(result, Err(SdkError::FreshHeadRequired { .. })),
        "{:?}",
        result.as_ref().err()
    );
}

fn install_gateway(account: &mut LocalBusAccountState, entries: Vec<GatewayInboxEntry>) {
    let mut gateway = crate::bus::dispatch::surface_transport::fixture::RecordingGateway::new(
        std::sync::Arc::default(),
    );
    gateway.inbox = entries;
    gateway.ack_target = account.gateway_config.target_delivery_id.clone();
    account.install_test_session(GatewaySessionEngine::with_test_transport(
        account.gateway_config.clone(),
        Box::new(gateway),
    ));
}

#[tokio::test]
async fn owner_failure_chain_is_characterised() -> TestResult {
    let (alice, bob, entry) = renamed_group_fixture().await?;
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        alice.config,
        alice.manifest.principal_commitment.clone(),
    );
    install_gateway(&mut account, vec![entry.clone()]);
    let mut state = daemon(account, &alice.root.0);
    let received = read_group(&mut state, "group.receive").await?;
    assert_eq!(received.response_body["decrypted_messages"][0]["body_utf8"], "after rename");
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    let messages = account.client.direct_messages("thread")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(
        account.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"after rename".to_vec())
    );
    assert_eq!(account.pending_deliveries.len(), 1);
    assert_eq!(account.client.account_db()?.unrouted_count()?, 0);
    let key = account.client.inbox_admission_key(&entry)?;
    assert!(!account.client.account_db()?.has_inbox_retry(&key)?);
    // Isolate a stale local head: the stored projection authenticates Bob, not Alice.
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    account.client.persist_fetched_identity_directory(&bob.manifest)?;
    assert_freshness_refusal(
        &account
            .client
            .require_current_device_authorization(&account.client.owned_device_identity()?),
    );
    for method in ["group.read", "group.receive"] {
        assert_eq!(
            read_group(&mut state, method).await?.response_body["decrypted_messages"][0]["body_utf8"],
            "after rename"
        );
    }
    // Both stale and peer-only stale display actual admitted content without a fetch.
    for local_fresh in [false, true] {
        let account = state.accounts.get_mut("owner").ok_or("Alice")?;
        *account.client.native_head_freshness.borrow_mut() =
            crate::client::identity_authority::NativeHeadFreshness::default();
        if local_fresh {
            account.client.persist_fetched_identity_directory(&alice.manifest)?;
        }
        assert_freshness_refusal(
            &account.client.committed_routing(HeadUse::NewAuthorization, &entry),
        );
        for method in ["group.read", "group.receive"] {
            assert_eq!(
                read_group(&mut state, method).await?.response_body["decrypted_messages"][0]["body_utf8"],
                "after rename"
            );
        }
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert_eq!(
        account.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"after rename".to_vec())
    );
    Ok(())
}

fn assert_retry_retained(account: &LocalBusAccountState, key: &str) -> TestResult {
    let db = account.client.account_db()?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 0);
    assert_eq!(db.unrouted_count()?, 0);
    assert!(db.has_inbox_retry(key)?);
    assert!(!db.journal_after(0, 100)?.iter().any(|event| event.topic == "message.undeliverable"));
    Ok(())
}

async fn assert_first_pass_admitted(
    account: &mut LocalBusAccountState,
    key: &str,
    at: i64,
) -> TestResult {
    let messages = account.client.direct_messages("thread")?;
    assert_eq!(messages.len(), 1, "served peer manifest must admit on the first pass");
    assert_eq!(
        account.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"after rename".to_vec())
    );
    assert!(!account.client.account_db()?.has_inbox_retry(key)?);
    assert_eq!(account.client.account_db()?.unrouted_count()?, 0);
    crate::bus::sync_driver::run_at(account, at + 1).await?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    Ok(())
}

async fn assert_deferred_reason(
    account: &mut LocalBusAccountState,
    entry: &GatewayInboxEntry,
    unavailable: bool,
) -> TestResult {
    // Replay the same production admission leg without changing the retained retry/backoff.
    let mut engine = account.session_client().await?;
    let pool = account.relay_quic_pool()?;
    let result = account.client.apply_routed_entry(&mut engine, &pool, entry, false).await;
    account.apply_session_metadata(engine);
    if unavailable {
        let error = result.err().ok_or("unavailable directory unexpectedly admitted")?;
        assert!(error.to_string().contains("404"), "{error}");
        assert!(account.client.inbound_device_manifest_request(entry)?.is_some());
    } else {
        assert_freshness_refusal(&result);
        assert!(account.client.inbound_device_manifest_request(entry)?.is_none());
        assert_freshness_refusal(
            &account
                .client
                .require_current_device_authorization(&account.client.owned_device_identity()?),
        );
    }
    Ok(())
}

async fn verify_refresh_redrive(
    account: &mut LocalBusAccountState,
    manifests: (&crate::SdkDeviceManifestResponse, &crate::SdkDeviceManifestResponse),
    flags: (bool, bool, bool),
    key: &str,
    delivery: (usize, i64),
    unrelated: &GatewayInboxEntry,
) -> TestResult {
    let (count, at) = delivery;
    let (alice, bob) = manifests;
    let (local_fresh, peer_fresh, serve_peer) = flags;
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    let refresh = crate::bus::couriers::head_refresh::test_apply;
    let dependency = if !peer_fresh && !serve_peer { bob } else { alice };
    let root = &dependency.principal_commitment;
    assert!(
        refresh(account, root, std::time::Instant::now(), Err(SdkError::NetworkingPending))
            .is_err()
    );
    let old = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(301))
        .ok_or("clock")?;
    assert!(!refresh(account, root, old, Ok(dependency.clone()))?);
    let mut invalid = dependency.clone();
    invalid.principal_id = "invalid-authority".into();
    assert!(refresh(account, root, std::time::Instant::now(), Ok(invalid)).is_err());
    assert!(!crate::bus::couriers::head_refresh::inbound::eligible(account, key));
    let unrelated_key = account.client.inbox_admission_key(unrelated)?;
    assert_eq!(
        account.client.account_db()?.defer_inbox_entry(
            &unrelated_key,
            &serde_json::to_vec(unrelated)?,
            at,
        )?,
        1
    );
    crate::bus::couriers::head_refresh::inbound::retain(
        account,
        unrelated,
        &unrelated_key,
        &SdkError::InboundPending("sender key not yet available".into()),
    )?;
    if !local_fresh {
        assert!(refresh(
            account,
            &alice.principal_commitment,
            std::time::Instant::now(),
            Ok(alice.clone())
        )?);
        if !peer_fresh && !serve_peer {
            assert!(
                !crate::bus::couriers::head_refresh::inbound::eligible(account, key),
                "peer dependency remains"
            );
            assert_retry_retained(account, key)?;
        }
    }
    if !peer_fresh && !serve_peer {
        assert!(refresh(
            account,
            &bob.principal_commitment,
            std::time::Instant::now(),
            Ok(bob.clone())
        )?);
    }
    assert!(crate::bus::couriers::head_refresh::inbound::eligible(account, key));
    assert!(handle.resync_needed(), "existing receive courier must be notified");
    assert!(!crate::bus::couriers::head_refresh::inbound::eligible(account, &unrelated_key));
    assert!(!account.client.account_db()?.inbox_retry_ready(&unrelated_key, at + 1)?);
    assert!(account.client.account_db()?.inbox_retry_ready(&unrelated_key, at + 2)?);
    // Run the existing receive loop with a one-hour tick; only the refresh wake can drive it.
    crate::bus::connection_manager::receive::test_redrive(account, "thread", count).await?;
    assert!(!crate::bus::couriers::head_refresh::inbound::eligible(account, &unrelated_key));
    assert!(!account.client.account_db()?.inbox_retry_ready(&unrelated_key, at + 1)?);
    assert!(account.client.account_db()?.inbox_retry_ready(&unrelated_key, at + 2)?);
    assert_eq!(
        account.client.account_db()?.defer_inbox_entry(
            &unrelated_key,
            &serde_json::to_vec(unrelated)?,
            at,
        )?,
        2,
        "refresh/redrive must not consume an unrelated attempt"
    );
    assert_eq!(account.client.direct_messages("thread")?.len(), count);
    assert!(!account.client.account_db()?.has_inbox_retry(key)?);
    assert_eq!(
        account.pending_deliveries.iter().map(|entry| entry.inbox_seq).collect::<Vec<_>>(),
        (1..=count as u64).collect::<Vec<_>>()
    );
    assert_eq!(account.client.account_db()?.unrouted_count()?, 0);
    Ok(())
}

async fn assert_wait_scope(state: &mut LocalBusDaemonState, opaque: bool) -> TestResult {
    for method in ["group.read", "group.receive"] {
        let result = read_group(state, method).await;
        if opaque {
            // A directory failure precedes private-route decoding. Opaque retries
            // remain background work and cannot hold an assumed group RPC.
            assert_eq!(result?.response_body["decrypted_messages"], json!([]));
        } else {
            let error = result.err().ok_or("known group dependency must remain pending")?;
            let wire = crate::bus::io::local_bus_error_body(&error);
            assert_eq!(wire.code, "NetworkingPending");
            assert!(wire.retry_after_ms.is_some());
            assert!(wire.details.as_ref().ok_or("details")?.get("networking").is_some());
        }
    }
    Ok(())
}

async fn characterise_gateway_admission(
    local_fresh: bool,
    peer_fresh: bool,
    serve_peer: bool,
) -> TestResult {
    Box::pin(admission_case((local_fresh, peer_fresh, serve_peer), false)).await
}

async fn admission_case(flags: (bool, bool, bool), duplicate_redelivery: bool) -> TestResult {
    let (local_fresh, peer_fresh, serve_peer) = flags;
    let (alice, bob, entry) = renamed_group_fixture().await?;
    let unrelated = group_entry(&alice, &bob, "unrelated-backoff", 3)?;
    let second = if !local_fresh && !peer_fresh && !serve_peer {
        Some(group_entry(&alice, &bob, "second-after-rename", 2)?)
    } else {
        None
    };
    let count = 1 + usize::from(second.is_some());
    let manifests = if serve_peer {
        BTreeMap::from([(
            bob.manifest.principal_commitment.clone(),
            serde_json::to_value(&bob.manifest)?,
        )])
    } else {
        BTreeMap::new()
    };
    let (address, directory) =
        crate::bus::dispatch::surface_transport::fixture::directory(&alice.root.0, manifests)
            .await?;
    let mut config = alice.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = alice.root.0.join("ca.pem");
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        config,
        alice.manifest.principal_commitment.clone(),
    );
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    if local_fresh {
        account.client.persist_fetched_identity_directory(&alice.manifest)?;
    }
    if peer_fresh {
        account.client.persist_fetched_identity_directory(&bob.manifest)?;
    }
    for (identity, fresh) in [
        (account.client.owned_device_identity()?, local_fresh),
        (bob.client.owned_device_identity()?, peer_fresh),
    ] {
        let result = account.client.require_current_device_authorization(&identity);
        if fresh {
            result?;
        } else {
            assert_freshness_refusal(&result);
        }
    }
    assert_eq!(
        account.client.inbound_device_manifest_request(&entry)?,
        (!peer_fresh).then(|| bob.manifest.principal_commitment.clone())
    );
    let key = account.client.inbox_admission_key(&entry)?;
    let entries = std::iter::once(entry.clone()).chain(second).collect();
    install_gateway(&mut account, entries);
    // Same driver and quarantine path as the bus; only its existing receive clock is injected.
    let at = now_unix_timestamp() + 60;
    crate::bus::sync_driver::run_at(&mut account, at).await?;
    if serve_peer && local_fresh {
        assert_first_pass_admitted(&mut account, &key, at).await?;
        directory.abort();
        return Ok(());
    }
    assert_retry_retained(&account, &key)?;
    assert_deferred_reason(&mut account, &entry, !peer_fresh && !serve_peer).await?;
    assert_eq!(account.client.account_db()?.due_inbox_retry_rows(at + 1)?.len(), 0);
    assert_eq!(account.client.account_db()?.due_inbox_retry_rows(at + 2)?.len(), count);
    let mut state = daemon(account, &alice.root.0);
    assert_wait_scope(&mut state, !peer_fresh && !serve_peer).await?;
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    assert_retry_retained(account, &key)?;
    verify_refresh_redrive(
        account,
        (&alice.manifest, &bob.manifest),
        (local_fresh, peer_fresh, serve_peer),
        &key,
        (count, at),
        &unrelated,
    )
    .await?;
    let received = read_group(&mut state, "group.receive").await?;
    assert_eq!(received.response_body["decrypted_messages"][0]["body_utf8"], "after rename");
    assert_eq!(
        state.accounts.get("owner").ok_or("Alice")?.client.direct_messages("thread")?.len(),
        count
    );
    if duplicate_redelivery {
        let account = state.accounts.get_mut("owner").ok_or("Alice")?;
        review::assert_duplicate_after_refresh(account, entry, count, at, &key).await?;
    }
    directory.abort();
    Ok(())
}

#[tokio::test]
async fn stale_local_head_gateway_admission_is_deferred_until_retry_due() -> TestResult {
    Box::pin(characterise_gateway_admission(false, true, false)).await
}

#[tokio::test]
async fn stale_peer_head_after_rename_gateway_admission_is_deferred_until_retry_due() -> TestResult
{
    Box::pin(characterise_gateway_admission(true, false, false)).await
}

#[tokio::test]
async fn both_stale_heads_gateway_admission_is_deferred_until_retry_due() -> TestResult {
    Box::pin(characterise_gateway_admission(false, false, false)).await
}

#[tokio::test]
async fn stale_peer_head_with_served_manifest_is_admitted_on_first_pass() -> TestResult {
    Box::pin(characterise_gateway_admission(true, false, true)).await
}

#[tokio::test]
async fn both_stale_heads_with_served_peer_manifest_defer_on_local_head() -> TestResult {
    Box::pin(characterise_gateway_admission(false, false, true)).await
}

#[tokio::test]
async fn stale_head_new_inbound_stays_pending_until_verified_refresh() -> TestResult {
    let (alice, bob, entry) = renamed_group_fixture().await?;
    let (address, directory) =
        crate::bus::dispatch::surface_transport::fixture::directory(&alice.root.0, BTreeMap::new())
            .await?;
    let mut config = alice.config;
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = alice.root.0.join("ca.pem");
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        config,
        alice.manifest.principal_commitment.clone(),
    );
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    account.client.persist_fetched_identity_directory(&alice.manifest)?;
    let key = account.client.inbox_admission_key(&entry)?;
    install_gateway(&mut account, vec![entry]);
    let at = now_unix_timestamp() + 60;
    crate::bus::sync_driver::run_at(&mut account, at).await?;
    assert_retry_retained(&account, &key)?;
    let old = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(301))
        .ok_or("clock")?;
    account.client.persist_fetched_identity_directory_at(&bob.manifest, old)?;
    let mut invalid = bob.manifest.clone();
    invalid.principal_id = "invalid-authority".into();
    assert!(account.client.persist_fetched_identity_directory(&invalid).is_err());
    crate::bus::sync_driver::run_at(&mut account, at + 2).await?;
    assert_retry_retained(&account, &key)?;
    let handle = account.connection.as_ref().ok_or("connection")?.clone();
    crate::bus::couriers::head_refresh::test_apply(
        &mut account,
        &bob.manifest.principal_commitment,
        std::time::Instant::now(),
        Ok(bob.manifest.clone()),
    )?;
    assert!(handle.resync_needed());
    crate::bus::sync_driver::run_at(&mut account, at + 3).await?;

    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert!(!account.client.account_db()?.has_inbox_retry(&key)?);
    directory.abort();
    Ok(())
}

#[tokio::test]
async fn stored_group_history_after_rename_with_expired_head_succeeds() -> TestResult {
    let (alice, _bob, entry) = renamed_group_fixture().await?;
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        alice.config,
        alice.manifest.principal_commitment,
    );
    install_gateway(&mut account, vec![entry]);
    let mut state = daemon(account, &alice.root.0);
    read_group(&mut state, "group.receive").await?;
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    account.engine = None;
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    assert!(crate::bus::readers::is_reader_request("group.history"));
    let result = read_group(&mut state, "group.history").await?.response_body;
    assert_eq!(result["metadata"]["name"], "After");
    assert_eq!(result["metadata"]["member_roster"].as_array().ok_or("roster")?.len(), 2);
    assert_eq!(result["decrypted_messages"][0]["body_utf8"], "after rename");
    let frame = LocalBusFrame::request(
        "offline-reader",
        Some("owner".into()),
        "ramflux.sdk.v1",
        "group.history",
        json!({"group_id":"group","conversation_id":"thread","limit":32}),
    );
    assert_eq!(crate::bus::readers::read_account(&state, "owner", &frame)?, result);
    assert!(state.accounts.get("owner").ok_or("Alice")?.engine.is_none());
    Ok(())
}

#[tokio::test]
async fn historical_read_ignores_clock_but_not_revocation() -> TestResult {
    let (alice, bob, entry) = renamed_group_fixture().await?;
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        alice.config,
        alice.manifest.principal_commitment,
    );
    install_gateway(&mut account, vec![entry]);
    let mut state = daemon(account, &alice.root.0);
    read_group(&mut state, "group.receive").await?;
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    for method in ["group.history", "group.read", "group.receive"] {
        assert_eq!(
            read_group(&mut state, method).await?.response_body["decrypted_messages"][0]["body_utf8"],
            "after rename"
        );
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    let identity = bob.client.owned_device_identity()?;
    account
        .client
        .account_db()?
        .persist_actor_state(&RamfluxClient::device_revocation_key(&identity), &true)?;
    let history = read_group(&mut state, "group.history").await?.response_body;
    assert_eq!(history["decrypted_messages"][0]["sender_verification"], "unverified");
    assert_eq!(history["messages"][0]["sender_verification"], "unverified");
    for method in ["group.read", "group.receive"] {
        assert!(
            matches!(read_group(&mut state, method).await,
            Err(SdkError::InboundRejected(reason)) if reason == "revoked device"),
            "unexpected revoked-sender outcome via {method}"
        );
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    account
        .client
        .account_db()?
        .persist_actor_state(&RamfluxClient::device_revocation_key(&identity), &false)?;
    let id = account.client.direct_messages("thread")?[0].message_id.clone();
    account.client.delete_direct_message("thread", &id, "local", "erase-proof")?;
    for method in ["group.history", "group.read", "group.receive"] {
        let body = read_group(&mut state, method).await?.response_body;
        assert_eq!(body["decrypted_messages"], json!([]), "erased content via {method}");
    }
    Ok(())
}

#[tokio::test]
async fn stored_group_history_degrades_sibling_and_revoked_senders_per_message() -> TestResult {
    let (alice, bob, entry) = renamed_group_fixture().await?;
    let mut account = LocalBusAccountState::disconnected(
        alice.client,
        alice.config,
        alice.manifest.principal_commitment,
    );
    install_gateway(&mut account, vec![entry]);
    let mut state = daemon(account, &alice.root.0);
    read_group(&mut state, "group.receive").await?;
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    account.engine = None;
    // Own-sent projections have no routed/message-owner row. A second device's
    // raw sender ID cannot prove its root locally and must not become trusted.
    for (id, sender, content) in [
        ("own-primary", "alice-device", "healthy primary"),
        ("own-sibling", "alice-sibling-device", "second device"),
    ] {
        account.client.send_direct_message("thread", id, sender, b"stored ciphertext")?;
        account.client.account_db()?.store_message_content("thread", id, content.as_bytes())?;
    }
    account.client.account_db()?.persist_actor_state(
        &RamfluxClient::device_revocation_key(&bob.client.owned_device_identity()?),
        &true,
    )?;
    *account.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    let frame = LocalBusFrame::request(
        "mixed-history",
        Some("owner".into()),
        "group",
        "group.history",
        json!({"group_id":"group","conversation_id":"thread","limit":32}),
    );
    let body = read_group(&mut state, "group.history").await?.response_body;
    assert_eq!(crate::bus::readers::read_account(&state, "owner", &frame)?, body);
    for field in ["messages", "decrypted_messages"] {
        let rows = body[field].as_array().ok_or("message rows")?;
        assert_eq!(rows.len(), 3, "one sender must not hide any stored message");
        for (id, marker) in [("own-primary", "verified"), ("own-sibling", "unknown")] {
            let row = rows.iter().find(|row| row["message_id"] == id).ok_or("own message")?;
            assert_eq!(row["sender_verification"], marker);
        }
        let revoked = rows
            .iter()
            .find(|row| row["sender_verification"] == "unverified")
            .ok_or("revoked message")?;
        assert_ne!(revoked["message_id"], "own-primary");
        assert_ne!(revoked["message_id"], "own-sibling");
    }
    let rows = body["decrypted_messages"].as_array().ok_or("plaintext rows")?;
    assert!(rows.iter().any(
        |row| row["body_utf8"] == "after rename" && row["sender_verification"] == "unverified"
    ));
    assert!(
        rows.iter()
            .any(|row| row["body_utf8"] == "second device"
                && row["sender_verification"] == "unknown")
    );
    assert!(state.accounts.get("owner").ok_or("Alice")?.engine.is_none());
    Ok(())
}

#[tokio::test]
async fn opaque_inbound_after_rename_refreshes_in_background_then_applies() -> TestResult {
    Box::pin(characterise_gateway_admission(true, false, false)).await
}

#[tokio::test]
async fn parked_inbound_is_applied_after_refresh_once() -> TestResult {
    Box::pin(admission_case((false, false, false), true)).await
}

mod review;
