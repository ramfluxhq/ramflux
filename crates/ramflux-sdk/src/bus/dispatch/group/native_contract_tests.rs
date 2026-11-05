// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group refusal contracts through the production bus dispatcher.
use super::*;
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

async fn renamed_group_fixture() -> TestResult<(Fixture, Fixture, GatewayInboxEntry)> {
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
    let mut message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "after-rename".into(),
        envelope_id: "after-rename".into(),
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
        crate::client::routed::Route::group_message("group"),
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
        inbox_seq: 1,
        target_delivery_id: alice.config.target_delivery_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&bob.config, &message, None)?,
    };
    Ok((alice, bob, entry))
}

fn assert_freshness_refusal<T>(result: &Result<T, SdkError>) {
    assert!(
        matches!(result, Err(SdkError::InboundPending(reason)) if reason ==
        "native current-head freshness expired; refresh directory"),
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
    // Both stale and peer-only stale fail on actual admitted content, with no gateway entry.
    for local_fresh in [false, true] {
        let account = state.accounts.get_mut("owner").ok_or("Alice")?;
        *account.client.native_head_freshness.borrow_mut() =
            crate::client::identity_authority::NativeHeadFreshness::default();
        if local_fresh {
            account.client.persist_fetched_identity_directory(&alice.manifest)?;
        }
        assert_freshness_refusal(&account.client.committed_routing(&entry));
        for method in ["group.read", "group.receive"] {
            assert_freshness_refusal(&read_group(&mut state, method).await);
        }
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert_eq!(
        account.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"after rename".to_vec())
    );
    // Differential probe localizes the failure to pending-delivery re-projection.
    let projected = std::mem::take(&mut account.pending_deliveries);
    for method in ["group.read", "group.receive"] {
        assert_eq!(
            read_group(&mut state, method).await?.response_body["decrypted_messages"][0]["body_utf8"],
            "after rename"
        );
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    account.pending_deliveries = projected;
    account.client.persist_fetched_identity_directory(&bob.manifest)?;
    for method in ["group.read", "group.receive"] {
        assert_eq!(
            read_group(&mut state, method).await?.response_body["decrypted_messages"][0]["body_utf8"],
            "after rename"
        );
    }
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

async fn characterise_gateway_admission(local_fresh: bool, peer_fresh: bool) -> TestResult {
    let (alice, bob, entry) = renamed_group_fixture().await?;
    // The peer refresh really reaches a TLS directory and fails with a deterministic 404.
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
    install_gateway(&mut account, vec![entry]);
    // Same driver and quarantine path as the bus; only its existing receive clock is injected.
    let at = now_unix_timestamp() + 60;
    crate::bus::sync_driver::run_at(&mut account, at).await?;
    assert_retry_retained(&account, &key)?;
    assert_eq!(account.client.account_db()?.due_inbox_retry_rows(at + 1)?.len(), 0);
    assert_eq!(account.client.account_db()?.due_inbox_retry_rows(at + 2)?.len(), 1);
    let mut state = daemon(account, &alice.root.0);
    for method in ["group.read", "group.receive"] {
        let result = read_group(&mut state, method).await?;
        assert_eq!(result.response_body["decrypted_messages"], json!([]));
    }
    let account = state.accounts.get_mut("owner").ok_or("Alice")?;
    assert_retry_retained(account, &key)?;
    account.client.persist_fetched_identity_directory(&alice.manifest)?;
    account.client.persist_fetched_identity_directory(&bob.manifest)?;
    crate::bus::sync_driver::run_at(account, at + 1).await?;
    assert_retry_retained(account, &key)?;
    crate::bus::sync_driver::run_at(account, at + 2).await?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert!(!account.client.account_db()?.has_inbox_retry(&key)?);
    assert_eq!(account.client.account_db()?.unrouted_count()?, 0);
    let received = read_group(&mut state, "group.receive").await?;
    assert_eq!(received.response_body["decrypted_messages"][0]["body_utf8"], "after rename");
    assert_eq!(
        state.accounts.get("owner").ok_or("Alice")?.client.direct_messages("thread")?.len(),
        1
    );
    directory.abort();
    Ok(())
}

#[tokio::test]
async fn stale_local_head_gateway_admission_is_deferred_until_retry_due() -> TestResult {
    Box::pin(characterise_gateway_admission(false, true)).await
}

#[tokio::test]
async fn stale_peer_head_after_rename_gateway_admission_is_deferred_until_retry_due() -> TestResult
{
    Box::pin(characterise_gateway_admission(true, false)).await
}

#[tokio::test]
async fn both_stale_heads_gateway_admission_is_deferred_until_retry_due() -> TestResult {
    Box::pin(characterise_gateway_admission(false, false)).await
}
