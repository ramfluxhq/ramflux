// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native consent uses the production directory projection and ordinary send transport.
use super::*;
use crate::client::native_test_support::{Fixture as NativeFixture, TestResult};
#[path = "native_contact_background_tests.rs"]
mod background;

fn native_card(sender: &NativeFixture) -> TestResult<String> {
    let now = crate::custody::network_now()?;
    let account = sender.client.born_v3_account.as_ref().ok_or("native account")?;
    let record = account.record();
    let signed = account.sign_contact_card(
        sender.vault.as_ref(),
        ramflux_protocol::custody::ContactCardV3 {
            version: 3,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            master_public_key: record.body.master_certificate.body.master_public_key.clone(),
            master_certificate: record.body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(record)?,
            authority_epoch: record.body.device_set_epoch,
            devices: record.body.devices.clone(),
            node_url: "https://node.example".into(),
            node_key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::fixture_public_key_base64url(),
            )?,
            display_name: record.body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now + 3600,
        },
        now,
    )?;
    Ok(crate::contact_card_native::encode(&signed, i64::try_from(now)?)?.0)
}

fn native_state(
    sender: &mut NativeFixture,
    target: &mut NativeFixture,
    directory: &Directory,
) -> Result<LocalBusDaemonState, SdkError> {
    let mut accounts = BTreeMap::new();
    for fixture in [&mut *sender, &mut *target] {
        let mut config = fixture.config.clone();
        config.transport_kind = GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = directory.addr;
        config.tcp_gateway_addr = Some(directory.addr);
        config.server_name = "directory.test".into();
        config.ca_cert = directory.ca.clone();
        let engine = GatewaySessionEngine::with_test_transport(
            config,
            Box::new(DirectorySession {
                captured: directory.captured.clone(),
                incoming: directory.incoming.clone(),
                acknowledged: directory.acknowledged.clone(),
                records: directory.records.clone(),
                unavailable: directory.unavailable.clone(),
                responses: VecDeque::new(),
            }),
        );
        accounts.insert(
            fixture.client.account_db()?.local_account_id.clone(),
            LocalBusAccountState::new(
                std::mem::take(&mut fixture.client),
                engine,
                fixture.manifest.principal_commitment.clone(),
            ),
        );
    }
    Ok(LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(sender.root.0.join("bus.sock"), &sender.root.0),
        accounts,
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    })
}

fn clear_safety_cache(receiver: &crate::RamfluxClient, principal: &str) -> TestResult {
    let db = receiver.account_db()?;
    let mut identity = db.client_record("identity", principal)?.ok_or("identity")?;
    identity.as_object_mut().ok_or("identity object")?.remove("safety_number");
    identity.as_object_mut().ok_or("identity object")?.remove("safety_number_algorithm_version");
    db.persist_client_record("identity", principal, &identity)?;
    Ok(())
}

#[tokio::test]
async fn native_auto_accepted_card_retry_repairs_an_uncached_identity_without_a_network_fetch()
-> TestResult {
    let mut sender = NativeFixture::with_device("alice", "alice").await?;
    let mut target = NativeFixture::with_device("bob", "bob").await?;
    let directory = Directory::from_records(
        &sender.root.0,
        vec![sender.manifest.clone(), target.manifest.clone()],
    )
    .await?;
    let card = native_card(&sender)?;
    let mut state = native_state(&mut sender, &mut target, &directory)?;
    requests::account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    call(&mut state, "alice", "contact.add", json!({"principal_id":target.manifest.principal_id}))
        .await?;
    let envelope =
        directory.captured.lock().map_err(|_| "capture poisoned")?.pop().ok_or("request")?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let receiver = state.accounts.get_mut("bob").ok_or("receiver")?;
    let mut engine = receiver.session_client().await?;
    let result = receiver
        .client
        .apply_routed_entry(&mut engine, &super::super::review::pool()?, &entry)
        .await;
    receiver.install_test_session(engine);
    result?;
    let principal = sender.manifest.principal_id.clone();
    let root = sender.manifest.principal_commitment.clone();
    let receiver = requests::account(&state, "bob")?;
    assert!(receiver.identity_root.is_none());
    assert!(receiver.friend_link_peer_is_accepted(&root)?);
    let row = crate::bus::read_model::row(receiver, "identity", &principal)?;
    assert_eq!(row["root_source"], "lookup");
    // Native first acceptance already caches safety. Exercise an older accepted row
    // whose derived cache is absent; the current authority and consent stay intact.
    assert_eq!(row["safety_number_available"], true);
    directory.unavailable.store(true, Ordering::SeqCst);
    target.vault.fail.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    for (index, (source, selector)) in [
        ("lookup", json!({"principal_id":principal})),
        // A card retry returns the existing state: no provenance change without the full checks.
        ("lookup", json!({"card":card})),
        ("lookup", json!({"principal_id":principal})),
        ("verified", json!({"card":card})),
    ]
    .into_iter()
    .enumerate()
    {
        let receiver = requests::account(&state, "bob")?;
        if source == "verified" {
            crate::client::contact_verification_cas::verify_linked_contact(receiver, &root)?;
        }
        clear_safety_cache(receiver, &principal)?;
        let verification = receiver.account_db()?.contact_verification(&root)?;
        let started = std::time::Instant::now();
        let accepted = call(&mut state, "bob", "contact.accept", selector).await?;
        assert_eq!(
            accepted["contact"]["root_source"], source,
            "retry {index}: provenance must stay what the earlier checks established"
        );
        let receiver = requests::account(&state, "bob")?;
        let row = crate::bus::read_model::row(receiver, "identity", &principal)?;
        assert_eq!(row["safety_number_available"], true);
        assert_eq!(row["safety_number_algorithm_version"], 2);
        assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
        assert_eq!(
            row["safety_number"],
            json!(receiver.contact_safety_number(&root)?.safety_number)
        );
        assert_eq!(row["verified"], source == "verified");
        assert_eq!(receiver.account_db()?.contact_verification(&root)?, verification);
        assert!(receiver.identity_root.is_none());
        eprintln!(
            "native acceptance readiness retry={index} elapsed_us={} remote_fetches={}",
            started.elapsed().as_micros(),
            directory.manifest_fetches.load(Ordering::SeqCst) - before
        );
    }
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_contact_request_crosses_the_ordinary_transport_before_first_direct_message()
-> TestResult {
    crate::client::native_test_support::watchdog::within(native_contact_request_crosses_body())
        .await?
}
async fn native_contact_request_crosses_body() -> TestResult {
    let sender = NativeFixture::with_device("native-transport-alice", "alice-device").await?;
    let target = NativeFixture::with_device("native-transport-bob", "bob-device").await?;
    let directory = Directory::from_records(
        &sender.root.0,
        vec![sender.manifest.clone(), target.manifest.clone()],
    )
    .await?;
    let mut config = sender.config.clone();
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = directory.addr;
    config.tcp_gateway_addr = Some(directory.addr);
    config.server_name = "directory.test".into();
    config.ca_cert = directory.ca.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(DirectorySession {
            captured: directory.captured.clone(),
            incoming: directory.incoming.clone(),
            acknowledged: directory.acknowledged.clone(),
            records: directory.records.clone(),
            unavailable: directory.unavailable.clone(),
            responses: VecDeque::new(),
        }),
    );
    sender.client.persist_observed_identity_directory_now(&target.manifest)?;
    sender.client.stage_contact_request(&target.manifest, "native-transport-contact", None)?;
    let mut intent = sender
        .client
        .account_db()?
        .list_actor_states::<crate::client::contact_requests::delivery::Intent>(
            "contact-request/send/",
        )?
        .pop()
        .ok_or("intent missing")?;
    let outcome = crate::client::contact_requests::delivery::deliver(
        &sender.client,
        &mut engine,
        &mut intent,
    )
    .await?;
    assert_eq!(outcome, (1, true));
    let entry = directory.captured.lock().map_err(|_| "capture poisoned")?[0].clone();
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: entry.target_delivery_id.clone(),
        envelope: entry,
    };
    let (route, body) = target
        .client
        .preview_native_contact_request(&entry, &sender.manifest, "bob-device")?
        .ok_or("native contact preview absent")?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &body,
            Some(&sender.manifest),
        )
        .await?;
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "bob-device")?;
    first_direct_after_native_contact(&sender, &target, &mut engine).await
}

async fn first_direct_after_native_contact(
    sender: &NativeFixture,
    target: &NativeFixture,
    engine: &mut GatewaySessionEngine,
) -> TestResult {
    let mut message = GatewayDirectMessage {
        conversation_id: ramflux_protocol::message::dm_scope::derive(
            &sender.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?,
        message_id: "first-direct".into(),
        envelope_id: "first-direct".into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: "alice-device".into(),
        recipient_device_id: Some("bob-device".into()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.client.owned_device_identity()?.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    assert!(
        sender
            .client
            .account_db()?
            .client_record("conversation", &message.conversation_id)?
            .is_none(),
        "first-contact calibration must have no preexisting root-pair conversation"
    );
    assert!(
        !sender.client.friend_link_peer_is_accepted(&target.manifest.principal_commitment)?,
        "outbound consent must still be pending before the first DM"
    );
    let prepared = sender.client.prepare_authored_message(
        &mut message,
        None,
        &ramflux_protocol::message::Message { text: "first message".into(), ..Default::default() },
    )?;
    let context = sender
        .client
        .account_db()?
        .client_record("conversation", &message.conversation_id)?
        .ok_or("first DM context")?;
    assert_eq!(
        context["participant_roots"],
        serde_json::json!([
            sender.manifest.principal_commitment,
            target.manifest.principal_commitment
        ]),
        "authored capture must bind the verified immutable root pair"
    );
    assert!(
        !sender.client.friend_link_peer_is_accepted(&target.manifest.principal_commitment)?,
        "creating local root context must not grant contact consent"
    );
    let sealed =
        sender.client.seal_routed_as(engine, &message, &prepared.wire, Route::direct()).await?;
    let envelope = crate::dm::gateway_envelope_from_sealed(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&sender.config)?,
        &mut message,
        sealed,
        None,
    )?;
    let entry = GatewayInboxEntry {
        envelope,
        forwarded: false,
        inbox_seq: 2,
        target_delivery_id: target.config.target_delivery_id.clone(),
    };
    let opened = target.client.open_routed(&entry, &target.config.device_id)?;
    assert_eq!(
        opened.body.as_slice(),
        prepared.exact,
        "request bootstrap must preserve the first ordinary generated DM"
    );
    Ok(())
}
