// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy compatibility receive quarantines one bad entry and still delivers the next.
use super::*;
#[tokio::test(flavor = "current_thread")]
async fn a_rejected_legacy_group_entry_does_not_block_read_or_receive_of_valid_messages()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture()?;
    let mut bad = good.clone();
    bad.inbox_seq = 1;
    bad.envelope.envelope_id = "bad".into();
    bad.envelope.signed.signature = "invalid".into();
    for entry in [&bad, &good] {
        receiver.client.account_db()?.hold_unrouted(
            &receiver.client.inbox_admission_key(entry)?,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
    }
    for method in ["group.receive", "group.read"] {
        let request = LocalBusFrame::request(
            method,
            Some("bob".into()),
            "group",
            method,
            serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
        );
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver)
            .await?;
    }
    assert!(receiver.client.direct_message_by_id("bad")?.is_none());
    assert!(
        receiver.client.direct_message_by_id("valid")?.is_some(),
        "messages {:?}, journal {}",
        receiver
            .client
            .direct_messages("thread")?
            .iter()
            .map(|m| &m.message_id)
            .collect::<Vec<_>>(),
        serde_json::to_string(&receiver.client.account_db()?.journal_after(0, 128)?)?
    );
    let readers = super::super::readers::AccountReaders::start(receiver.client.account_db()?)?;
    let page = readers
        .request(LocalBusFrame::request(
            "message-read",
            Some("bob".into()),
            "message",
            "message.read",
            serde_json::json!({"conversation_id":"thread"}),
        ))
        .await?;
    readers.stop().await;
    assert_eq!(page["messages"].as_array().map(Vec::len), Some(1));
    assert_eq!(page["messages"][0]["message_id"], "valid");
    assert_eq!(page["messages"][0]["body_utf8"], "valid after rejected");
    assert_eq!(receiver.client.account_db()?.unrouted_entries()?, Vec::<Vec<u8>>::new());
    let journal = serde_json::to_string(&receiver.client.account_db()?.journal_after(0, 128)?)?;
    assert!(journal.contains("schema_invalid"));
    assert!(!journal.contains("valid after rejected"));
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn legacy_group_fixture()
-> Result<(PathBuf, LocalBusAccountState, LocalBusAccountState, GatewayInboxEntry), SdkError> {
    legacy_group_fixture_with_pin(true)
}
fn legacy_group_fixture_with_pin(
    pin: bool,
) -> Result<(PathBuf, LocalBusAccountState, LocalBusAccountState, GatewayInboxEntry), SdkError> {
    let root = root("legacy-group-page");
    let mut sender =
        account(&root.join("sender"), "alice", None, Arc::new(AtomicBool::new(false)))?;
    let receiver = account(&root.join("receiver"), "bob", None, Arc::new(AtomicBool::new(false)))?;
    sender.client.create_identity_root("alice", [0x71; 32]);
    sender.client.create_device_branch("alice", "device-alice", 1, [0x72; 32]);
    sender.client.initialize_and_publish_prekey_bundle(
        "alice",
        "device-alice",
        "target",
        [0x72; 32],
        None,
    )?;
    let d = sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let master = sender.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let commitment = crate::identity_root_public_key_commitment(
        &ramflux_protocol::encode_base64url(master.signing_key.verifying_key().to_bytes()),
    )?;
    receiver.client.account_db()?.persist_client_record("device","device-alice",&serde_json::json!({"principal_id":"alice","principal_commitment":commitment,"x25519_identity_public":sender.client.load_x3dh_private_state(&sender.client.owned_device_identity()?)?.bundle.identity_key,"signing_public_key":ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes())}))?;
    let sender_manifest =
        crate::client::identity_authority::test_support::manifest(&sender.client)?;
    receiver.client.persist_root_verified_directory(&sender_manifest)?;
    receiver.client.initialize_and_publish_prekey_bundle(
        "bob",
        "device-bob",
        "target",
        [0x62; 32],
        None,
    )?;
    let receiver_manifest =
        crate::client::identity_authority::test_support::manifest(&receiver.client)?;
    sender.client.persist_root_verified_directory(&receiver_manifest)?;
    sender.client.create_group("g", "device-alice")?;
    sender.client.add_group_member(
        "g",
        receiver.client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    receiver.client.create_group("g", "device-bob")?;
    if pin {
        receiver.client.add_group_member(
            "g",
            sender.client.owned_device_identity()?.storage_key(),
            "member",
        )?;
        receiver.client.import_group_sender_key_distribution(
            &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
        )?;
    } else {
        receiver.client.account_db()?.upsert_group_local_membership_snapshot(
            "g",
            2,
            64,
            "none",
            "device-bob",
            "owner",
            1,
        )?;
        receiver.client.account_db()?.upsert_group_member_snapshot(
            "g",
            "device-alice",
            "member",
            2,
        )?;
    }
    receiver.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"kind":"group","group_id":"g"}),
    )?;
    let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
        &root.join("sender"),
        "alice",
    ))?;
    let config =
        GatewaySessionConfig::quic(manifest.gateway).with_account_identity(&sender.client)?;
    let encrypted =
        sender.client.encrypt_group_message("g", "device-alice", b"valid after rejected")?;
    let message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "valid".into(),
        envelope_id: "valid".into(),
        source_principal_id: "alice".into(),
        sender_id: "device-alice".into(),
        recipient_device_id: Some("device-bob".into()),
        recipient_principal_commitment: Some(
            receiver.client.owned_device_identity()?.root_commitment().into(),
        ),
        target_delivery_id: "target".into(),
        encrypted_body: encrypted,
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let good = GatewayInboxEntry {
        inbox_seq: 2,
        target_delivery_id: "target".into(),
        envelope: crate::dm::gateway_direct_message_envelope(&config, &message, None)?,
    };
    receiver.client.authenticated_envelope_sender(&good)?;
    if pin {
        receiver.client.require_group_sender_pin(
            "g",
            "alice",
            &sender.client.owned_device_identity()?,
        )?;
    }
    assert!(receiver.client.legacy_group_binding("thread", "g", &good)?);
    Ok((root, sender, receiver, good))
}

use crate::client::group_quarantine::{LegacyGroupDelivery, legacy_key};
#[test]
fn transient_gateway_and_manifest_failures_keep_genuine_legacy_ciphertext_unacknowledged()
-> Result<(), SdkError> {
    let (root, sender, receiver, good) = legacy_group_fixture()?;
    let start = now_unix_timestamp();
    for error in [
        SdkError::GatewaySessionRejected("HTTP 503 or timeout".into()),
        SdkError::LocalBus("missing device manifest".into()),
        SdkError::InboundPending("directory not ready".into()),
    ] {
        assert!(matches!(
            receiver.client.isolate_legacy_group_delivery(&good, Err(error))?,
            LegacyGroupDelivery::Held
        ));
    }
    let db = receiver.client.account_db()?;
    assert!(db.has_inbox_retry(&legacy_key(&good)?)?);
    assert_eq!(db.due_inbox_retries(start + 1)?, Vec::<Vec<u8>>::new());
    assert_eq!(db.unrouted_count()?, 1);
    assert!(!db.journal_after(0, 64)?.iter().any(|e| e.topic == "message.undeliverable"));
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn repeated_group_receives_respect_backoff_and_a_new_pin_redrives_the_genuine_message()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture_with_pin(false)?;
    receiver.client.retain_legacy_group_entry(&good)?;
    let request = LocalBusFrame::request(
        "receive",
        Some("bob".into()),
        "group",
        "group.receive",
        serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
    );
    let start = now_unix_timestamp();
    for _ in 0..4 {
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver)
            .await?;
    }
    let db = receiver.client.account_db()?;
    assert!(db.has_inbox_retry(&legacy_key(&good)?)?);
    assert_eq!(db.due_inbox_retries(start + 1)?, Vec::<Vec<u8>>::new());
    assert_eq!(db.due_inbox_retries(start + 10)?.len(), 1);
    assert!(receiver.client.direct_message_by_id("valid")?.is_none());
    assert!(!db.journal_after(0, 64)?.iter().any(|e| e.topic == "message.undeliverable"));
    receiver.client.pin_joined_group_member("g", "device-alice")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
    )?;
    crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver).await?;
    assert!(receiver.client.direct_message_by_id("valid")?.is_some());
    assert!(!receiver.client.account_db()?.has_inbox_retry(&legacy_key(&good)?)?);
    assert_eq!(receiver.client.account_db()?.unrouted_count()?, 0);
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn forged_sources_and_forged_claims_of_the_real_device_cannot_spend_its_retry_quota()
-> Result<(), SdkError> {
    for (count, same_device) in [(16, false), (2, true)] {
        let (root, sender, mut receiver, good) = legacy_group_fixture_with_pin(false)?;
        let db = receiver.client.account_db()?;
        for index in 0..count {
            let mut forged = good.clone();
            forged.envelope.envelope_id = format!("forged-{index}");
            forged.envelope.signed.signature = "invalid".into();
            if !same_device {
                forged.envelope.source_device_id = format!("claimed-{index}");
                let record = db
                    .client_record("device", "device-alice")?
                    .ok_or(SdkError::IdentityRootMissing)?;
                db.persist_client_record("device", &forged.envelope.source_device_id, &record)?;
            }
            let error = receiver
                .client
                .authenticated_envelope_sender(&forged)
                .err()
                .ok_or(SdkError::IdentityRootMissing)?;
            assert!(matches!(
                receiver.client.isolate_legacy_group_delivery(&forged, Err(error))?,
                LegacyGroupDelivery::Rejected
            ));
        }
        let pending = receiver.client.append_group_gateway_delivery_for_recipient(
            "thread",
            "g",
            "valid",
            &good,
            "device-bob",
        );
        assert!(matches!(
            receiver.client.isolate_legacy_group_delivery(&good, pending)?,
            LegacyGroupDelivery::Held
        ));
        assert!(db.has_inbox_retry(&legacy_key(&good)?)?);
        assert!(
            !db.journal_after(0, 64)?
                .iter()
                .any(|e| e.topic == "message.undeliverable" && e.body["envelope_id"] == "valid")
        );
        receiver.client.pin_joined_group_member("g", "device-alice")?;
        receiver.client.import_group_sender_key_distribution(
            &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
        )?;
        let request = LocalBusFrame::request(
            "receive",
            Some("bob".into()),
            "group",
            "group.receive",
            serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
        );
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver)
            .await?;
        assert!(receiver.client.direct_message_by_id("valid")?.is_some());
        drop(sender);
        drop(receiver);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn exhausted_or_expired_legacy_retries_stay_held_without_terminal_rejection() -> Result<(), SdkError>
{
    let (root, sender, receiver, good) = legacy_group_fixture()?;
    let start = now_unix_timestamp();
    assert!(matches!(
        receiver.client.isolate_legacy_group_delivery(
            &good,
            Err(SdkError::GatewaySessionRejected("temporary failure".into()))
        )?,
        LegacyGroupDelivery::Held
    ));
    let db = receiver.client.account_db()?;
    let key = legacy_key(&good)?;
    let bytes = serde_json::to_vec(&good)?;
    for retry in 1..8 {
        assert_ne!(db.defer_inbox_entry(&key, &bytes, start + retry * 64)?, 0);
    }
    assert_eq!(db.defer_inbox_entry(&key, &bytes, start + 512)?, 0);
    db.park_legacy_inbox_retry(&key)?;
    db.expire_inbox_holds(start + 601)?;
    assert_eq!(db.unrouted_count()?, 1);
    assert!(!db.has_inbox_retry(&key)?);
    assert!(db.legacy_inbox_parked(&key)?);
    assert_eq!(db.due_inbox_retries(start + 602)?, Vec::<Vec<u8>>::new());
    assert!(!db.journal_after(0, 64)?.iter().any(|e| e.topic == "message.undeliverable"));
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn gateway_receipt_replays_share_one_legacy_retry_key_but_forged_signatures_do_not()
-> Result<(), SdkError> {
    let (root, sender, receiver, mut original) = legacy_group_fixture()?;
    original.envelope.ext.ext.insert("franking".into(), serde_json::json!({}));
    original.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::signed_bytes(&original.envelope)?,
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
    );
    let mut replay = original.clone();
    replay.envelope.ext.ext.insert(
        "franking".into(),
        serde_json::json!({"franking_tag":"receipt","node_id":"gateway","accepted_at":123}),
    );
    receiver.client.authenticated_envelope_sender(&original)?;
    receiver.client.authenticated_envelope_sender(&replay)?;
    assert_eq!(legacy_key(&original)?, legacy_key(&replay)?);
    replay.envelope.signed.signature = "forged".into();
    assert_ne!(legacy_key(&original)?, legacy_key(&replay)?);
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn gateway_tcp_tls_503_during_first_contact_is_backed_off_without_acking_the_group_message()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture()?;
    let db = receiver.client.account_db()?;
    let mut record =
        db.client_record("device", "device-alice")?.ok_or(SdkError::IdentityRootMissing)?;
    let complete_record = record.clone();
    record.as_object_mut().ok_or(SdkError::IdentityRootMissing)?.remove("x25519_identity_public");
    db.persist_client_record("device", "device-alice", &record)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["lookup.test".into()])
        .map_err(|e| SdkError::LocalBus(e.to_string()))?;
    let ca = root.join("lookup-ca.pem");
    std::fs::write(&ca, certified.cert.pem())?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )
        .map_err(|e| SdkError::LocalBus(e.to_string()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        while let Ok((socket, _)) = listener.accept().await {
            let stream = tokio_rustls::TlsStream::Server(acceptor.accept(socket).await?);
            let (mut receive, mut send) = tokio::io::split(stream);
            let request: ramflux_transport::GatewayQuicRequest =
                ramflux_transport::read_gateway_session_json(&mut receive).await?;
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/mvp1/prekey/device-alice");
            observed.fetch_add(1, Ordering::SeqCst);
            ramflux_transport::write_gateway_session_json(
                &mut send,
                &ramflux_transport::GatewayQuicResponse {
                    status: 503,
                    body: serde_json::json!({"error":"unavailable"}),
                },
            )
            .await?;
        }
        Ok::<(), SdkError>(())
    });
    let mut engine = receiver.take_live_engine().await?;
    engine.config.transport_kind = GatewaySessionTransportKind::TcpTls;
    engine.config.tcp_gateway_addr = Some(address);
    engine.config.server_name = "lookup.test".into();
    engine.config.ca_cert = ca;
    receiver.put_engine(engine);
    receiver.client.retain_legacy_group_entry(&good)?;
    let request = LocalBusFrame::request(
        "receive",
        Some("bob".into()),
        "group",
        "group.receive",
        serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
    );
    for _ in 0..4 {
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver)
            .await?;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(receiver.client.account_db()?.has_inbox_retry(&legacy_key(&good)?)?);
    assert_eq!(receiver.client.account_db()?.unrouted_count()?, 1);
    assert!(receiver.client.direct_message_by_id("valid")?.is_none());
    assert!(
        !receiver
            .client
            .account_db()?
            .journal_after(0, 64)?
            .iter()
            .any(|e| e.topic == "message.undeliverable")
    );
    receiver.client.account_db()?.persist_client_record(
        "device",
        "device-alice",
        &complete_record,
    )?;
    crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver).await?;
    assert!(receiver.client.direct_message_by_id("valid")?.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
    let _ = server.await;
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn fresh_legacy_delivery_can_complete_even_when_its_sources_retry_slots_are_full()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture_with_pin(false)?;
    for index in 0..8 {
        let mut held = good.clone();
        held.inbox_seq = 10 + index;
        held.envelope.envelope_id = format!("held-{index}");
        held.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::signed_bytes(&held.envelope)?,
            sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        );
        let result = receiver.client.append_group_gateway_delivery_for_recipient(
            "thread",
            "g",
            &held.envelope.envelope_id,
            &held,
            "device-bob",
        );
        assert!(matches!(
            receiver.client.isolate_legacy_group_delivery(&held, result)?,
            LegacyGroupDelivery::Held
        ));
    }
    receiver.client.pin_joined_group_member("g", "device-alice")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
    )?;
    receiver.client.retain_legacy_group_entry(&good)?;
    let request = LocalBusFrame::request(
        "receive",
        Some("bob".into()),
        "group",
        "group.receive",
        serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
    );
    crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver).await?;
    assert!(receiver.client.direct_message_by_id("valid")?.is_some());
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn a_verified_pin_arrival_repairs_legacy_delivery_after_its_network_retry_budget_is_exhausted()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture_with_pin(false)?;
    let pending = receiver.client.append_group_gateway_delivery_for_recipient(
        "thread",
        "g",
        "valid",
        &good,
        "device-bob",
    );
    assert!(matches!(
        receiver.client.isolate_legacy_group_delivery(&good, pending)?,
        LegacyGroupDelivery::Held
    ));
    let key = legacy_key(&good)?;
    let now = now_unix_timestamp();
    let bytes = serde_json::to_vec(&good)?;
    for retry in 1..8 {
        assert_ne!(
            receiver.client.account_db()?.defer_inbox_entry(&key, &bytes, now + retry * 64)?,
            0
        );
    }
    receiver.client.account_db()?.park_legacy_inbox_retry(&key)?;
    receiver.client.pin_joined_group_member("g", "device-alice")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
    )?;
    let request = LocalBusFrame::request(
        "receive",
        Some("bob".into()),
        "group",
        "group.receive",
        serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
    );
    crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver).await?;
    assert!(receiver.client.direct_message_by_id("valid")?.is_some());
    assert!(!receiver.client.account_db()?.has_inbox_retry(&key)?);
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn a_legacy_failure_without_a_retry_slot_cannot_reenter_as_a_fresh_delivery() -> Result<(), SdkError>
{
    let (root, sender, receiver, good) = legacy_group_fixture_with_pin(false)?;
    let db = receiver.client.account_db()?;
    let now = now_unix_timestamp();
    for index in 0..64 {
        let key = format!("occupied-{index}");
        let identity = receiver.client.owned_account_device_identity(&key)?;
        assert!(db.set_verified_inbox_failure_policy(
            &key,
            b"{}",
            ramflux_storage::InboxFailurePolicy {
                verified_source: Some(&identity),
                trusted: true,
                dependency: ("none", ""),
                at: now,
            }
        )?);
        assert_eq!(db.defer_inbox_entry(&key, b"{}", now)?, 1);
    }
    let pending = receiver.client.append_group_gateway_delivery_for_recipient(
        "thread",
        "g",
        "valid",
        &good,
        "device-bob",
    );
    assert!(matches!(
        receiver.client.isolate_legacy_group_delivery(&good, pending)?,
        LegacyGroupDelivery::Held
    ));
    let key = legacy_key(&good)?;
    assert!(!db.has_inbox_retry(&key)?);
    for _ in 0..4 {
        assert!(!receiver.client.legacy_group_retry_ready(&good)?);
    }
    assert!(!db.has_inbox_retry(&key)?);
    db.remove_inbox_retry("occupied-0")?;
    assert!(!receiver.client.legacy_group_retry_ready(&good)?);
    assert!(!db.has_inbox_retry(&key)?);
    assert!(db.legacy_inbox_parked(&key)?);
    receiver.client.pin_joined_group_member("g", "device-alice")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
    )?;
    assert!(receiver.client.legacy_group_retry_ready(&good)?);
    assert!(!db.has_inbox_retry(&key)?);
    assert!(!db.journal_after(0, 64)?.iter().any(|event| event.topic == "message.undeliverable"));
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn held_legacy_group_messages_emit_one_metadata_only_unrouted_journal_event()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture_with_pin(false)?;
    receiver.client.account_db()?.hold_unrouted(
        &legacy_key(&good)?,
        good.inbox_seq,
        &serde_json::to_vec(&good)?,
        now_unix_timestamp(),
    )?;
    crate::bus::sync_driver::run(&mut receiver).await?;
    crate::bus::sync_driver::run(&mut receiver).await?;
    let rows = receiver.client.account_db()?.journal_after(0, 64)?;
    let held = rows.iter().filter(|e| e.topic == "message.unrouted").collect::<Vec<_>>();
    assert_eq!(held.len(), 1);
    let body = serde_json::to_string(&held[0])?;
    assert!(body.contains("legacy_group"));
    assert!(!body.contains("valid after rejected"));
    assert!(!body.contains(&good.envelope.encrypted_payload));
    assert!(receiver.client.direct_message_by_id("valid")?.is_none());
    assert_eq!(receiver.client.account_db()?.unrouted_count()?, 1);
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
