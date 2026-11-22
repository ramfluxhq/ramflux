// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Auxiliary copies never take availability from primary sends or precede their confirmation.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    source: LocalBusAccountState,
    sibling: LocalBusAccountState,
    config: GatewaySessionConfig,
    receiver: GatewaySessionConfig,
    directory: tokio::task::JoinHandle<()>,
    _root: ramflux_test_support::TestPath,
}
impl Fixture {
    async fn new(name: &str) -> TestResult<Self> {
        let root = runtime_tests::root(name);
        let mut source = runtime_tests::account(
            &root.join("source"),
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let (sibling, config, receiver, directory) =
            super::own_tests::sibling_fixture(&root, &mut source).await?;
        Ok(Self { source, sibling, config, receiver, directory, _root: root })
    }
    fn message(&self, id: &str) -> TestResult<GatewayDirectMessage> {
        Ok(GatewayDirectMessage {
            conversation_id: super::dm_tests::conversation(&self.source.client)?,
            message_id: id.into(),
            envelope_id: format!("env-{id}"),
            source_principal_id: "sender".into(),
            sender_id: "device-sender".into(),
            recipient_device_id: Some("device-peer-one".into()),
            recipient_principal_commitment: self
                .source
                .client
                .account_db()?
                .client_record("identity", "peer")?
                .and_then(|row| row["contact_identity_commitment"].as_str().map(str::to_owned)),
            target_delivery_id: self
                .source
                .client
                .account_db()?
                .client_record("identity", "peer")?
                .and_then(|row| row["contact_identity_commitment"].as_str().map(str::to_owned))
                .map(|root| {
                    self.source
                        .client
                        .device_identity_for_root(&root, "device-peer-one")
                        .map(|identity| identity.storage_key().to_owned())
                })
                .transpose()?
                .ok_or("certified peer target")?,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 300,
        })
    }
    fn cleanup(self) {
        self.directory.abort();
        drop(self);
    }
    fn assert_failed_copy(&self, message: &str) -> TestResult {
        assert_eq!(
            self.source
                .client
                .account_db()?
                .client_record("message", message)?
                .ok_or("copy status")?["own_device_copy_state"],
            "failed"
        );
        assert_eq!(
            self.source.client.account_db()?.load_actor_state::<u64>("own-device/sent-failures")?,
            Some(1)
        );
        Ok(())
    }
}
#[tokio::test]
async fn a_full_copy_queue_does_not_fail_the_real_dm_or_group_send() -> TestResult {
    let mut f = Fixture::new("own-copy-capacity").await?;
    let captured = Arc::default();
    let mut engine = GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::clone(&captured))),
    );
    let (seed, _) = f
        .source
        .client
        .send_generated_content_via_gateway(
            &mut engine,
            f.message("capacity-seed")?,
            &text_content("seed"),
        )
        .await?;
    f.source.client.stage_authored_history()?;
    let db = f.source.client.account_db()?;
    let key = db
        .actor_state_key_page("own-history/pending/", 1)?
        .into_iter()
        .next()
        .ok_or("seed own work")?;
    let work: Value = db.load_actor_state(&key)?.ok_or("seed own work")?;
    db.write_transaction(|| -> Result<(), SdkError> {
        for n in 1..256 {
            let mut queued = work.clone();
            queued["binding"] = json!(format!("capacity-binding-{n}"));
            db.persist_message_actor_state(
                &seed,
                &format!("own-history/pending/capacity-{n:03}"),
                &queued,
            )?;
        }
        Ok(())
    })?;
    let (primary, _) = f
        .source
        .client
        .send_generated_content_via_gateway(
            &mut engine,
            f.message("primary")?,
            &text_content("primary body"),
        )
        .await?;
    assert_eq!(
        f.source
            .client
            .generated_message_detail(&super::dm_tests::conversation(&f.source.client)?, &primary)?
            .message
            .text
            .as_deref(),
        Some("primary body")
    );
    f.source.install_test_session(engine);
    f.source.client.fixture_group_create(
        "capacity-group",
        "capacity-thread",
        None,
        "device-sender",
    )?;
    let request = LocalBusFrame::request(
        "group",
        Some("sender".into()),
        "group",
        "group.send",
        json!({
            "group_id":"capacity-group", "conversation_id":"capacity-thread", "message_id":"group-primary", "sender_id":"device-sender", "encrypted_body_base64":"", "plaintext_body_base64":ramflux_protocol::encode_base64url(b"group body")
        }),
    );
    let result = super::super::group::dispatch_group_send_request(&request, &mut f.source).await?;
    let group_id = result.response_body["message_id"].as_str().ok_or("allocated group id")?;
    assert_eq!(
        f.source
            .client
            .generated_message_detail("capacity-thread", group_id)?
            .message
            .text
            .as_deref(),
        Some("group body")
    );
    f.source.client.stage_authored_history()?;
    assert_eq!(
        f.source.client.account_db()?.actor_state_usage("own-history/pending/")?.0,
        256,
        "own-history backpressure never rolls back either primary producer"
    );
    assert_eq!(
        captured.lock().map_err(|_| "captured")?.len(),
        2,
        "both direct primary submits completed"
    );
    f.cleanup();
    Ok(())
}

fn text_content(text: &str) -> ramflux_protocol::message::Content {
    use ramflux_protocol::message as g;
    g::Content {
        value: Some(g::content::Value::Message(g::Message {
            text: text.into(),
            ..Default::default()
        })),
    }
}

#[tokio::test]
async fn an_oversized_copy_payload_cannot_roll_back_primary_storage_or_submission() -> TestResult {
    let f = Fixture::new("own-copy-size").await?;
    let captured = Arc::default();
    let mut engine = GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::clone(&captured))),
    );
    let mut message = f.message("large")?;
    let prepared = f.source.client.prepare_authored_content(
        &mut message,
        None,
        &text_content("primary body"),
    )?;
    let sealed = f
        .source
        .client
        .seal_routed_as(
            &mut engine,
            &message,
            &prepared.wire,
            crate::client::routed::Route::direct(),
        )
        .await?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    // Exercise oversize admission independently of the primary frame budget: metadata expansion
    // can make a replica too large even when its already sealed primary fits the transport.
    let copy_body = vec![b'x'; crate::client::own_device_copy::MAX_PACKET_BYTES];
    f.source.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
        f.source.client.send_direct_message(
            "thread",
            "large",
            "device-sender",
            &message.encrypted_body,
        )?;
        f.source.client.account_db()?.store_message_content("thread", "large", b"primary body")?;
        let ticket = f.source.client.queue_own_sent_copy("large", || {
            f.source.client.stage_own_sent_message(
                crate::client::own_sent_message::OwnSentInput {
                    envelope: &message.envelope_id,
                    conversation: "thread",
                    message: "large",
                    sender: "device-sender",
                    original_recipients: &[],
                    group: None,
                    peer: Some("peer"),
                    body: &copy_body,
                    ciphertext: &message.encrypted_body,
                    at: now_unix_timestamp(),
                },
            )?;
            Ok(message.envelope_id.clone())
        });
        assert!(ticket.is_none());
        Ok(())
    })?;
    engine
        .submit_envelope(crate::dm::gateway_generated_envelope_from_sealed(
            &engine.sealing_config()?,
            &mut message,
            sealed,
        )?)
        .await?;
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    assert_eq!(
        f.source.client.account_db()?.message_content("large")?,
        Some(b"primary body".to_vec())
    );
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.assert_failed_copy("large")?;
    f.cleanup();
    Ok(())
}

#[tokio::test]
async fn missing_group_or_peer_copy_context_cannot_roll_back_a_primary_transaction() -> TestResult {
    for group in [false, true] {
        let f =
            Fixture::new(if group { "own-copy-missing-group" } else { "own-copy-missing-peer" })
                .await?;
        f.source.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            f.source.client.send_direct_message(
                "thread",
                "primary",
                "device-sender",
                b"primary ciphertext",
            )?;
            f.source.client.account_db()?.store_message_content(
                "thread",
                "primary",
                b"primary body",
            )?;
            let ticket = f.source.client.queue_own_sent_copy("primary", || {
                if !group {
                    let mut missing =
                        f.message("primary").map_err(|_| SdkError::IdentityRootMissing)?;
                    missing.recipient_device_id = Some("absent-device".into());
                    f.source.client.own_sent_peer(&missing)?;
                }
                f.source.client.stage_own_sent_message(
                    crate::client::own_sent_message::OwnSentInput {
                        envelope: "primary-env",
                        conversation: "thread",
                        message: "primary",
                        sender: "device-sender",
                        original_recipients: &[],
                        group: Some("missing-group"),
                        peer: None,
                        body: b"primary body",
                        ciphertext: b"primary ciphertext",
                        at: now_unix_timestamp(),
                    },
                )?;
                Ok("primary-env".into())
            });
            assert!(ticket.is_none());
            Ok(())
        })?;
        assert!(f.source.client.direct_message_by_id("primary")?.is_some());
        assert_eq!(
            f.source.client.account_db()?.message_content("primary")?,
            Some(b"primary body".to_vec())
        );
        assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
        f.assert_failed_copy("primary")?;
        f.cleanup();
    }
    Ok(())
}
#[tokio::test]
async fn held_copies_are_never_couriered_before_confirmation_and_failed_submissions_discard_them()
-> TestResult {
    let mut f = Fixture::new("own-copy-held").await?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    f.source.install_test_session(GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(gateway),
    ));
    for (id, confirmed) in [("discard", false), ("release", true)] {
        let mut message = f.message(id)?;
        let prepared = f.source.client.prepare_authored_content(
            &mut message,
            None,
            &text_content("held body"),
        )?;
        f.source.client.send_direct_message(
            &message.conversation_id,
            &message.message_id,
            "device-sender",
            b"cipher",
        )?;
        f.source.client.stage_own_sent_message(crate::client::own_sent_message::OwnSentInput {
            envelope: id,
            conversation: &message.conversation_id,
            message: &message.message_id,
            sender: "device-sender",
            original_recipients: &[],
            group: None,
            peer: Some("peer"),
            body: &prepared.exact,
            ciphertext: b"cipher",
            at: now_unix_timestamp(),
        })?;
        assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
        assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
        f.source.client.finish_own_sent_copy(&message.message_id, Some(id), confirmed);
        assert_eq!(
            crate::bus::own_device_copy::flush(&mut f.source).await?,
            usize::from(confirmed)
        );
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.cleanup();
    Ok(())
}
#[tokio::test]
async fn a_rejected_primary_dm_discards_its_staged_copy() -> TestResult {
    let mut f = Fixture::new("own-copy-reject").await?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.fail_after = Some(0);
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    let result = f
        .source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            f.message("rejected")?,
            b"not accepted",
        )
        .await;
    assert!(result.is_err());
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.source.install_test_session(engine);
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    f.cleanup();
    Ok(())
}
fn refused_group_event(client: &crate::RamfluxClient, conversation: &str) -> TestResult<String> {
    let rows = client.direct_messages(conversation)?;
    let mut authored = None;
    let mut service_rows = 0_u32;
    for row in &rows {
        let detail = client.generated_message_detail(conversation, &row.message_id)?;
        if detail.message.kind == "service" {
            service_rows = service_rows.saturating_add(1);
            continue;
        }
        if detail.message.text.as_deref() == Some("not accepted") {
            authored = Some(row.message_id.clone());
        }
    }
    assert!(service_rows >= 1, "accepted group changes stay beside the refused send");
    authored.ok_or("allocated rejected group message".into())
}
#[tokio::test]
async fn a_rejected_primary_group_preserves_its_allocated_event_for_retry() -> TestResult {
    let mut f = Fixture::new("own-copy-group-reject").await?;
    f.source.client.fixture_group_create(
        "group-reject",
        "rejected-group-thread",
        None,
        "device-sender",
    )?;
    let peer = f.source.client.account_db()?.client_record("identity", "peer")?.ok_or("peer")?;
    f.source
        .client
        .cache_verified_device_manifest(
            &f.config,
            peer["contact_identity_commitment"].as_str().ok_or("peer root")?,
            "rejected_group_fixture",
        )
        .await?;
    let peer_ref = f.source.client.device_identity_for_root(
        peer["contact_identity_commitment"].as_str().ok_or("peer root")?,
        "device-peer-one",
    )?;
    let record = f
        .source
        .client
        .trusted_device(crate::client::identity_authority::HeadUse::NewAuthorization, &peer_ref)?;
    f.source.client.fixture_group_change(
        "group-reject",
        "device-sender",
        ramflux_protocol::GroupStateChange::Add {
            member: ramflux_protocol::group_state::GroupMemberIdentity {
                principal_id: "peer".into(),
                root_commitment: peer_ref.root_commitment().into(),
                device_id: peer_ref.device_id().into(),
                signing_public_key: record["signing_public_key"]
                    .as_str()
                    .ok_or("peer signing key")?
                    .into(),
                target_delivery_id: record["target_delivery_id"]
                    .as_str()
                    .ok_or("peer target")?
                    .into(),
            },
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.fail_after = Some(0);
    let own = Arc::clone(&gateway.own);
    f.source.install_test_session(GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(gateway),
    ));
    let request = LocalBusFrame::request(
        "reject-group",
        Some("sender".into()),
        "group",
        "group.send",
        json!({"group_id":"group-reject","conversation_id":"rejected-group-thread",
            "message_id":"rejected-group","sender_id":"device-sender",
            "encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"not accepted")}),
    );
    let result = super::super::group::dispatch_group_send_request(&request, &mut f.source).await;
    let error = result.err().ok_or("group send unexpectedly succeeded")?;
    assert!(error.to_string().contains("injected submit failure"), "{error}");
    let id = refused_group_event(&f.source.client, "rejected-group-thread")?;
    assert_eq!(
        f.source
            .client
            .generated_message_detail("rejected-group-thread", &id)?
            .message
            .text
            .as_deref(),
        Some("not accepted"),
        "primary failure preserves the exact authored event for retry"
    );
    assert_eq!(
        f.source.client.account_db()?.load_actor_state::<u64>("own-device/sent-failures")?,
        None
    );
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty());
    f.cleanup();
    Ok(())
}
#[tokio::test]
async fn offline_authored_dates_do_not_expire_freshly_staged_live_copies() -> TestResult {
    let mut f = Fixture::new("own-copy-offline-date").await?;
    let mut message = f.message("offline")?;
    message.created_at -= 3600;
    message.ttl = 7200;
    let authored = message.created_at;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    f.source
        .client
        .send_plaintext_direct_message_via_gateway(&mut engine, message, b"composed offline")
        .await?;
    f.source.install_test_session(engine);
    crate::bus::couriers::authored_history::drive_once(&mut f.source).await?;
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    crate::client::native_test_support::bus::receive_copy(
        &mut f.sibling.client,
        &f.receiver,
        &GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        },
    )
    .await?;
    let rows =
        f.sibling.client.direct_messages(&super::dm_tests::conversation(&f.source.client)?)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].created_at, authored);
    f.cleanup();
    Ok(())
}
#[tokio::test]
async fn multiple_plain_copies_reuse_local_membership_without_gateway_manifest_requests()
-> TestResult {
    let mut f = Fixture::new("own-copy-cached").await?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    for id in ["first", "second"] {
        f.source
            .client
            .send_plaintext_direct_message_via_gateway(&mut engine, f.message(id)?, b"cached copy")
            .await?;
    }
    f.source.install_test_session(engine);
    f.directory.abort();
    let _ = (&mut f.directory).await;
    for _ in 0..2 {
        crate::bus::couriers::authored_history::drive_once(&mut f.source).await?;
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 2);
    assert!(
        f.source
            .client
            .account_db()?
            .load_actor_state::<serde_json::Value>("own-device/manifest-refresh")?
            .is_none()
    );
    f.cleanup();
    Ok(())
}

fn revoke_sibling(f: &mut Fixture) -> TestResult {
    crate::client::native_test_support::bus::revoke_device(&mut f.source, "device-sibling")
}
#[tokio::test]
async fn a_single_active_device_sends_without_any_copy_state_writes_or_manifest_fetch() -> TestResult
{
    let mut f = Fixture::new("own-copy-no-siblings").await?;
    revoke_sibling(&mut f)?;
    let before = f.source.client.account_db()?.actor_state_usage("own-device/")?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    for id in ["single-one", "single-two"] {
        f.source
            .client
            .send_plaintext_direct_message_via_gateway(
                &mut engine,
                f.message(id)?,
                b"single device",
            )
            .await?;
    }
    f.source.install_test_session(engine);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/")?, before);
    assert!(f.source.client.account_db()?.client_record("message", "single-one")?.is_none());
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert_eq!(
        usize::from(crate::bus::couriers::authored_history::drive_once(&mut f.source).await?),
        0
    );
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    f.cleanup();
    Ok(())
}
#[tokio::test]
async fn a_device_set_change_invalidates_membership_before_preparing_queued_copies() -> TestResult {
    let mut f = Fixture::new("own-copy-membership-change").await?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    f.source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            f.message("before-revocation")?,
            b"queued",
        )
        .await?;
    f.source.install_test_session(engine);
    f.source.client.stage_authored_history()?;
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-history/pending/")?.0, 1);
    revoke_sibling(&mut f)?;
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert_eq!(
        usize::from(crate::bus::couriers::authored_history::drive_once(&mut f.source).await?),
        0
    );
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-history/pending/")?.0, 0);
    f.cleanup();
    Ok(())
}

#[tokio::test]
async fn removing_retired_manifest_cache_does_not_block_native_authored_history() -> TestResult {
    let mut f = Fixture::new("own-copy-native-cached").await?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = gateway.own.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
    f.source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            f.message("refresh")?,
            b"already submitted",
        )
        .await?;
    f.source.install_test_session(engine);
    f.source
        .client
        .account_db()?
        .remove_actor_state(&format!("identity/manifest-root/{}", f.source.principal_commitment))?;
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert!(
        crate::bus::couriers::authored_history::drive_once(&mut f.source).await?,
        "current native pins authorize the already paired sibling"
    );
    assert_eq!(own.lock().map_err(|_| "own packets")?.len(), 1);
    assert!(
        !f.source.client.account_db()?.actor_state_exists("own-device/manifest-refresh")?,
        "native history does not enter the retired directory refresh path"
    );
    f.cleanup();
    Ok(())
}

#[tokio::test]
async fn untyped_plain_copy_intents_are_refused_without_any_submission() -> TestResult {
    let mut f = Fixture::new("own-copy-legacy-unconfirmed").await?;
    f.source.client.send_direct_message("thread", "legacy", "device-sender", b"cipher")?;
    f.source.client.stage_own_sent_message(crate::client::own_sent_message::OwnSentInput {
        envelope: "legacy",
        conversation: "thread",
        message: "legacy",
        sender: "device-sender",
        original_recipients: &[],
        group: None,
        peer: Some("peer"),
        body: b"legacy body",
        ciphertext: b"cipher",
        at: now_unix_timestamp(),
    })?;
    let db = f.source.client.account_db()?;
    let key = db.actor_state_key_page("own-device/send/", 1)?.into_iter().next().ok_or("intent")?;
    let mut work: serde_json::Value = db.load_actor_state(&key)?.ok_or("work")?;
    let fields = work.as_object_mut().ok_or("fields")?;
    fields.remove("held");
    fields.remove("local_manifest");
    db.persist_actor_state(&key, &work)?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    f.source.install_test_session(GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(gateway),
    ));
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    assert!(f.source.client.direct_message_by_id("legacy")?.is_some());
    let retained = f.source.client.account_db()?.list_actor_states::<Value>("own-device/send/")?;
    assert_eq!(
        retained.first().ok_or("refused work")?["attempts"],
        1,
        "invalid generated payload is charged and retained for bounded failure handling"
    );
    assert_eq!(
        crate::bus::own_device_copy::flush(&mut f.source).await?,
        0,
        "backoff prevents an immediate malformed retry"
    );
    assert!(own.lock().map_err(|_| "own packets")?.is_empty());
    f.cleanup();
    Ok(())
}

#[tokio::test]
async fn deleting_a_sent_message_erases_held_and_prepared_copy_work() -> TestResult {
    for prepared in [false, true] {
        let mut f = Fixture::new("own-copy-delete-work").await?;
        let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
        gateway.fail_own_ack = true;
        let own = gateway.own.clone();
        let mut engine =
            GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway));
        let conversation = super::dm_tests::conversation(&f.source.client)?;
        let (id, _) = f
            .source
            .client
            .send_generated_content_via_gateway(
                &mut engine,
                f.message("delete-copy-message")?,
                &text_content("private queued sent text"),
            )
            .await?;
        f.source.install_test_session(engine);
        f.source.client.stage_authored_history()?;
        if prepared {
            assert!(
                crate::bus::couriers::authored_history::drive_once(&mut f.source).await.is_err(),
                "uncertain own ACK retains the exact signed packet"
            );
            let work =
                f.source.client.account_db()?.list_actor_states::<Value>("own-history/pending/")?;
            assert_eq!(work.len(), 1);
            assert!(!work.first().ok_or("prepared history")?["envelope"].is_null());
        }
        assert_eq!(f.source.client.account_db()?.actor_state_usage("own-history/pending/")?.0, 1);
        f.source.client.delete_direct_message(
            &conversation,
            &id,
            "local",
            &ramflux_protocol::encode_base64url([69; 32]),
        )?;
        assert_eq!(f.source.client.account_db()?.actor_state_usage("own-history/pending/")?.0, 0);
        assert!(
            !f.source
                .client
                .account_db()?
                .actor_state_exists(&format!("own-history/capture/{id}"))?
        );
        let deleted = f.source.client.direct_message_by_id(&id)?.ok_or("deleted message")?;
        assert!(
            deleted.deleted && deleted.is_own,
            "local tombstone retains only the outgoing projection fence"
        );
        assert!(f.source.client.account_db()?.message_content(&id)?.is_none());
        let sent_before = own.lock().map_err(|_| "own packets")?.len();
        assert!(
            !crate::bus::couriers::authored_history::drive_once(&mut f.source).await?,
            "erasure prevents held and prepared history resurrection"
        );
        assert_eq!(own.lock().map_err(|_| "own packets")?.len(), sent_before);
        f.cleanup();
    }
    Ok(())
}
