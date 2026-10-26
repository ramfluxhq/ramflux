// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Auxiliary copies never take availability from primary sends or precede their confirmation.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    root: PathBuf,
    source: LocalBusAccountState,
    sibling: LocalBusAccountState,
    config: GatewaySessionConfig,
    receiver: GatewaySessionConfig,
    directory: tokio::task::JoinHandle<()>,
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
        Ok(Self { root, source, sibling, config, receiver, directory })
    }
    fn message(&self, id: &str) -> TestResult<GatewayDirectMessage> {
        Ok(GatewayDirectMessage {
            conversation_id: "thread".into(),
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
            target_delivery_id: "device-peer-one".into(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 300,
        })
    }
    fn cleanup(self) -> TestResult {
        self.directory.abort();
        let root = self.root;
        drop((self.source, self.sibling));
        std::fs::remove_dir_all(root)?;
        Ok(())
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
    f.source.client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
        for n in 0..256 {
            crate::bus::own_device_copy::stage(
                &f.source.client,
                crate::client::own_device_copy::OwnMessageInput {
                    id: &format!("blocked-{n}"),
                    created_at: now_unix_timestamp(),
                    conversation: "blocked",
                    group: None,
                    body: b"pending",
                },
                None,
            )?;
        }
        Ok(())
    })?;
    let captured = Arc::default();
    let mut engine = GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::clone(&captured))),
    );
    f.source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            f.message("primary")?,
            b"primary body",
        )
        .await?;
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    assert_eq!(
        f.source.client.account_db()?.message_content("primary")?,
        Some(b"primary body".to_vec())
    );
    f.assert_failed_copy("primary")?;
    f.source.put_engine(engine);
    f.source.client.create_group("group", "device-sender")?;
    let request = LocalBusFrame::request(
        "group",
        Some("sender".into()),
        "group",
        "group.send",
        json!({"group_id":"group","conversation_id":"group-thread","message_id":"group-primary","sender_id":"device-sender","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"group body")}),
    );
    super::super::group::dispatch_group_send_request(&request, &mut f.source).await?;
    assert_eq!(
        f.source.client.account_db()?.message_content("group-primary")?,
        Some(b"group body".to_vec())
    );
    assert_eq!(
        f.source
            .client
            .account_db()?
            .client_record("message", "group-primary")?
            .ok_or("group status")?["own_device_copy_state"],
        "failed"
    );
    assert_eq!(
        f.source.client.account_db()?.load_actor_state::<u64>("own-device/sent-failures")?,
        Some(2)
    );
    f.cleanup()
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
    let sealed = f
        .source
        .client
        .seal_routed_as(
            &mut engine,
            &message,
            b"primary body",
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
        .submit_envelope(gateway_direct_message_envelope(&engine.config, &message, None)?)
        .await?;
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    assert_eq!(
        f.source.client.account_db()?.message_content("large")?,
        Some(b"primary body".to_vec())
    );
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.assert_failed_copy("large")?;
    f.cleanup()
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
        f.cleanup()?;
    }
    Ok(())
}
#[tokio::test]
async fn held_copies_are_never_couriered_before_confirmation_and_failed_submissions_discard_them()
-> TestResult {
    let mut f = Fixture::new("own-copy-held").await?;
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    f.source
        .put_engine(GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway)));
    for (id, confirmed) in [("discard", false), ("release", true)] {
        f.source.client.send_direct_message("thread", id, "device-sender", b"cipher")?;
        f.source.client.stage_own_sent_message(crate::client::own_sent_message::OwnSentInput {
            envelope: id,
            conversation: "thread",
            message: id,
            sender: "device-sender",
            original_recipients: &[],
            group: None,
            peer: Some("peer"),
            body: b"held body",
            ciphertext: b"cipher",
            at: now_unix_timestamp(),
        })?;
        assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
        assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
        f.source.client.finish_own_sent_copy(id, Some(id), confirmed);
        assert_eq!(
            crate::bus::own_device_copy::flush(&mut f.source).await?,
            usize::from(confirmed)
        );
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.cleanup()
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
    f.source.put_engine(engine);
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    f.cleanup()
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
    f.source.put_engine(engine);
    crate::bus::own_device_copy::flush(&mut f.source).await?;
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    f.sibling
        .client
        .receive_own_device_message(
            &f.receiver,
            &GatewayInboxEntry { inbox_seq: 1, target_delivery_id: "sibling".into(), envelope },
        )
        .await?;
    let rows = f.sibling.client.direct_messages("thread")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].created_at, authored);
    f.cleanup()
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
    f.source.put_engine(engine);
    f.directory.abort();
    let _ = (&mut f.directory).await;
    for _ in 0..2 {
        crate::bus::own_device_copy::flush(&mut f.source).await?;
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 2);
    assert!(
        f.source
            .client
            .account_db()?
            .load_actor_state::<serde_json::Value>("own-device/manifest-refresh")?
            .is_none()
    );
    f.cleanup()
}

fn revoke_sibling(f: &Fixture) -> TestResult {
    let mut manifest = f
        .source
        .client
        .account_db()?
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{}",
            f.source.principal_commitment
        ))?
        .ok_or("own manifest")?;
    let old = manifest.signed_device_set.as_ref().ok_or("signed set")?;
    let mut devices = old.devices.clone();
    for device in &mut devices {
        if device.device_id == "device-sibling" {
            device.status = ramflux_protocol::DeviceSetStatus::Revoked;
            device.revoked_at = Some(now_unix_timestamp());
        }
    }
    manifest.signed_device_set = Some(ramflux_crypto::sign_device_set_with_profile(
        f.source.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: old.principal_kind,
            device_set_epoch: old.device_set_epoch + 1,
            devices,
        },
        old.profile.as_deref().cloned(),
    )?);
    manifest.devices.retain(|device| device.device_id != "device-sibling");
    f.source.client.persist_root_verified_directory(&manifest)?;
    Ok(())
}
#[tokio::test]
async fn a_single_active_device_sends_without_any_copy_state_writes_or_manifest_fetch() -> TestResult
{
    let mut f = Fixture::new("own-copy-no-siblings").await?;
    revoke_sibling(&f)?;
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
    f.source.put_engine(engine);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/")?, before);
    assert!(f.source.client.account_db()?.client_record("message", "single-one")?.is_none());
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    f.cleanup()
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
    f.source.put_engine(engine);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    revoke_sibling(&f)?;
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    f.cleanup()
}

#[tokio::test]
async fn a_missing_local_manifest_backs_off_refresh_across_copy_retries() -> TestResult {
    let mut f = Fixture::new("own-copy-refresh-backoff").await?;
    let mut engine = GatewaySessionEngine::with_test_transport(
        f.config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    f.source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            f.message("refresh")?,
            b"already submitted",
        )
        .await?;
    f.source.put_engine(engine);
    f.source
        .client
        .account_db()?
        .remove_actor_state(&format!("identity/manifest-root/{}", f.source.principal_commitment))?;
    f.directory.abort();
    let _ = (&mut f.directory).await;
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    let db = f.source.client.account_db()?;
    let mut marker: serde_json::Value =
        db.load_actor_state("own-device/manifest-refresh")?.ok_or("refresh marker")?;
    marker["next_at"] = json!(i64::MAX);
    db.persist_actor_state("own-device/manifest-refresh", &marker)?;
    let key =
        db.actor_state_key_page("own-device/send/", 1)?.into_iter().next().ok_or("pending copy")?;
    let mut work: serde_json::Value = db.load_actor_state(&key)?.ok_or("work")?;
    work["next_at"] = json!(0);
    db.persist_actor_state(&key, &work)?;
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(
        f.source
            .client
            .account_db()?
            .load_actor_state::<serde_json::Value>("own-device/manifest-refresh")?,
        Some(marker)
    );
    assert_eq!(
        f.source.client.account_db()?.message_content("refresh")?,
        Some(b"already submitted".to_vec())
    );
    f.cleanup()
}

#[tokio::test]
async fn legacy_plain_copy_intents_without_submission_confirmation_are_not_assumed_sent()
-> TestResult {
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
    f.source
        .put_engine(GatewaySessionEngine::with_test_transport(f.config.clone(), Box::new(gateway)));
    assert_eq!(crate::bus::own_device_copy::flush(&mut f.source).await?, 0);
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 0);
    assert_eq!(f.source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    assert!(f.source.client.direct_message_by_id("legacy")?.is_some());
    f.cleanup()
}
