// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provider contracts exercised with current native custody and funded notification authority.

use super::permit_tests::Peer;
use super::*;
use ramflux_node_core::test_support::notification_authority::{NativeDevice, NativeScenario};
use std::time::Duration;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(5);

struct NativeWebPush {
    system: NativeScenario,
    peer: Peer,
    target: String,
    _temp: tempfile::TempDir,
}
impl NativeWebPush {
    fn new() -> TestResult<Self> {
        let temp = tempfile::TempDir::new()?;
        let system = NativeScenario::new(temp.path())?;
        let now = ramflux_node_core::now_unix_seconds();
        let device = NativeDevice::new("recipient.example", 30, now)?;
        system.publish(&device, now)?;
        let peer = Peer::new(false)?;
        let subscription = super::tests::test_webpush_subscription();
        system.notify.update_provider_credential(
            &ramflux_node_core::ProviderCredential::WebPush(
                ramflux_node_core::WebPushProviderCredential {
                    credential_id: "webpush".into(),
                    vapid_public_key_ref: "literal:fixture-public".into(),
                    vapid_private_key_ref: format!(
                        "literal:{}",
                        rcgen::KeyPair::generate()?.serialize_pem()
                    ),
                    subject: "mailto:ops@ramflux.example".into(),
                    provider_ca_pem_ref: Some(format!("literal:{}", peer.ca_pem)),
                },
            ),
        )?;
        let owner = system
            .router
            .mvp1_device_auth_key_checked(&device.target)?
            .ok_or("test: native WebPush owner")?;
        system.notify.register_authenticated_push_route(
            &owner,
            &ramflux_node_core::DevicePushRoute {
                device_delivery_id: device.target.clone(),
                provider: ramflux_node_core::PushProviderKind::WebPush,
                credential_id: Some("webpush".into()),
                token: "raw_token_not_logged".into(),
                endpoint: format!("https://localhost:{}/webpush", peer.port),
                webpush_p256dh: Some(subscription.0),
                webpush_auth: Some(subscription.1),
                registered_at: now,
                expires_at: now + 172_800,
                route_generation: 0,
            },
        )?;
        Ok(Self { system, peer, target: device.target, _temp: temp })
    }
    fn admitted(&self, byte: u8, expires_at: u64) -> TestResult<S13WakeRequest> {
        let key = ramflux_node_core::NodeServiceSigningKey::from_seed([8; 32]);
        let signed = key.sign_wake_v2(&ramflux_protocol::WakeV2 {
            version: 2,
            signing_key_id: String::new(),
            signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
            audience: ramflux_protocol::NOTIFY_WAKE_AUDIENCE.into(),
            action: ramflux_protocol::WakeAction::Enqueue,
            wake_id: ramflux_protocol::encode_base64url([byte; 16]),
            target_delivery_id: self.target.clone(),
            target_owner_epoch: 1,
            source_event_id: format!("native-message-{byte}"),
            class: ramflux_protocol::WakeClass::Message,
            created_at: ramflux_node_core::now_unix_seconds(),
            expires_at,
            call_intent_digest: None,
        })?;
        let mut request = S13WakeRequest {
            device_delivery_id: self.target.clone(),
            signed_wake: signed,
            queued_at: None,
            dnd_active: None,
            admission: AdmittedWake::Unverified,
        };
        request.admit(&NotifyWakeAuth { key }, &self.system.notify)?;
        Ok(request)
    }
    fn prepared(&self, byte: u8) -> TestResult<ramflux_node_core::PreparedProviderPush> {
        let now = ramflux_node_core::now_unix_seconds();
        let request = self.admitted(byte, now + 86400)?;
        let wake = request.queued_provider_wake()?.ok_or("test: native wake admission")?;
        let (_, mut pushes) =
            self.system.notify.queue_wake_for_push(&self.target, wake, now, false)?;
        pushes.pop().ok_or_else(|| "test: native WebPush preparation".into())
    }
}

#[test]
fn s13_dispatch_sends_wake_to_tls_h2_provider() -> TestResult {
    let mut fixture = NativeWebPush::new()?;
    let prepared = fixture.prepared(0x22)?;
    assert!(
        send_provider_push(&fixture.system.notify, &prepared)?.accepted(),
        "native WebPush was refused"
    );
    let received = fixture.peer.capture.recv_timeout(WAIT)?;
    assert_eq!(received.path, "/webpush", "provider path changed");
    let topic = received.headers.get("topic").ok_or("test: WebPush topic")?;
    assert_eq!(
        Some(topic.as_str()),
        prepared.payload.collapse_key.as_deref(),
        "collapse header drifted"
    );
    assert_eq!(topic.len(), 32, "topic ceased to be opaque bounded metadata");
    assert!(
        topic.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "invalid topic alphabet"
    );
    assert!(
        received.headers.keys().all(|name| !name.starts_with("ramflux-")),
        "private header leaked"
    );
    let ttl: u64 = received.headers.get("ttl").ok_or("test: TTL")?.parse()?;
    assert!((86390..=86400).contains(&ttl), "original message deadline was reminted");
    assert_eq!(
        received.headers.get("urgency").map(String::as_str),
        Some("normal"),
        "WebPush priority changed"
    );
    assert_eq!(
        received.headers.get("content-encoding").map(String::as_str),
        Some("aes128gcm"),
        "WebPush lost encryption"
    );
    assert!(!received.body.is_empty(), "encrypted body missing");
    for forbidden in
        [prepared.payload.wake_id.as_bytes(), b"target:".as_slice(), b"encrypted_hint".as_slice()]
    {
        assert!(
            !received.body.windows(forbidden.len()).any(|window| window == forbidden),
            "WebPush encrypted body leaked a plaintext marker"
        );
    }
    fixture.peer.close()?;
    Ok(())
}

#[test]
fn handler_admission_keeps_the_signed_absolute_expiry() -> TestResult {
    let mut fixture = NativeWebPush::new()?;
    let now = ramflux_node_core::now_unix_seconds();
    let signed_expiry = now + 120;
    let request = fixture.admitted(0x44, signed_expiry)?;
    let wake = request.queued_provider_wake()?.ok_or("test: admitted message")?;
    let (entry, _) =
        fixture.system.notify.queue_wake_for_push(&fixture.target, wake, now + 1000, false)?;
    assert_eq!(entry.expires_at, signed_expiry, "queue time extended signed expiry");
    assert_ne!(
        entry.expires_at,
        entry.queued_at + u64::from(entry.wake.ttl),
        "test did not distinguish a reminted budget"
    );
    fixture.peer.close()?;
    Ok(())
}

#[test]
fn stale_route_generation_drops_the_live_provider_send() -> TestResult {
    let mut fixture = NativeWebPush::new()?;
    let old = fixture.prepared(0x31)?;
    let owner = fixture
        .system
        .router
        .mvp1_device_auth_key_checked(&fixture.target)?
        .ok_or("test: native route owner")?;
    fixture.system.notify.register_authenticated_push_route(
        &owner,
        &ramflux_node_core::DevicePushRoute {
            route_generation: 0,
            token: "rotated-token".into(),
            ..old.route.clone()
        },
    )?;
    assert!(!send_provider_push(&fixture.system.notify, &old)?.accepted(), "stale route issued");
    assert!(fixture.peer.capture.try_recv().is_err(), "provider saw stale route");
    let current = fixture.prepared(0x32)?;
    assert!(
        send_provider_push(&fixture.system.notify, &current)?.accepted(),
        "rotated route failed its positive control"
    );
    fixture.peer.capture.recv_timeout(WAIT)?;
    fixture.peer.close()?;
    Ok(())
}

#[test]
fn wake_ledger_rows_expire_after_the_retain_horizon() -> TestResult {
    let mut fixture = NativeWebPush::new()?;
    let now = ramflux_node_core::now_unix_seconds();
    let expires = now + 600;
    let request = fixture.admitted(0x41, expires)?;
    fixture.system.notify.cancel_pending_wake(&request.signed_wake.body.wake_id)?;
    assert!(
        fixture.system.notify.claim_signed_wake(&request.signed_wake, expires)?.is_none(),
        "cancelled wake reopened"
    );
    assert_eq!(fixture.system.notify.prune_wake_ledger(now)?, 0, "live denial was collected");
    let horizon = expires + ramflux_protocol::CLOCK_UNCERTAINTY_SECONDS;
    assert_eq!(
        fixture.system.notify.prune_wake_ledger(horizon)?,
        1,
        "indexed denial was not collected"
    );
    assert!(
        fixture.system.notify.claim_signed_wake(&request.signed_wake, expires).is_err(),
        "expired wake recreated authority after collection"
    );
    fixture.peer.close()?;
    Ok(())
}

#[test]
fn one_signed_wake_is_sent_once_and_an_absent_cancel_blocks_enqueue() -> TestResult {
    let mut fixture = NativeWebPush::new()?;
    let prepared = fixture.prepared(0x55)?;
    assert!(
        send_provider_push(&fixture.system.notify, &prepared)?.accepted(),
        "first native send failed"
    );
    fixture.peer.capture.recv_timeout(WAIT)?;
    assert!(
        !send_provider_push(&fixture.system.notify, &prepared)?.accepted(),
        "one attempt issued twice"
    );
    assert!(fixture.peer.capture.try_recv().is_err(), "provider saw duplicate attempt");
    let now = ramflux_node_core::now_unix_seconds();
    let blocked = ramflux_protocol::encode_base64url([0x66; 16]);
    fixture.system.notify.cancel_pending_wake(&blocked)?;
    assert!(
        fixture.admitted(0x66, now + 600)?.queued_provider_wake()?.is_none(),
        "absent cancellation did not block enqueue"
    );
    assert!(
        fixture.admitted(0x77, now + 600)?.queued_provider_wake()?.is_some(),
        "fresh wake failed its positive control"
    );
    fixture.peer.close()?;
    Ok(())
}
