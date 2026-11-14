// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provider-contract acceptance rows. Each test calls the production builder or ingress.
use super::provider_outcome::{
    AttemptClock, AttemptStep, ProviderFamily, ProviderOutcome, classify_provider_response,
    invalidates_token, next_attempt,
};
use super::provider_payload::{
    ProviderBuildError, ProviderBuildInput, ProviderWireMode, build_provider_parts,
    ensure_encrypted_web_body_fits, provider_class_for_internal, select_apns_mode,
};
use ramflux_protocol::{NotificationDeliveryClass, WakeClass};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const SENTINELS: &[&str] = &[
    "env-sentinel-envelope",
    "sender-sentinel",
    "conversation-sentinel",
    "content-sentinel",
    "ciphertext-sentinel",
    "hash-sentinel",
    "ext-sentinel",
    "wake_env-sentinel-envelope",
    "encrypted_hint",
];

fn wake_id() -> String {
    ramflux_protocol::encode_base64url([9_u8; 16])
}

fn collapse() -> String {
    ramflux_protocol::encode_base64url([7_u8; 24])
}

fn input<'a>(
    class: WakeClass,
    id: &'a str,
    key: Option<&'a str>,
    token_topic: (&'a str, &'a str),
    window: (u64, u64),
    mode: ProviderWireMode,
) -> ProviderBuildInput<'a> {
    ProviderBuildInput {
        class,
        wake_id: id,
        collapse_key: key,
        token: token_topic.0,
        topic: token_topic.1,
        expires_at: window.0,
        now: window.1,
        mode,
    }
}

fn parse(
    parts: &super::provider_payload::ProviderRequestParts,
) -> Result<Value, ProviderBuildError> {
    serde_json::from_slice(&parts.body).map_err(|_source| ProviderBuildError::PayloadTooLarge)
}

fn key_set(value: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    collect_keys(value, "", &mut keys);
    keys
}

fn collect_keys(value: &Value, prefix: &str, keys: &mut BTreeSet<String>) {
    let Value::Object(map) = value else {
        return;
    };
    for (key, child) in map {
        let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        keys.insert(path.clone());
        collect_keys(child, &path, keys);
    }
}

fn assert_exact_keys(value: &Value, expected: &[&str]) {
    let keys = key_set(value);
    let expected = expected.iter().map(|key| (*key).to_owned()).collect::<BTreeSet<_>>();
    assert_eq!(keys, expected);
}

fn assert_clean(body: &str, headers: &[(String, String)]) {
    for sentinel in SENTINELS {
        assert!(!body.contains(sentinel));
        assert!(
            headers
                .iter()
                .all(|(name, value)| !name.contains(sentinel) && !value.contains(sentinel))
        );
    }
    assert!(!body.contains("notification"));
    assert!(headers.iter().all(|(name, _)| !name.starts_with("ramflux-")));
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

fn no_nulls(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => items.iter().all(no_nulls),
        Value::Object(map) => map.values().all(no_nulls),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

#[test]
fn fcm_real_builder_is_data_only() -> Result<(), ProviderBuildError> {
    let id = wake_id();
    let key = collapse();
    let classes = [
        NotificationDeliveryClass::SelfDeviceControlNotification,
        NotificationDeliveryClass::UserContentNotification,
        NotificationDeliveryClass::AiTaskNotification,
        NotificationDeliveryClass::A2uiSurfaceNotification,
        NotificationDeliveryClass::ConferenceWakeNotification,
        NotificationDeliveryClass::CallWakeNotification,
    ];
    for class in classes {
        let provider = provider_class_for_internal(&class);
        let collapse_key = matches!(provider, WakeClass::Message).then_some(key.as_str());
        let built = build_provider_parts(&input(
            provider,
            &id,
            collapse_key,
            ("fcm-token", ""),
            (1_030, 1_000),
            ProviderWireMode::Fcm,
        ))?;
        let retried = build_provider_parts(&input(
            provider,
            &id,
            collapse_key,
            ("fcm-token", ""),
            (1_030, 1_001),
            ProviderWireMode::Fcm,
        ))?;
        for parts in [&built, &retried] {
            let parsed = parse(parts)?;
            assert!(parsed.pointer("/message/notification").is_none());
            assert!(no_nulls(&parsed));
            let data =
                parsed.pointer("/message/data").ok_or(ProviderBuildError::PayloadTooLarge)?;
            let data = data.as_object().ok_or(ProviderBuildError::PayloadTooLarge)?;
            assert!(data.values().all(Value::is_string));
            assert_eq!(parts.headers.len(), 0);
            if provider == WakeClass::CallWake {
                assert!(data.get("collapse_key").is_none());
                assert!(parsed.pointer("/message/android/collapse_key").is_none());
                assert_eq!(
                    parsed.pointer("/message/android/priority").and_then(Value::as_str),
                    Some("HIGH")
                );
            }
        }
        assert_eq!(
            parse(&built)?.pointer("/message/android/ttl").and_then(Value::as_str),
            Some("30s")
        );
        assert_eq!(
            parse(&retried)?.pointer("/message/android/ttl").and_then(Value::as_str),
            Some("29s")
        );
    }
    Ok(())
}

#[test]
fn call_wake_deadline_is_thirty_seconds_across_dispatch_and_replay()
-> Result<(), ProviderBuildError> {
    let id = wake_id();
    let t0 = 5_000_u64;
    let deadline = t0.saturating_add(30);
    let initial = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("tok", "app.example"),
        (deadline, t0),
        ProviderWireMode::ApnsAlert,
    ))?;
    assert_eq!(header(&initial.headers, "apns-expiration"), Some("5030"));
    assert_ne!(header(&initial.headers, "apns-expiration"), Some("5060"));
    assert_ne!(header(&initial.headers, "apns-expiration"), Some("91400"));
    assert_eq!(header(&initial.headers, "apns-priority"), Some("10"));
    assert!(header(&initial.headers, "apns-collapse-id").is_none());
    let delayed = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("tok", "app.example"),
        (deadline, t0.saturating_add(20)),
        ProviderWireMode::ApnsAlert,
    ))?;
    assert_eq!(header(&delayed.headers, "apns-expiration"), Some("5030"));
    let fcm = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("tok", ""),
        (deadline, t0.saturating_add(20)),
        ProviderWireMode::Fcm,
    ))?;
    assert_eq!(parse(&fcm)?.pointer("/message/android/ttl").and_then(Value::as_str), Some("10s"));
    assert_eq!(
        parse(&fcm)?.pointer("/message/android/priority").and_then(Value::as_str),
        Some("HIGH")
    );
    let expired = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("tok", "app.example"),
        (deadline, deadline),
        ProviderWireMode::ApnsAlert,
    ));
    assert_eq!(expired.err(), Some(ProviderBuildError::Expired));
    let earlier =
        ramflux_protocol::effective_expiry(t0.saturating_add(10), t0, WakeClass::CallWake);
    assert_eq!(earlier, t0.saturating_add(10));
    let bounded = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("tok", "app.example"),
        (earlier, t0),
        ProviderWireMode::ApnsAlert,
    ))?;
    assert_eq!(header(&bounded.headers, "apns-expiration"), Some("5010"));
    Ok(())
}

#[test]
fn all_provider_payloads_and_headers_exclude_message_identifiers() -> Result<(), ProviderBuildError>
{
    let id = wake_id();
    let key = collapse();
    assert_ne!(id, "wake_env-sentinel-envelope");
    let alert = build_provider_parts(&input(
        WakeClass::Message,
        &id,
        Some(&key),
        ("transport-token", "app.example"),
        (2_000, 1_000),
        ProviderWireMode::ApnsAlert,
    ))?;
    let alert_json = parse(&alert)?;
    assert_exact_keys(
        &alert_json,
        &[
            "aps",
            "aps.alert",
            "aps.alert.body",
            "aps.alert.title",
            "class",
            "collapse_key",
            "wake_id",
        ],
    );
    let voip = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("transport-token", "app.example.voip"),
        (2_000, 1_000),
        ProviderWireMode::ApnsVoip,
    ))?;
    assert_exact_keys(&parse(&voip)?, &["aps", "class", "wake_id"]);
    let fcm = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("transport-token", ""),
        (2_000, 1_000),
        ProviderWireMode::Fcm,
    ))?;
    let fcm_json = parse(&fcm)?;
    assert_exact_keys(
        &fcm_json,
        &[
            "message",
            "message.android",
            "message.android.priority",
            "message.android.ttl",
            "message.data",
            "message.data.class",
            "message.data.wake_id",
            "message.token",
        ],
    );
    assert_eq!(fcm_json.pointer("/message/token").and_then(Value::as_str), Some("transport-token"));
    let web = build_provider_parts(&input(
        WakeClass::Message,
        &id,
        Some(&key),
        ("transport-token", ""),
        (2_000, 1_000),
        ProviderWireMode::WebPush,
    ))?;
    assert_exact_keys(&parse(&web)?, &["class", "collapse_key", "wake_id"]);
    for parts in [&alert, &voip, &fcm, &web] {
        let body = String::from_utf8_lossy(&parts.body);
        assert_clean(&body, &parts.headers);
    }
    assert!(!String::from_utf8_lossy(&alert.body).contains("transport-token"));
    assert!(!String::from_utf8_lossy(&web.body).contains("transport-token"));
    Ok(())
}

fn build_box(err: ProviderBuildError) -> Box<dyn std::error::Error> {
    std::io::Error::other(format!("{err:?}")).into()
}

fn apns_push(
    class: NotificationDeliveryClass,
    provider: ramflux_node_core::PushProviderKind,
    topic: &str,
    token: &str,
) -> ramflux_node_core::PreparedProviderPush {
    ramflux_node_core::PreparedProviderPush {
        route: ramflux_node_core::DevicePushRoute {
            device_delivery_id: "device".to_owned(),
            provider: provider.clone(),
            credential_id: Some("cred".to_owned()),
            token: token.to_owned(),
            endpoint: "https://api.push.apple.com".to_owned(),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: 1_000,
            expires_at: 9_000,
            route_generation: 1,
        },
        credential: ramflux_node_core::ProviderCredential::Apns(
            ramflux_node_core::ApnsProviderCredential {
                credential_id: "cred".to_owned(),
                team_id: "team".to_owned(),
                key_id: "key".to_owned(),
                p8_key_ref: "env:APNS_P8".to_owned(),
                topic: topic.to_owned(),
                sandbox: false,
                provider_ca_pem_ref: None,
            },
        ),
        payload: ramflux_node_core::ProviderPushPayload {
            wake_id: wake_id(),
            provider,
            delivery_class: class,
            priority: ramflux_protocol::PushPriority::High,
            ttl: 60,
            collapse_key: None,
            encrypted_hint: None,
        },
        push_alias_hash: String::new(),
        collapse_key_hash: String::new(),
        action: ramflux_node_core::NotifyDeliveryAction::Accept,
        expires_at: 1_030,
        admitted_unix: 1_000,
        boot_id: 0,
        owner_epoch: 0,
    }
}

#[test]
fn apns_route_topic_and_body_follow_push_mode() -> Result<(), Box<dyn std::error::Error>> {
    let id = wake_id();
    let key = collapse();
    let alert = build_provider_parts(&input(
        WakeClass::Message,
        &id,
        Some(&key),
        ("alert-token", "app.example"),
        (2_000, 1_000),
        ProviderWireMode::ApnsAlert,
    ))
    .map_err(build_box)?;
    let alert_json = parse(&alert).map_err(|_| "alert json")?;
    assert_eq!(alert_json.pointer("/aps/alert/title").and_then(Value::as_str), Some("Ramflux"));
    assert_eq!(
        alert_json.pointer("/aps/alert/body").and_then(Value::as_str),
        Some("You have a new Ramflux update.")
    );
    assert!(alert_json.pointer("/aps/mutable-content").is_none());
    assert_eq!(header(&alert.headers, "apns-topic"), Some("app.example"));
    assert_eq!(header(&alert.headers, "apns-push-type"), Some("alert"));
    let voip = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("voip-token", "app.example.voip"),
        (1_030, 1_000),
        ProviderWireMode::ApnsVoip,
    ))
    .map_err(build_box)?;
    let voip_json = parse(&voip).map_err(|_| "voip json")?;
    assert_eq!(voip_json.pointer("/aps"), Some(&Value::Object(serde_json::Map::new())));
    assert!(voip_json.pointer("/aps/alert").is_none());
    assert_eq!(header(&voip.headers, "apns-topic"), Some("app.example.voip"));
    assert_eq!(header(&voip.headers, "apns-push-type"), Some("voip"));
    assert_eq!(header(&voip.headers, "apns-expiration"), Some("0"));
    let fallback = apns_push(
        NotificationDeliveryClass::CallWakeNotification,
        ramflux_node_core::PushProviderKind::Apns,
        "app.example",
        "alert-token",
    );
    let mode =
        super::wire_mode(&fallback, provider_class_for_internal(&fallback.payload.delivery_class))?;
    assert_eq!(mode, ProviderWireMode::ApnsAlert);
    let selected = apns_push(
        NotificationDeliveryClass::CallWakeNotification,
        ramflux_node_core::PushProviderKind::ApnsVoip,
        "app.example.voip",
        "voip-token",
    );
    let mode =
        super::wire_mode(&selected, provider_class_for_internal(&selected.payload.delivery_class))?;
    assert_eq!(mode, ProviderWireMode::ApnsVoip);
    let wrong = apns_push(
        NotificationDeliveryClass::CallWakeNotification,
        ramflux_node_core::PushProviderKind::ApnsVoip,
        "app.example",
        "voip-token",
    );
    assert!(
        super::wire_mode(&wrong, provider_class_for_internal(&wrong.payload.delivery_class))
            .is_err()
    );
    let message_on_voip = build_provider_parts(&input(
        WakeClass::Message,
        &id,
        Some(&key),
        ("tok", "app.example.voip"),
        (2_000, 1_000),
        ProviderWireMode::ApnsVoip,
    ));
    assert_eq!(message_on_voip.err(), Some(ProviderBuildError::VoipRequiresCall));
    Ok(())
}

#[test]
fn voip_expiration_is_zero() -> Result<(), ProviderBuildError> {
    let id = wake_id();
    let parts = build_provider_parts(&input(
        WakeClass::CallWake,
        &id,
        None,
        ("voip-token", "app.example.voip"),
        (9_999, 1_000),
        ProviderWireMode::ApnsVoip,
    ))?;
    assert_eq!(header(&parts.headers, "apns-expiration"), Some("0"));
    assert_ne!(header(&parts.headers, "apns-expiration"), Some("9999"));
    assert_eq!(header(&parts.headers, "apns-push-type"), Some("voip"));
    Ok(())
}

#[test]
fn conference_wake_never_uses_voip() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        provider_class_for_internal(&NotificationDeliveryClass::ConferenceWakeNotification),
        WakeClass::Message
    );
    assert_eq!(select_apns_mode(WakeClass::Message, true, true), ProviderWireMode::ApnsAlert);
    let conference = apns_push(
        NotificationDeliveryClass::ConferenceWakeNotification,
        ramflux_node_core::PushProviderKind::ApnsVoip,
        "app.example.voip",
        "voip-token",
    );
    assert!(
        super::wire_mode(
            &conference,
            provider_class_for_internal(&conference.payload.delivery_class),
        )
        .is_err()
    );
    let alert = apns_push(
        NotificationDeliveryClass::ConferenceWakeNotification,
        ramflux_node_core::PushProviderKind::Apns,
        "app.example",
        "alert-token",
    );
    let mode =
        super::wire_mode(&alert, provider_class_for_internal(&alert.payload.delivery_class))?;
    assert_eq!(mode, ProviderWireMode::ApnsAlert);
    let built = build_provider_parts(&input(
        provider_class_for_internal(&NotificationDeliveryClass::ConferenceWakeNotification),
        &wake_id(),
        Some(&collapse()),
        ("alert-token", "app.example"),
        (2_000, 1_000),
        mode,
    ))
    .map_err(build_box)?;
    assert_eq!(header(&built.headers, "apns-push-type"), Some("alert"));
    assert_ne!(header(&built.headers, "apns-push-type"), Some("voip"));
    Ok(())
}

#[test]
fn provider_payload_limits_and_disabled_modes_fail_closed() -> Result<(), ProviderBuildError> {
    assert_eq!(select_apns_mode(WakeClass::CallWake, true, false), ProviderWireMode::ApnsAlert);
    assert_eq!(ensure_encrypted_web_body_fits(4_095), Ok(()));
    assert_eq!(ensure_encrypted_web_body_fits(4_096), Err(ProviderBuildError::PayloadTooLarge));
    let huge = "t".repeat(4_096);
    let id = wake_id();
    assert_eq!(
        build_provider_parts(&input(
            WakeClass::CallWake,
            &id,
            None,
            (&huge, ""),
            (2_000, 1_000),
            ProviderWireMode::Fcm,
        ))
        .err(),
        Some(ProviderBuildError::PayloadTooLarge)
    );
    assert!(
        serde_json::from_str::<ramflux_node_core::ProviderCredential>(r#"{"provider":"apns"}"#)
            .is_err()
    );
    let key = collapse();
    let capped = build_provider_parts(&input(
        WakeClass::Message,
        &id,
        Some(&key),
        ("tok", ""),
        (1_000 + 86_400, 1_000),
        ProviderWireMode::Fcm,
    ))?;
    assert!(capped.body.len() <= super::provider_payload::PROVIDER_JSON_CEILING);
    Ok(())
}

fn sends_until_stop(outcome: ProviderOutcome, now: u64, expires_at: u64) -> u32 {
    let mut used = 0_u32;
    let mut clock_now = now;
    loop {
        used = used.saturating_add(1);
        match next_attempt(
            AttemptClock { attempts_used: used, now: clock_now, expires_at },
            outcome,
            None,
            false,
            0,
        ) {
            AttemptStep::Stop(_) => return used,
            AttemptStep::Wait { delay, .. } => {
                clock_now = clock_now.saturating_add(delay.as_secs().max(1));
                if used > 6 {
                    return used;
                }
            }
        }
    }
}

#[test]
fn provider_retry_classification_preserves_deadline_and_rotated_tokens() {
    let (payload, _, _) = classify_provider_response(
        ProviderFamily::Fcm,
        400,
        br#"{"error":{"status":"INVALID_ARGUMENT"}}"#,
        false,
        None,
    );
    assert_eq!(payload, ProviderOutcome::PermanentPayload);
    assert!(!invalidates_token(payload));
    assert_eq!(sends_until_stop(payload, 1_000, 90_000), 1);
    let (token, _, _) = classify_provider_response(
        ProviderFamily::Apns,
        400,
        br#"{"reason":"Unregistered"}"#,
        false,
        None,
    );
    assert_eq!(token, ProviderOutcome::InvalidToken);
    assert!(invalidates_token(token));
    assert_eq!(sends_until_stop(token, 1_000, 90_000), 1);
    let (config, _, _) = classify_provider_response(
        ProviderFamily::Apns,
        403,
        br#"{"reason":"Forbidden"}"#,
        false,
        None,
    );
    assert_eq!(config, ProviderOutcome::PermanentConfig);
    assert_eq!(sends_until_stop(config, 1_000, 90_000), 1);
    let (quota, _, exceeded) = classify_provider_response(
        ProviderFamily::Fcm,
        429,
        br#"{"error":{"status":"QUOTA_EXCEEDED"}}"#,
        false,
        Some("5"),
    );
    assert_eq!(quota, ProviderOutcome::Transient);
    assert!(exceeded);
    let waited = next_attempt(
        AttemptClock { attempts_used: 1, now: 1_000, expires_at: 90_000 },
        quota,
        Some(5),
        true,
        0,
    );
    assert_eq!(
        waited,
        AttemptStep::Wait {
            delay: std::time::Duration::from_secs(60),
            outcome: ProviderOutcome::Transient
        }
    );
    assert_eq!(sends_until_stop(ProviderOutcome::Transient, 1_000, 90_000), 3);
    assert_eq!(sends_until_stop(ProviderOutcome::Transient, 1_000, 1_001), 1);
    let late = next_attempt(
        AttemptClock { attempts_used: 1, now: 2_000, expires_at: 2_000 },
        ProviderOutcome::Transient,
        None,
        false,
        0,
    );
    assert_eq!(late, AttemptStep::Stop(ProviderOutcome::Expired));
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().map_err(|_| std::io::Error::other("log lock"))?.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture(body: impl FnOnce()) -> Result<String, Box<dyn std::error::Error>> {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || LogWriter(Arc::clone(&writer)))
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    let bytes = buf.lock().map_err(|_| "log lock")?.clone();
    Ok(String::from_utf8(bytes)?)
}

#[test]
fn notify_logs_and_metrics_have_no_identifiers() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let path = temp.path().join("notify.redb");
    let store = ramflux_node_core::NotifyRedbStore::open(&path)?;
    let now = ramflux_node_core::now_unix_seconds();
    let mut wake = ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
        version: 2,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "node-service-ed25519-v1".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "sig".to_owned(),
        },
        wake_id: "wake-sentinel".to_owned(),
        push_alias: "alias-sentinel".to_owned(),
        delivery_class: NotificationDeliveryClass::UserContentNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 60,
        absolute_expires_at: now.saturating_add(60),
        collapse_key: None,
        encrypted_hint: None,
    };
    wake.wake_id = "wake-sentinel".to_owned();
    // Async claim reads the WAL. The sync snapshot queue is not in that scan.
    let _entry = store.queue_wake_for_async_accept("device-sentinel", &wake, now, false)?;
    let in_flight = Arc::new(Mutex::new(BTreeSet::new()));
    let text = capture(|| {
        let _claimed = super::notify_async_claim_entries(&store, &in_flight, 4);
        let push = apns_push(
            NotificationDeliveryClass::UserContentNotification,
            ramflux_node_core::PushProviderKind::Apns,
            "app.example",
            "token-sentinel",
        );
        let _accepted = super::note_provider_send(
            &store,
            &push,
            Err(ramflux_node_core::NodeCoreError::ItestHttp("provider send failed".to_owned())),
        );
    })?;
    assert!(text.contains("notify async delivery claimed pending entries"));
    assert!(text.contains("candidate_count"));
    assert!(text.contains("claimed_count=1"));
    assert!(text.contains("push provider send failed"));
    for sentinel in ["wake-sentinel", "device-sentinel", "token-sentinel", "alias-sentinel"] {
        assert!(!text.contains(sentinel));
    }
    Ok(())
}

fn signed_message(
    key: &ramflux_node_core::NodeServiceSigningKey,
    device: &str,
    event: &str,
    now: u64,
) -> Result<ramflux_protocol::SignedWakeV2, ramflux_node_core::NodeCoreError> {
    let body = ramflux_protocol::WakeV2 {
        version: 2,
        signing_key_id: key.signing_key_id().to_owned(),
        signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
        audience: ramflux_protocol::NOTIFY_WAKE_AUDIENCE.to_owned(),
        action: ramflux_protocol::WakeAction::Enqueue,
        wake_id: ramflux_protocol::encode_base64url([4_u8; 16]),
        target_delivery_id: device.to_owned(),
        target_owner_epoch: 1,
        source_event_id: event.to_owned(),
        class: WakeClass::Message,
        created_at: now,
        expires_at: now.saturating_add(3_600),
        call_intent_digest: None,
    };
    key.sign_wake_v2(&body)
}

#[test]
fn wake_v2_rejects_v1_and_unsigned_on_every_ingress() -> Result<(), Box<dyn std::error::Error>> {
    let v1 = br#"{"device_delivery_id":"device-v1","wake":{"schema":"ramflux.notification_wake.v1","wake_id":"legacy-sentinel-wake"}}"#;
    assert!(serde_json::from_slice::<super::S13WakeRequest>(v1).is_err());
    let key = ramflux_node_core::NodeServiceSigningKey::from_seed([4_u8; 32]);
    let now = ramflux_node_core::now_unix_seconds();
    let mut bad = signed_message(&key, "device-v2", "env-v2", now)?;
    bad.signature = ramflux_protocol::encode_base64url([8_u8; 64]);
    let temp = tempfile::TempDir::new()?;
    let path = temp.path().join("notify.redb");
    let store = ramflux_node_core::NotifyRedbStore::open(&path)?;
    let auth = super::NotifyWakeAuth { key: key.clone() };
    let mut request = super::S13WakeRequest {
        device_delivery_id: "device-v2".to_owned(),
        signed_wake: bad.clone(),
        queued_at: Some(now),
        dnd_active: Some(false),
        admission: super::AdmittedWake::Unverified,
    };
    assert!(request.admit(&auth, &store).is_err());
    assert!(
        super::project_mvp10_signed_wake(
            &auth,
            &serde_json::json!({"wake": {"wake_id": "legacy-sentinel-wake"}})
        )
        .is_err()
    );
    assert!(
        super::project_mvp10_signed_wake(&auth, &serde_json::json!({"signed_wake": bad})).is_err()
    );
    let (reply, mut response) = tokio::sync::oneshot::channel();
    super::verify_and_enqueue_wake_batch(
        &auth,
        &store,
        0,
        vec![super::WakeVerifyRequest {
            signed: bad,
            device_delivery_id: "device-v2".to_owned(),
            raw_body: Vec::new(),
            queued_at: now,
            reply,
        }],
    );
    assert!(matches!(response.try_recv(), Ok(Err(_))));
    let raw = serde_json::to_vec(&serde_json::json!({
        "device_delivery_id": "device-v1",
        "schema": "ramflux.notification_wake.v1",
        "wake_id": "legacy-sentinel-wake"
    }))?;
    store.queue_raw_wakes_for_async_accept_shard_batch(0, vec![(raw, now)])?;
    let pending = store.pending_entries_without_attempts(10)?;
    assert!(pending.iter().all(|entry| entry.wake.wake_id != "legacy-sentinel-wake"));
    let good = signed_message(&key, "device-v2", "env-good", now)?;
    let mut admitted = super::S13WakeRequest {
        device_delivery_id: "device-v2".to_owned(),
        signed_wake: good,
        queued_at: Some(now),
        dnd_active: Some(false),
        admission: super::AdmittedWake::Unverified,
    };
    admitted.admit(&auth, &store)?;
    assert!(admitted.queued_provider_wake()?.is_some());
    drop(store);
    let wal_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("notify.redb");
    let _ = std::fs::remove_dir_all(path.with_file_name(format!("{wal_name}.wal")));
    let _ = std::fs::remove_file(&path);
    Ok(())
}
