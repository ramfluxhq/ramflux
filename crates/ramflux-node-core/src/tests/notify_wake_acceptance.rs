// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Acceptance rows that prepare real provider pushes from stored routes.
use super::*;

fn apns_credential(id: &str, topic: &str) -> ProviderCredential {
    ProviderCredential::Apns(ApnsProviderCredential {
        credential_id: id.to_owned(),
        team_id: "team".to_owned(),
        key_id: "key".to_owned(),
        p8_key_ref: "env:APNS_P8".to_owned(),
        topic: topic.to_owned(),
        sandbox: false,
        provider_ca_pem_ref: None,
    })
}

fn fcm_credential(id: &str) -> ProviderCredential {
    ProviderCredential::Fcm(FcmProviderCredential {
        credential_id: id.to_owned(),
        project_id: "project".to_owned(),
        service_account_json_ref: "env:FCM_JSON".to_owned(),
        oauth_scope: "https://www.googleapis.com/auth/firebase.messaging".to_owned(),
        oauth_token_url: None,
        provider_ca_pem_ref: None,
    })
}

fn route_for(
    device: &str,
    provider: PushProviderKind,
    credential_id: &str,
    token: &str,
    now: u64,
) -> DevicePushRoute {
    DevicePushRoute {
        device_delivery_id: device.to_owned(),
        provider,
        credential_id: Some(credential_id.to_owned()),
        token: token.to_owned(),
        endpoint: "https://push.example.test/route".to_owned(),
        webpush_p256dh: None,
        webpush_auth: None,
        registered_at: now,
        expires_at: now.saturating_add(86_400),
        route_generation: 1,
    }
}

fn install_credentials(store: &NotifyRedbStore) -> Result<(), Box<dyn std::error::Error>> {
    store.update_provider_credential(&apns_credential("cred-apns", "app.example"))?;
    store.update_provider_credential(&apns_credential("cred-voip", "app.example.voip"))?;
    store.update_provider_credential(&fcm_credential("cred-fcm"))?;
    store.update_provider_credential(&notify_webpush_credential("cred-web"))?;
    Ok(())
}

fn install_route(
    store: &NotifyRedbStore,
    device: &str,
    provider: PushProviderKind,
    credential_id: &str,
    token: &str,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    store.register_push_route(route_for(device, provider, credential_id, token, now))?;
    Ok(())
}

fn class_wake(
    id: &str,
    class: ramflux_protocol::NotificationDeliveryClass,
    ttl: u32,
) -> ramflux_protocol::NotificationWake {
    let mut wake = notification_wake(id, ttl);
    wake.delivery_class = class;
    wake.collapse_key = None;
    wake.encrypted_hint = None;
    wake
}

fn kinds(pushes: &[PreparedProviderPush]) -> BTreeSet<PushProviderKind> {
    pushes.iter().map(|push| push.route.provider.clone()).collect()
}

fn queue_kinds(
    store: &NotifyRedbStore,
    device: &str,
    class: &ramflux_protocol::NotificationDeliveryClass,
    wake_id: &str,
    now: u64,
) -> Result<BTreeSet<PushProviderKind>, Box<dyn std::error::Error>> {
    let (_entry, pushes) =
        store.queue_wake_for_push(device, &class_wake(wake_id, class.clone(), 30), now, false)?;
    Ok(kinds(&pushes))
}

fn recovered_kinds(
    store: &NotifyRedbStore,
    wake_id: &str,
) -> Result<BTreeSet<PushProviderKind>, Box<dyn std::error::Error>> {
    let state = store.load_state()?.ok_or("missing recovered notify state")?;
    let entry = state.entry(wake_id).ok_or("missing recovered wake")?.clone();
    Ok(kinds(&store.prepare_provider_pushes_for_entry(&entry)?))
}

fn message_alert() -> BTreeSet<PushProviderKind> {
    BTreeSet::from([PushProviderKind::Apns, PushProviderKind::Fcm, PushProviderKind::WebPush])
}

fn call_voip() -> BTreeSet<PushProviderKind> {
    BTreeSet::from([PushProviderKind::ApnsVoip, PushProviderKind::Fcm])
}

#[test]
fn conference_wake_never_uses_voip() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("conference_wake_never_uses_voip")?;
    let key = NodeSecret::ephemeral()?;
    let now = now_unix_seconds();
    let store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    store.set_voip_policy(Some(true))?;
    install_credentials(&store)?;
    for (device, provider, credential, token) in [
        ("conf-both", PushProviderKind::Apns, "cred-apns", "alert-token"),
        ("conf-both", PushProviderKind::ApnsVoip, "cred-voip", "voip-token"),
        ("conf-both", PushProviderKind::Fcm, "cred-fcm", "fcm-token"),
        ("conf-both", PushProviderKind::WebPush, "cred-web", "web-token"),
        ("conf-alert", PushProviderKind::Apns, "cred-apns", "alert-only"),
        ("conf-voip", PushProviderKind::ApnsVoip, "cred-voip", "voip-only"),
        ("conf-other", PushProviderKind::Fcm, "cred-fcm", "fcm-only"),
        ("conf-other", PushProviderKind::WebPush, "cred-web", "web-only"),
    ] {
        install_route(&store, device, provider, credential, token, now)?;
    }
    let conference = ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification;
    let call = ramflux_protocol::NotificationDeliveryClass::CallWakeNotification;
    assert_eq!(queue_kinds(&store, "conf-both", &conference, "c-both", now)?, message_alert());
    assert_eq!(
        queue_kinds(&store, "conf-alert", &conference, "c-alert", now)?,
        BTreeSet::from([PushProviderKind::Apns])
    );
    assert_eq!(queue_kinds(&store, "conf-voip", &conference, "c-voip", now)?.len(), 0);
    assert_eq!(
        queue_kinds(&store, "conf-other", &conference, "c-other", now)?,
        BTreeSet::from([PushProviderKind::Fcm, PushProviderKind::WebPush])
    );
    assert_eq!(queue_kinds(&store, "conf-both", &call, "k-call", now)?, call_voip());
    assert_eq!(
        queue_kinds(&store, "conf-voip", &call, "k-voip-only", now)?,
        BTreeSet::from([PushProviderKind::ApnsVoip])
    );
    drop(store);
    let store = NotifyRedbStore::open_with_route_key(&path, key)?;
    store.set_voip_policy(Some(true))?;
    assert_eq!(recovered_kinds(&store, "c-both")?, message_alert());
    assert_eq!(recovered_kinds(&store, "k-call")?, call_voip());
    store.set_voip_policy(Some(false))?;
    let fallback = recovered_kinds(&store, "k-call")?;
    assert_eq!(fallback, BTreeSet::from([PushProviderKind::Apns, PushProviderKind::Fcm]));
    Ok(())
}

fn collapse_of(
    store: &NotifyRedbStore,
    device: &str,
    class: &ramflux_protocol::NotificationDeliveryClass,
    wake_id: &str,
    now: u64,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let (_entry, pushes) =
        store.queue_wake_for_push(device, &class_wake(wake_id, class.clone(), 60), now, false)?;
    let push = pushes.first().ok_or("missing prepared push")?;
    Ok(push.payload.collapse_key.clone())
}

#[test]
fn message_collapse_is_device_scoped_and_calls_never_collapse()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("message_collapse_is_device_scoped")?;
    let key = NodeSecret::ephemeral()?;
    let now = now_unix_seconds();
    let store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    install_credentials(&store)?;
    for device in ["device-a", "device-b"] {
        install_route(&store, device, PushProviderKind::Apns, "cred-apns", device, now)?;
        install_route(&store, device, PushProviderKind::Fcm, "cred-fcm", device, now)?;
        install_route(&store, device, PushProviderKind::WebPush, "cred-web", device, now)?;
    }
    let expected_a = key.device_collapse_key("device-a")?;
    let expected_b = key.device_collapse_key("device-b")?;
    assert_ne!(expected_a, expected_b);
    assert!(expected_a.len() <= 64);
    for marker in ["target:", "content", "task", "surface", "conference", "self_device"] {
        assert!(!expected_a.contains(marker));
    }
    let classes = [
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
        ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification,
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification,
        ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification,
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification,
    ];
    for (index, class) in classes.iter().enumerate() {
        let id = format!("msg-a-{index}");
        assert_eq!(
            collapse_of(&store, "device-a", class, &id, now)?.as_deref(),
            Some(expected_a.as_str())
        );
    }
    assert_eq!(
        collapse_of(
            &store,
            "device-b",
            &ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            "msg-b",
            now,
        )?
        .as_deref(),
        Some(expected_b.as_str())
    );
    let (_call, call_pushes) = store.queue_wake_for_push(
        "device-a",
        &class_wake(
            "call-a",
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
            30,
        ),
        now,
        false,
    )?;
    assert!(call_pushes.iter().all(|push| push.payload.collapse_key.is_none()));
    assert!(call_pushes.iter().all(|push| push.collapse_key_hash.is_empty()));
    drop(store);
    let store = NotifyRedbStore::open_with_route_key(&path, key)?;
    let state = store.load_state()?.ok_or("missing collapse state")?;
    let entry = state.entry("call-a").ok_or("missing call replay")?.clone();
    let replay = store.prepare_provider_pushes_for_entry(&entry)?;
    assert!(replay.iter().all(|push| push.payload.collapse_key.is_none()));
    assert!(replay.iter().all(|push| push.collapse_key_hash.is_empty()));
    let message = state.entry("msg-a-0").ok_or("missing message replay")?.clone();
    let replay = store.prepare_provider_pushes_for_entry(&message)?;
    assert!(
        replay.iter().all(|push| push.payload.collapse_key.as_deref() == Some(expected_a.as_str()))
    );
    assert_eq!(message.expires_at, message.wake.absolute_expires_at);
    assert_ne!(message.expires_at, message.queued_at.saturating_add(u64::from(message.wake.ttl)));
    Ok(())
}

#[test]
fn call_wake_deadline_is_thirty_seconds_across_dispatch_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("call_wake_deadline_is_thirty_seconds")?;
    let key = NodeSecret::ephemeral()?;
    let now = now_unix_seconds();
    let store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    install_credentials(&store)?;
    install_route(&store, "call-device", PushProviderKind::Apns, "cred-apns", "alert", now)?;
    install_route(&store, "call-device", PushProviderKind::Fcm, "cred-fcm", "fcm", now)?;
    let mut wake = class_wake(
        "deadline-call",
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
        60,
    );
    wake.absolute_expires_at = now.saturating_add(30);
    let (entry, pushes) = store.queue_wake_for_push("call-device", &wake, now, false)?;
    assert_eq!(entry.wake.absolute_expires_at, now.saturating_add(30));
    assert_eq!(entry.expires_at, now.saturating_add(30));
    assert_ne!(entry.expires_at, now.saturating_add(60));
    assert_ne!(entry.expires_at, now.saturating_add(86_400));
    assert_eq!(entry.wake.priority, ramflux_protocol::PushPriority::High);
    assert!(pushes.iter().all(|push| push.expires_at == entry.expires_at));
    assert!(pushes.iter().all(|push| push.payload.collapse_key.is_none()));
    drop(store);
    let store = NotifyRedbStore::open_with_route_key(&path, key)?;
    let state = store.load_state()?.ok_or("missing deadline state")?;
    let restored = state.entry("deadline-call").ok_or("missing deadline wake")?.clone();
    assert_eq!(restored.expires_at, now.saturating_add(30));
    let replay = store.prepare_provider_pushes_for_entry(&restored)?;
    assert!(replay.iter().all(|push| push.expires_at == now.saturating_add(30)));
    Ok(())
}

#[test]
fn provider_payload_limits_and_disabled_modes_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("provider_payload_limits_no_route")?;
    let key = NodeSecret::ephemeral()?;
    let now = now_unix_seconds();
    let store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    store.set_voip_policy(Some(false))?;
    let (entry, pushes) = store.queue_wake_for_push(
        "quiet-device",
        &class_wake(
            "quiet-message",
            ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            60,
        ),
        now,
        false,
    )?;
    assert_eq!(pushes.len(), 0);
    assert_eq!(entry.status, NotifyQueueStatus::Pending);
    install_credentials(&store)?;
    install_route(&store, "fallback-device", PushProviderKind::Apns, "cred-apns", "alert", now)?;
    install_route(&store, "fallback-device", PushProviderKind::ApnsVoip, "cred-voip", "voip", now)?;
    let kinds = queue_kinds(
        &store,
        "fallback-device",
        &ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
        "fallback-call",
        now,
    )?;
    assert_eq!(kinds, BTreeSet::from([PushProviderKind::Apns]));
    drop(store);
    let store = NotifyRedbStore::open_with_route_key(&path, key)?;
    let state = store.load_state()?.ok_or("missing quiet state")?;
    let restored = state.entry("quiet-message").ok_or("quiet message was dropped")?;
    assert_eq!(restored.status, NotifyQueueStatus::Pending);
    assert_eq!(restored.expires_at, restored.wake.absolute_expires_at);
    assert_ne!(restored.expires_at, now.saturating_add(60));
    Ok(())
}

#[test]
fn provider_retry_classification_preserves_deadline_and_rotated_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("provider_retry_rotated_token")?;
    let key = NodeSecret::ephemeral()?;
    let mut store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "rotated-retry".into();
    let owner = gateway_registered_key(&open)?;
    let now = now_unix_seconds();
    let mut first = route_for("rotated-retry", PushProviderKind::Apns, "cred-apns", "token-a", now);
    let mut second =
        route_for("rotated-retry", PushProviderKind::Apns, "cred-apns", "token-b", now);
    assert!(store.register_authenticated_push_route_at(&owner, &first, Some(1))?);
    let admitted =
        store.load_state()?.ok_or("missing route state")?.push_routes("rotated-retry", now);
    let current = admitted.first().ok_or("missing first route")?;
    first.route_generation = current.route_generation;
    first.token.clone_from(&current.token);
    assert!(store.register_authenticated_push_route_at(&owner, &second, Some(2))?);
    let admitted =
        store.load_state()?.ok_or("missing rotated state")?.push_routes("rotated-retry", now);
    let rotated =
        admitted.iter().find(|route| route.token == "token-b").ok_or("missing token-b")?;
    second.route_generation = rotated.route_generation;
    assert!(!store.delete_snapshotted_route(&first)?);
    let admitted =
        store.load_state()?.ok_or("missing surviving state")?.push_routes("rotated-retry", now);
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted.first().ok_or("missing surviving route")?.token, "token-b");
    assert!(store.delete_snapshotted_route(&second)?);
    Ok(())
}
