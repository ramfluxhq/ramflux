// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provider request bodies for the two-class wake contract.
//!
//! Background push is unsupported: this module has no background builder.
//! Custom `ramflux-*` headers are not produced. A call omits collapse fields.
//! `VoIP` `apns-expiration` is `0`; the signed deadline still refuses the send.

use ramflux_protocol::{NotificationDeliveryClass, WakeClass};
use serde::Serialize;

/// Shared JSON ceiling. Web's encrypted body is stricter and is checked separately.
pub const PROVIDER_JSON_CEILING: usize = 4096;
/// Encrypted Web Push bodies must be strictly shorter than this.
pub const WEB_ENCRYPTED_BODY_LIMIT: usize = 4096;

const GENERIC_TITLE: &str = "Ramflux";
const GENERIC_BODY: &str = "You have a new Ramflux update.";
const WAKE_ID_BYTES: usize = 16;
const COLLAPSE_BYTES: usize = 24;

/// How a prepared wake is placed on a provider transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWireMode {
    /// APNs alert, including call fallback on the normal bundle topic.
    ApnsAlert,
    /// APNs `VoIP` on a `PushKit` token and `<bundle>.voip` topic.
    ApnsVoip,
    /// FCM data message.
    Fcm,
    /// Web Push. Calls are refused.
    WebPush,
}

/// Why a provider body was not built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBuildError {
    /// `now >= expires_at`, so remaining whole seconds are zero.
    Expired,
    /// A message was missing its device collapse key.
    MissingCollapseKey,
    /// A call carried a collapse key.
    UnexpectedCollapseKey,
    /// Web Push has no call class.
    WebCallRefused,
    /// `VoIP` was selected for a non-call.
    VoipRequiresCall,
    /// The APNs topic does not match the wire mode.
    TopicMismatch,
    /// The serialized body exceeds [`PROVIDER_JSON_CEILING`], or an encrypted Web body is not strictly smaller than [`WEB_ENCRYPTED_BODY_LIMIT`].
    PayloadTooLarge,
    /// The wake id is not canonical unpadded base64url of 16 bytes.
    InvalidWakeId,
    /// The collapse key is not canonical unpadded base64url of 24 bytes.
    InvalidCollapseKey,
    /// The provider token is empty.
    EmptyToken,
}

/// Inputs already decided by admission. The builder does not read the clock itself.
pub struct ProviderBuildInput<'a> {
    /// Authorized provider class.
    pub class: WakeClass,
    /// Opaque wake id.
    pub wake_id: &'a str,
    /// Device collapse key for messages. Absent for calls.
    pub collapse_key: Option<&'a str>,
    /// Provider device token. It is placed only in the FCM transport field.
    pub token: &'a str,
    /// APNs topic. Ignored for FCM and Web Push.
    pub topic: &'a str,
    /// Persisted absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Current time, Unix seconds.
    pub now: u64,
    /// Selected transport.
    pub mode: ProviderWireMode,
}

/// Body plus the provider headers this contract owns.
///
/// Authorization and content type stay with the HTTP client.
pub struct ProviderRequestParts {
    /// Serialized provider JSON, or the Web Push plaintext before encryption.
    pub body: Vec<u8>,
    /// Contract headers. No `ramflux-*` names.
    pub headers: Vec<(String, String)>,
}

/// Map an internal delivery class onto the closed provider class.
/// Conference and every non-call class become `message`.
#[must_use]
pub const fn provider_class_for_internal(class: &NotificationDeliveryClass) -> WakeClass {
    match *class {
        NotificationDeliveryClass::CallWakeNotification => WakeClass::CallWake,
        NotificationDeliveryClass::SelfDeviceControlNotification
        | NotificationDeliveryClass::UserContentNotification
        | NotificationDeliveryClass::AiTaskNotification
        | NotificationDeliveryClass::A2uiSurfaceNotification
        | NotificationDeliveryClass::ConferenceWakeNotification => WakeClass::Message,
    }
}

/// Select the APNs wire mode. Messages never use `VoIP`. A call uses `VoIP` only when
/// the flag is on and a current `VoIP` route exists; otherwise it uses alert fallback.
#[must_use]
pub const fn select_apns_mode(
    class: WakeClass,
    voip_route_available: bool,
    voip_enabled: bool,
) -> ProviderWireMode {
    match class {
        WakeClass::CallWake if voip_route_available && voip_enabled => ProviderWireMode::ApnsVoip,
        WakeClass::CallWake | WakeClass::Message => ProviderWireMode::ApnsAlert,
    }
}

/// Reject an encrypted Web Push body that is not strictly under 4096 bytes.
///
/// # Errors
/// Returns [`ProviderBuildError::PayloadTooLarge`] at the limit and above.
pub const fn ensure_encrypted_web_body_fits(len: usize) -> Result<(), ProviderBuildError> {
    if len < WEB_ENCRYPTED_BODY_LIMIT { Ok(()) } else { Err(ProviderBuildError::PayloadTooLarge) }
}

/// Build one provider body and its contract headers.
///
/// # Errors
/// Returns [`ProviderBuildError`] when the class, deadline, topic, or size rules fail.
pub fn build_provider_parts(
    input: &ProviderBuildInput<'_>,
) -> Result<ProviderRequestParts, ProviderBuildError> {
    if input.now >= input.expires_at {
        return Err(ProviderBuildError::Expired);
    }
    if input.token.is_empty() {
        return Err(ProviderBuildError::EmptyToken);
    }
    validate_wake_id(input.wake_id)?;
    let collapse = collapse_for_class(input.class, input.collapse_key)?;
    let remaining = input.expires_at - input.now;
    let class_name = class_name(input.class);
    let (body, headers) = match input.mode {
        ProviderWireMode::ApnsAlert => {
            validate_alert_topic(input.topic)?;
            let body = apns_alert_body(input.wake_id, class_name, collapse)?;
            let headers = apns_headers(input, false, collapse);
            (body, headers)
        }
        ProviderWireMode::ApnsVoip => {
            if input.class != WakeClass::CallWake {
                return Err(ProviderBuildError::VoipRequiresCall);
            }
            validate_voip_topic(input.topic)?;
            let body = apns_voip_body(input.wake_id, class_name)?;
            let headers = apns_headers(input, true, None);
            (body, headers)
        }
        ProviderWireMode::Fcm => {
            let body = fcm_body(input, class_name, collapse, remaining)?;
            (body, Vec::new())
        }
        ProviderWireMode::WebPush => {
            if input.class != WakeClass::Message {
                return Err(ProviderBuildError::WebCallRefused);
            }
            let key = collapse.ok_or(ProviderBuildError::MissingCollapseKey)?;
            let body = serde_json::to_vec(&WebPlain {
                wake_id: input.wake_id,
                class: class_name,
                collapse_key: key,
            })
            .map_err(|_source| ProviderBuildError::PayloadTooLarge)?;
            let headers = vec![
                ("TTL".to_owned(), remaining.to_string()),
                ("Urgency".to_owned(), "normal".to_owned()),
                ("Topic".to_owned(), key.to_owned()),
            ];
            (body, headers)
        }
    };
    if body.len() > PROVIDER_JSON_CEILING {
        return Err(ProviderBuildError::PayloadTooLarge);
    }
    Ok(ProviderRequestParts { body, headers })
}

fn class_name(class: WakeClass) -> &'static str {
    match class {
        WakeClass::Message => "message",
        WakeClass::CallWake => "call_wake",
    }
}

fn validate_wake_id(value: &str) -> Result<(), ProviderBuildError> {
    let decoded = ramflux_protocol::decode_base64url(value)
        .map_err(|_source| ProviderBuildError::InvalidWakeId)?;
    if decoded.len() == WAKE_ID_BYTES && ramflux_protocol::encode_base64url(&decoded) == value {
        Ok(())
    } else {
        Err(ProviderBuildError::InvalidWakeId)
    }
}

fn validate_collapse(value: &str) -> Result<(), ProviderBuildError> {
    let decoded = ramflux_protocol::decode_base64url(value)
        .map_err(|_source| ProviderBuildError::InvalidCollapseKey)?;
    if decoded.len() == COLLAPSE_BYTES && ramflux_protocol::encode_base64url(&decoded) == value {
        Ok(())
    } else {
        Err(ProviderBuildError::InvalidCollapseKey)
    }
}

fn collapse_for_class(
    class: WakeClass,
    collapse_key: Option<&str>,
) -> Result<Option<&str>, ProviderBuildError> {
    match (class, collapse_key) {
        (WakeClass::Message, Some(key)) => {
            validate_collapse(key)?;
            Ok(Some(key))
        }
        (WakeClass::Message, None) => Err(ProviderBuildError::MissingCollapseKey),
        (WakeClass::CallWake, None) => Ok(None),
        (WakeClass::CallWake, Some(_)) => Err(ProviderBuildError::UnexpectedCollapseKey),
    }
}

fn voip_suffix(topic: &str) -> bool {
    topic.get(topic.len().saturating_sub(5)..) == Some(".voip")
}

fn validate_alert_topic(topic: &str) -> Result<(), ProviderBuildError> {
    if topic.is_empty() || voip_suffix(topic) || topic == "voip" {
        Err(ProviderBuildError::TopicMismatch)
    } else {
        Ok(())
    }
}

fn validate_voip_topic(topic: &str) -> Result<(), ProviderBuildError> {
    if !voip_suffix(topic) || topic.len() <= 5 {
        Err(ProviderBuildError::TopicMismatch)
    } else {
        Ok(())
    }
}

fn apns_headers(
    input: &ProviderBuildInput<'_>,
    voip: bool,
    collapse: Option<&str>,
) -> Vec<(String, String)> {
    let priority = match input.class {
        WakeClass::CallWake => "10",
        WakeClass::Message => "5",
    };
    let expiration = if voip { "0".to_owned() } else { input.expires_at.to_string() };
    let push_type = if voip { "voip" } else { "alert" };
    let mut headers = vec![
        ("apns-push-type".to_owned(), push_type.to_owned()),
        ("apns-topic".to_owned(), input.topic.to_owned()),
        ("apns-priority".to_owned(), priority.to_owned()),
        ("apns-expiration".to_owned(), expiration),
    ];
    if let Some(key) = collapse {
        headers.push(("apns-collapse-id".to_owned(), key.to_owned()));
    }
    headers
}

fn apns_alert_body(
    wake_id: &str,
    class_name: &'static str,
    collapse: Option<&str>,
) -> Result<Vec<u8>, ProviderBuildError> {
    serde_json::to_vec(&ApnsAlertBody {
        aps: ApnsAlertAps { alert: ApnsAlertText { title: GENERIC_TITLE, body: GENERIC_BODY } },
        wake_id,
        class: class_name,
        collapse_key: collapse,
    })
    .map_err(|_source| ProviderBuildError::PayloadTooLarge)
}

fn apns_voip_body(wake_id: &str, class_name: &'static str) -> Result<Vec<u8>, ProviderBuildError> {
    serde_json::to_vec(&ApnsVoipBody { aps: ApnsEmpty {}, wake_id, class: class_name })
        .map_err(|_source| ProviderBuildError::PayloadTooLarge)
}

fn fcm_body(
    input: &ProviderBuildInput<'_>,
    class_name: &'static str,
    collapse: Option<&str>,
    remaining: u64,
) -> Result<Vec<u8>, ProviderBuildError> {
    let priority = match input.class {
        WakeClass::CallWake => "HIGH",
        WakeClass::Message => "NORMAL",
    };
    let ttl = format!("{remaining}s");
    serde_json::to_vec(&FcmEnvelope {
        message: FcmMessage {
            token: input.token,
            data: FcmData { wake_id: input.wake_id, class: class_name, collapse_key: collapse },
            android: FcmAndroid { priority, ttl, collapse_key: collapse },
        },
    })
    .map_err(|_source| ProviderBuildError::PayloadTooLarge)
}

#[derive(Serialize)]
struct ApnsAlertText {
    title: &'static str,
    body: &'static str,
}

#[derive(Serialize)]
struct ApnsAlertAps {
    alert: ApnsAlertText,
}

#[derive(Serialize)]
struct ApnsAlertBody<'a> {
    aps: ApnsAlertAps,
    wake_id: &'a str,
    class: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,
}

#[derive(Serialize)]
struct ApnsEmpty {}

#[derive(Serialize)]
struct ApnsVoipBody<'a> {
    aps: ApnsEmpty,
    wake_id: &'a str,
    class: &'static str,
}

#[derive(Serialize)]
struct WebPlain<'a> {
    wake_id: &'a str,
    class: &'static str,
    collapse_key: &'a str,
}

#[derive(Serialize)]
struct FcmData<'a> {
    wake_id: &'a str,
    class: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,
}

#[derive(Serialize)]
struct FcmAndroid<'a> {
    priority: &'static str,
    ttl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    collapse_key: Option<&'a str>,
}

#[derive(Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    data: FcmData<'a>,
    android: FcmAndroid<'a>,
}

#[derive(Serialize)]
struct FcmEnvelope<'a> {
    message: FcmMessage<'a>,
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderBuildError, ProviderBuildInput, ProviderWireMode, build_provider_parts,
        ensure_encrypted_web_body_fits, provider_class_for_internal, select_apns_mode,
    };
    use ramflux_protocol::{NotificationDeliveryClass, WakeClass};
    use serde_json::Value;

    fn wake_id() -> String {
        ramflux_protocol::encode_base64url([9_u8; 16])
    }

    fn collapse() -> String {
        ramflux_protocol::encode_base64url([7_u8; 24])
    }

    fn json_of(parts: &super::ProviderRequestParts) -> Result<Value, ProviderBuildError> {
        serde_json::from_slice(&parts.body).map_err(|_source| ProviderBuildError::PayloadTooLarge)
    }

    #[test]
    fn message_alert_fcm_and_web_match_the_contract() -> Result<(), ProviderBuildError> {
        let id = wake_id();
        let key = collapse();
        let alert = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::Message,
            wake_id: &id,
            collapse_key: Some(&key),
            token: "tok",
            topic: "app.bundle",
            expires_at: 2_000,
            now: 1_000,
            mode: ProviderWireMode::ApnsAlert,
        })?;
        let parsed = json_of(&alert)?;
        assert_eq!(parsed["aps"]["alert"]["title"], "Ramflux");
        assert_eq!(parsed["aps"]["alert"]["body"], "You have a new Ramflux update.");
        assert!(parsed["aps"].get("mutable-content").is_none());
        assert!(parsed["aps"].get("content-available").is_none());
        assert_eq!(parsed["class"], "message");
        assert_eq!(parsed["collapse_key"], key);
        assert!(alert.headers.iter().any(|(name, value)| name == "apns-priority" && value == "5"));
        assert!(
            alert.headers.iter().any(|(name, value)| name == "apns-expiration" && value == "2000")
        );
        assert!(
            alert.headers.iter().any(|(name, value)| name == "apns-collapse-id" && value == &key)
        );
        assert!(alert.headers.iter().all(|(name, _)| !name.starts_with("ramflux-")));

        let fcm = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::Message,
            wake_id: &id,
            collapse_key: Some(&key),
            token: "tok",
            topic: "",
            expires_at: 1_000 + 86_400,
            now: 1_000,
            mode: ProviderWireMode::Fcm,
        })?;
        let parsed = json_of(&fcm)?;
        assert!(parsed["message"].get("notification").is_none());
        assert_eq!(parsed["message"]["data"]["class"], "message");
        assert_eq!(parsed["message"]["android"]["priority"], "NORMAL");
        assert_eq!(parsed["message"]["android"]["ttl"], "86400s");
        assert_eq!(fcm.headers.len(), 0);

        let web = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::Message,
            wake_id: &id,
            collapse_key: Some(&key),
            token: "tok",
            topic: "",
            expires_at: 1_100,
            now: 1_000,
            mode: ProviderWireMode::WebPush,
        })?;
        assert!(web.headers.iter().any(|(name, value)| name == "Topic" && value == &key));
        assert!(web.headers.iter().any(|(name, value)| name == "TTL" && value == "100"));
        assert!(web.headers.iter().any(|(name, value)| name == "Urgency" && value == "normal"));
        Ok(())
    }

    #[test]
    fn call_alert_and_voip_omit_collapse_and_voip_expiration_is_zero()
    -> Result<(), ProviderBuildError> {
        let id = wake_id();
        let alert = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::CallWake,
            wake_id: &id,
            collapse_key: None,
            token: "voip-or-alert",
            topic: "app.bundle",
            expires_at: 1_030,
            now: 1_020,
            mode: ProviderWireMode::ApnsAlert,
        })?;
        let parsed = json_of(&alert)?;
        assert_eq!(parsed["class"], "call_wake");
        assert!(parsed.get("collapse_key").is_none());
        assert!(alert.headers.iter().all(|(name, _)| name != "apns-collapse-id"));
        assert!(alert.headers.iter().any(|(name, value)| name == "apns-priority" && value == "10"));
        assert!(
            alert.headers.iter().any(|(name, value)| name == "apns-expiration" && value == "1030")
        );

        let voip = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::CallWake,
            wake_id: &id,
            collapse_key: None,
            token: "pushkit",
            topic: "app.bundle.voip",
            expires_at: 1_030,
            now: 1_000,
            mode: ProviderWireMode::ApnsVoip,
        })?;
        let parsed = json_of(&voip)?;
        assert_eq!(parsed["aps"], serde_json::json!({}));
        assert!(parsed.get("collapse_key").is_none());
        assert!(voip.headers.iter().any(|(name, value)| name == "apns-expiration" && value == "0"));
        assert!(
            voip.headers
                .iter()
                .any(|(name, value)| name == "apns-topic" && value == "app.bundle.voip")
        );
        assert!(
            voip.headers.iter().any(|(name, value)| name == "apns-push-type" && value == "voip")
        );

        let fcm = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::CallWake,
            wake_id: &id,
            collapse_key: None,
            token: "tok",
            topic: "",
            expires_at: 1_030,
            now: 1_020,
            mode: ProviderWireMode::Fcm,
        })?;
        let parsed = json_of(&fcm)?;
        assert!(parsed["message"]["data"].get("collapse_key").is_none());
        assert!(parsed["message"]["android"].get("collapse_key").is_none());
        assert_eq!(parsed["message"]["android"]["priority"], "HIGH");
        assert_eq!(parsed["message"]["android"]["ttl"], "10s");
        assert!(parsed["message"].get("notification").is_none());
        Ok(())
    }

    #[test]
    fn closed_failures_and_conference_never_select_voip() {
        let id = wake_id();
        let key = collapse();
        let expired = build_provider_parts(&ProviderBuildInput {
            class: WakeClass::CallWake,
            wake_id: &id,
            collapse_key: None,
            token: "tok",
            topic: "app.bundle",
            expires_at: 1_030,
            now: 1_030,
            mode: ProviderWireMode::ApnsAlert,
        });
        assert_eq!(expired.err(), Some(ProviderBuildError::Expired));
        assert_eq!(
            build_provider_parts(&ProviderBuildInput {
                class: WakeClass::CallWake,
                wake_id: &id,
                collapse_key: None,
                token: "tok",
                topic: "",
                expires_at: 2_000,
                now: 1_000,
                mode: ProviderWireMode::WebPush,
            })
            .err(),
            Some(ProviderBuildError::WebCallRefused)
        );
        assert_eq!(
            build_provider_parts(&ProviderBuildInput {
                class: WakeClass::Message,
                wake_id: &id,
                collapse_key: Some(&key),
                token: "tok",
                topic: "app.bundle.voip",
                expires_at: 2_000,
                now: 1_000,
                mode: ProviderWireMode::ApnsVoip,
            })
            .err(),
            Some(ProviderBuildError::VoipRequiresCall)
        );
        assert_eq!(
            provider_class_for_internal(&NotificationDeliveryClass::ConferenceWakeNotification),
            WakeClass::Message
        );
        assert_eq!(select_apns_mode(WakeClass::Message, true, true), ProviderWireMode::ApnsAlert);
        assert_eq!(select_apns_mode(WakeClass::CallWake, true, false), ProviderWireMode::ApnsAlert);
        assert_eq!(select_apns_mode(WakeClass::CallWake, true, true), ProviderWireMode::ApnsVoip);
        assert_eq!(ensure_encrypted_web_body_fits(4095), Ok(()));
        assert_eq!(ensure_encrypted_web_body_fits(4096), Err(ProviderBuildError::PayloadTooLarge));
        let huge = "t".repeat(4096);
        assert_eq!(
            build_provider_parts(&ProviderBuildInput {
                class: WakeClass::CallWake,
                wake_id: &id,
                collapse_key: None,
                token: &huge,
                topic: "",
                expires_at: 2_000,
                now: 1_000,
                mode: ProviderWireMode::Fcm,
            })
            .err(),
            Some(ProviderBuildError::PayloadTooLarge)
        );
    }
}
