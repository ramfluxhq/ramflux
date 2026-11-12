// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional push wake handling. Nothing in the core needs a push provider.
//!
//! Send and receive complete on the foreground connection. A push only tells the
//! application to show the fixed generic notification, or that a call is ringing. A build
//! without the `android-push-fcm` feature contains no vendor-push provider at all, and a
//! device without Google Play services simply reports [`NotificationMode::ForegroundOnly`].
//!
//! The wake payload is three opaque fields at most. Anything else in a provider message is
//! refused, so a server regression that leaks an identifier is visible on the device.

use std::time::Duration;

/// A call wake older than this is stale and must not ring.
pub const CALL_WAKE_LIFETIME: Duration = Duration::from_secs(30);
const MAX_WAKE_ID_LEN: usize = 128;

/// Push providers this build can register with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushProvider {
    /// Firebase Cloud Messaging. Present only with the `android-push-fcm` feature.
    #[cfg(feature = "android-push-fcm")]
    Fcm,
}

/// The providers compiled into this build. Empty by default.
#[must_use]
pub const fn compiled_push_providers() -> &'static [PushProvider] {
    &[
        #[cfg(feature = "android-push-fcm")]
        PushProvider::Fcm,
    ]
}

/// How the user learns about new messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationMode {
    /// A provider is compiled in and the host registered a token with it.
    Push(PushProvider),
    /// No provider: messages arrive while the application is open, and there is no
    /// notification while it is not. Send and receive are unaffected.
    ForegroundOnly,
}

/// Choose the notification mode. `host_registered` is the provider the host obtained a
/// token from at runtime, which is `None` on a device without that provider's services.
#[must_use]
pub fn notification_mode(host_registered: Option<PushProvider>) -> NotificationMode {
    host_registered
        .filter(|provider| compiled_push_providers().contains(provider))
        .map_or(NotificationMode::ForegroundOnly, NotificationMode::Push)
}

/// The client class a wake carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeClass {
    Message,
    CallWake,
}

/// Why a provider message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeRefusal {
    /// A field other than `wake_id` and `class` is present.
    UnexpectedField,
    /// `wake_id` or `class` is missing or repeated.
    MissingField,
    /// `class` is not `message` or `call_wake`.
    UnknownClass,
    /// `wake_id` is empty, too long, or not an opaque token.
    MalformedWakeId,
}

/// A validated wake. The wake id is opaque and is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct WakePayload {
    class: WakeClass,
    wake_id: String,
}

impl std::fmt::Debug for WakePayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WakePayload").field("class", &self.class).finish_non_exhaustive()
    }
}

impl WakePayload {
    /// Validate the data fields of a provider message.
    ///
    /// # Errors
    /// A [`WakeRefusal`] when the message is not exactly an opaque wake id and a class.
    pub fn parse<'a>(
        fields: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, WakeRefusal> {
        let mut class = None;
        let mut wake_id = None;
        for (name, value) in fields {
            let slot = match name {
                "class" => &mut class,
                "wake_id" => &mut wake_id,
                _ => return Err(WakeRefusal::UnexpectedField),
            };
            if slot.replace(value).is_some() {
                return Err(WakeRefusal::MissingField);
            }
        }
        let class = match class.ok_or(WakeRefusal::MissingField)? {
            "message" => WakeClass::Message,
            "call_wake" => WakeClass::CallWake,
            _ => return Err(WakeRefusal::UnknownClass),
        };
        let wake_id = wake_id.ok_or(WakeRefusal::MissingField)?;
        let opaque = !wake_id.is_empty()
            && wake_id.len() <= MAX_WAKE_ID_LEN
            && wake_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            // The retired form embedded an envelope id after this prefix.
            && !wake_id.starts_with("wake_");
        if !opaque {
            return Err(WakeRefusal::MalformedWakeId);
        }
        Ok(Self { class, wake_id: wake_id.to_owned() })
    }

    #[must_use]
    pub const fn class(&self) -> WakeClass {
        self.class
    }

    /// The opaque id, for de-duplicating a redelivered wake. Not for logs.
    #[must_use]
    pub fn wake_id(&self) -> &str {
        &self.wake_id
    }
}

/// What the host does with a wake. No variant opens the store or a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeAction {
    /// Post the fixed generic notification. The text contains no sender and no preview.
    PostGenericNotification,
    /// Report an incoming call to the telecom framework; stop ringing after `remaining`.
    RingCall { remaining: Duration },
    /// A call wake that outlived its lifetime, or whose send time is unknown.
    Ignore,
}

/// Decide what to do with a validated wake.
///
/// `sent_at` and `now` are milliseconds since the Unix epoch: the provider's send time for
/// the message and the device clock.
#[must_use]
pub fn wake_action(payload: &WakePayload, sent_at: Option<u64>, now: u64) -> WakeAction {
    match payload.class {
        WakeClass::Message => WakeAction::PostGenericNotification,
        WakeClass::CallWake => {
            let Some(sent_at) = sent_at else {
                return WakeAction::Ignore;
            };
            let age = Duration::from_millis(now.saturating_sub(sent_at));
            match CALL_WAKE_LIFETIME.checked_sub(age) {
                Some(remaining) if !remaining.is_zero() => WakeAction::RingCall { remaining },
                _ => WakeAction::Ignore,
            }
        }
    }
}

/// A provider registration token. It identifies the device to the provider, so it is kept
/// out of `Debug` output and logs.
#[cfg(feature = "android-push-fcm")]
#[derive(Clone, PartialEq, Eq)]
pub struct PushToken(zeroize::Zeroizing<String>);

#[cfg(feature = "android-push-fcm")]
impl PushToken {
    /// Wrap a token the host obtained from the provider.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(zeroize::Zeroizing::new(token))
    }

    /// The token, for the registration request to the user's own node.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A short hash for log correlation that does not reveal the token.
    #[must_use]
    pub fn log_label(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ramflux.android.push_token_label.v1\0");
        hasher.update(self.0.as_bytes());
        hasher.finalize().to_hex()[..12].to_owned()
    }
}

#[cfg(feature = "android-push-fcm")]
impl std::fmt::Debug for PushToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("PushToken").field(&self.log_label()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAKE_ID: &str = "pZ3n0q9wTtq2m8Vb1cXyAg";

    #[test]
    fn default_build_has_no_push_provider_and_degrades_to_foreground_only() {
        #[cfg(not(feature = "android-push-fcm"))]
        assert!(compiled_push_providers().is_empty());
        assert_eq!(notification_mode(None), NotificationMode::ForegroundOnly);
    }

    #[cfg(feature = "android-push-fcm")]
    #[test]
    fn fcm_is_used_only_when_the_host_registered_it() {
        assert_eq!(compiled_push_providers(), &[PushProvider::Fcm]);
        assert_eq!(
            notification_mode(Some(PushProvider::Fcm)),
            NotificationMode::Push(PushProvider::Fcm)
        );
        assert_eq!(notification_mode(None), NotificationMode::ForegroundOnly);
        let token = PushToken::new("device-token-value".to_owned());
        assert!(!format!("{token:?}").contains("device-token-value"));
    }

    #[test]
    fn manifest_keeps_vendor_push_optional() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
        assert!(manifest.contains("\ndefault = []\n"), "a default feature was added");
        assert!(
            manifest.contains("\nandroid-push-fcm = []\n"),
            "the push feature gained a dependency"
        );
        for vendor in ["firebase", "fcm =", "gms", "play-services"] {
            let lowered = manifest.to_lowercase();
            let hits = lowered.matches(vendor).count();
            let allowed = usize::from(vendor == "fcm =");
            assert!(hits <= allowed, "manifest references {vendor}");
        }
        Ok(())
    }

    #[test]
    fn wake_with_only_id_and_class_is_accepted() {
        let wake = WakePayload::parse([("wake_id", WAKE_ID), ("class", "message")]);
        assert_eq!(wake.as_ref().map(WakePayload::class), Ok(WakeClass::Message));
        let wake = WakePayload::parse([("class", "call_wake"), ("wake_id", WAKE_ID)]);
        assert_eq!(wake.as_ref().map(WakePayload::class), Ok(WakeClass::CallWake));
    }

    #[test]
    fn wake_carrying_any_other_field_is_refused() {
        for leaked in [
            "envelope_id",
            "conversation_id",
            "sender",
            "encrypted_hint",
            "ciphertext",
            "preview",
            "body",
            "title",
        ] {
            let wake =
                WakePayload::parse([("wake_id", WAKE_ID), ("class", "message"), (leaked, "x")]);
            assert_eq!(wake, Err(WakeRefusal::UnexpectedField), "{leaked}");
        }
    }

    #[test]
    fn malformed_wakes_are_refused() {
        let cases = [
            (vec![("class", "message")], WakeRefusal::MissingField),
            (vec![("wake_id", WAKE_ID)], WakeRefusal::MissingField),
            (
                vec![("wake_id", WAKE_ID), ("wake_id", WAKE_ID), ("class", "message")],
                WakeRefusal::MissingField,
            ),
            (vec![("wake_id", WAKE_ID), ("class", "conference_wake")], WakeRefusal::UnknownClass),
            (vec![("wake_id", ""), ("class", "message")], WakeRefusal::MalformedWakeId),
            (
                vec![("wake_id", "wake_0193a7c2"), ("class", "message")],
                WakeRefusal::MalformedWakeId,
            ),
            (
                vec![("wake_id", "target:abc:content"), ("class", "message")],
                WakeRefusal::MalformedWakeId,
            ),
        ];
        for (fields, refusal) in cases {
            assert_eq!(WakePayload::parse(fields), Err(refusal));
        }
    }

    #[test]
    fn debug_output_omits_the_wake_id() {
        let wake = WakePayload::parse([("wake_id", WAKE_ID), ("class", "message")]);
        assert!(!format!("{wake:?}").contains(WAKE_ID));
    }

    #[test]
    fn message_wake_posts_the_generic_notification() {
        let wake = WakePayload::parse([("wake_id", WAKE_ID), ("class", "message")]);
        let action = wake.map(|wake| wake_action(&wake, None, 1_000));
        assert_eq!(action, Ok(WakeAction::PostGenericNotification));
    }

    #[test]
    fn call_wake_rings_only_inside_thirty_seconds() {
        let Ok(wake) = WakePayload::parse([("wake_id", WAKE_ID), ("class", "call_wake")]) else {
            return;
        };
        assert_eq!(
            wake_action(&wake, Some(100_000), 110_000),
            WakeAction::RingCall { remaining: Duration::from_secs(20) }
        );
        assert_eq!(wake_action(&wake, Some(100_000), 130_000), WakeAction::Ignore);
        assert_eq!(wake_action(&wake, Some(100_000), 500_000), WakeAction::Ignore);
        assert_eq!(wake_action(&wake, None, 110_000), WakeAction::Ignore);
        // A device clock behind the provider clock still rings for the full lifetime at most.
        assert_eq!(
            wake_action(&wake, Some(100_000), 90_000),
            WakeAction::RingCall { remaining: CALL_WAKE_LIFETIME }
        );
    }
}
