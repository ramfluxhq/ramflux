// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Choose which stored routes a wake may use.
//!
//! A call uses the current `VoIP` route when that route is enabled. Otherwise it uses the
//! alert route. One iOS device never receives both. Messages never use a `VoIP` route, and
//! calls are not sent to Web Push.
use super::PushProviderKind;
use ramflux_protocol::NotificationDeliveryClass;

/// `true` when `topic` is an Apple `PushKit` topic (`*.voip`).
#[must_use]
pub fn apns_topic_is_voip(topic: &str) -> bool {
    topic.get(topic.len().saturating_sub(5)..) == Some(".voip")
}

/// `VoIP` sending is off unless the operator set this variable to exactly `1`.
#[must_use]
pub fn voip_push_enabled() -> bool {
    crate::environment::var("RAMFLUX_NOTIFY_APNS_VOIP_ENABLED").as_deref() == Ok("1")
}

/// Keep the routes this wake may send.
///
/// `voip_ready` reports whether a `VoIP` route still has a current `VoIP` credential.
/// A route that is absent, disabled, or not ready falls back to the alert route before send.
pub(super) fn select_wake_routes(
    mut routes: Vec<super::DevicePushRoute>,
    class: &NotificationDeliveryClass,
    voip_enabled: bool,
    mut voip_ready: impl FnMut(&super::DevicePushRoute) -> bool,
) -> Vec<super::DevicePushRoute> {
    let call = matches!(*class, NotificationDeliveryClass::CallWakeNotification);
    let use_voip = call
        && voip_enabled
        && routes
            .iter()
            .any(|route| route.provider == PushProviderKind::ApnsVoip && voip_ready(route));
    routes.retain(|route| match route.provider {
        PushProviderKind::ApnsVoip => use_voip,
        PushProviderKind::Apns => !use_voip,
        PushProviderKind::WebPush => !call,
        PushProviderKind::Fcm => true,
    });
    routes
}
