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
    routes.retain(|route| {
        route.capability == super::DevicePushRoute::capability_for(&route.provider)
    });
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

/// Keep the sealed routes a central wake may use (A6.3, A6.4).
///
/// A route is usable when it is sealed, not marked for reseal, not paused by `unserved`, and its
/// provider is served (`dir.served`). A provider that is not served is never submitted to. An iOS
/// call uses the `VoIP` route when it is usable, otherwise the alert route, never both. `m`, `x`
/// and `t` never use a `VoIP` route. Web Push has no central route.
pub(super) fn select_central_routes(
    routes: Vec<super::DevicePushRoute>,
    class: crate::push_handoff::CentralClass,
    served: &crate::push_handoff::Served,
    now_ms: u64,
) -> Vec<super::DevicePushRoute> {
    use crate::push_handoff::CentralClass;
    let provider_served = |provider: &PushProviderKind| match provider {
        PushProviderKind::Apns => served.apns,
        PushProviderKind::ApnsVoip => served.apns_voip,
        PushProviderKind::Fcm => served.fcm,
        PushProviderKind::WebPush => false,
    };
    let mut routes = routes;
    routes.retain(|route| {
        route.sealed
            && !route.needs_reseal
            && now_ms >= route.unserved_until_ms
            && route.capability == super::DevicePushRoute::capability_for(&route.provider)
            && provider_served(&route.provider)
    });
    let use_voip = class == CentralClass::Call
        && routes.iter().any(|route| route.provider == PushProviderKind::ApnsVoip);
    routes.retain(|route| match route.provider {
        PushProviderKind::ApnsVoip => use_voip,
        PushProviderKind::Apns => !use_voip,
        PushProviderKind::Fcm => true,
        PushProviderKind::WebPush => false,
    });
    routes
}
