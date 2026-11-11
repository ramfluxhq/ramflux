// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate client delivery classes (S10a P08). Live six-value enum stays until P24.

use crate::{DeliveryClass, NotificationDeliveryClass, ProtocolError};

/// Decision 4 client classes. Only invitation production is `CallWake`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientDeliveryClass {
    Message,
    CallWake,
}

/// Provider mapping after class/mode. Typing never reaches here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPush {
    MessageWake,
    CallWakeVoip,
    None,
}

/// Map a live envelope class onto the two client classes.
///
/// # Errors
/// Object and federation-control values are not client envelope classes.
pub fn client_class_from_delivery(
    class: &DeliveryClass,
) -> Result<ClientDeliveryClass, ProtocolError> {
    match class {
        DeliveryClass::Message | DeliveryClass::OpaqueEvent | DeliveryClass::SelfDeviceControl => {
            Ok(ClientDeliveryClass::Message)
        }
        DeliveryClass::CallWake | DeliveryClass::NotificationWake => {
            Ok(ClientDeliveryClass::CallWake)
        }
        DeliveryClass::ObjectManifest
        | DeliveryClass::ObjectChunk
        | DeliveryClass::FederationControl => Err(ProtocolError::InvalidDomain {
            expected: "message|call_wake",
            actual: format!("{class:?}"),
        }),
    }
}

/// Map a notification class. Conference invitations are `call_wake`, never message.
#[must_use]
pub fn client_class_from_notification(class: &NotificationDeliveryClass) -> ClientDeliveryClass {
    match class {
        NotificationDeliveryClass::CallWakeNotification
        | NotificationDeliveryClass::ConferenceWakeNotification => ClientDeliveryClass::CallWake,
        NotificationDeliveryClass::SelfDeviceControlNotification
        | NotificationDeliveryClass::UserContentNotification
        | NotificationDeliveryClass::AiTaskNotification
        | NotificationDeliveryClass::A2uiSurfaceNotification => ClientDeliveryClass::Message,
    }
}

/// Shared class-to-provider policy. Ephemeral traffic has no provider request.
#[must_use]
pub fn provider_push(class: ClientDeliveryClass, ephemeral: bool) -> ProviderPush {
    if ephemeral {
        return ProviderPush::None;
    }
    match class {
        ClientDeliveryClass::Message => ProviderPush::MessageWake,
        ClientDeliveryClass::CallWake => ProviderPush::CallWakeVoip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_classes_producers_consumers_and_push_mapping() {
        let delivery = [
            (DeliveryClass::OpaqueEvent, Ok(ClientDeliveryClass::Message)),
            (DeliveryClass::SelfDeviceControl, Ok(ClientDeliveryClass::Message)),
            (DeliveryClass::NotificationWake, Ok(ClientDeliveryClass::CallWake)),
            (DeliveryClass::ObjectManifest, Err(())),
            (DeliveryClass::ObjectChunk, Err(())),
            (DeliveryClass::FederationControl, Err(())),
        ];
        for (class, want) in delivery {
            assert_eq!(client_class_from_delivery(&class).ok(), want.ok());
        }
        let notifications = [
            (
                NotificationDeliveryClass::SelfDeviceControlNotification,
                ClientDeliveryClass::Message,
            ),
            (NotificationDeliveryClass::UserContentNotification, ClientDeliveryClass::Message),
            (NotificationDeliveryClass::AiTaskNotification, ClientDeliveryClass::Message),
            (NotificationDeliveryClass::A2uiSurfaceNotification, ClientDeliveryClass::Message),
            (NotificationDeliveryClass::CallWakeNotification, ClientDeliveryClass::CallWake),
            (NotificationDeliveryClass::ConferenceWakeNotification, ClientDeliveryClass::CallWake),
        ];
        for (class, want) in notifications {
            assert_eq!(client_class_from_notification(&class), want);
            let ephemeral = provider_push(want, true);
            assert_eq!(ephemeral, ProviderPush::None);
            let durable = provider_push(want, false);
            match want {
                ClientDeliveryClass::Message => assert_eq!(durable, ProviderPush::MessageWake),
                ClientDeliveryClass::CallWake => assert_eq!(durable, ProviderPush::CallWakeVoip),
            }
        }
    }

    #[test]
    fn conference_invite_maps_to_call_wake() {
        let class =
            client_class_from_notification(&NotificationDeliveryClass::ConferenceWakeNotification);
        assert_eq!(class, ClientDeliveryClass::CallWake);
        assert_ne!(class, ClientDeliveryClass::Message);
        assert_eq!(provider_push(class, false), ProviderPush::CallWakeVoip);
    }
}
