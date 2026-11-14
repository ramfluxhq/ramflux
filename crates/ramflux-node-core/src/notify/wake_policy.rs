// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Derived provider policy for an immutable signed `WakeV2`.
//!
//! The signed body is not rewritten. Effective expiry is `min(signed expiry, admission now + class cap)`.
//! Background delivery is unsupported: there is no background builder.

use ramflux_protocol::{
    Ext, NotificationDeliveryClass, NotificationWake, ProtocolError, PushPriority, SignatureAlg,
    SignedFields, SignedWakeV2, WakeAction, WakeClass, effective_expiry,
};

/// Project a shape-valid signed wake into the internal queue row.
///
/// # Errors
/// Returns a contract error when the wake is a cancel, already expired, or not `WakeV2`.
pub fn project_wake_v2(signed: &SignedWakeV2, now: u64) -> Result<NotificationWake, ProtocolError> {
    signed.body.validate_shape()?;
    signed.body.validate_times(now)?;
    if signed.body.action != WakeAction::Enqueue {
        return Err(ProtocolError::NotificationContract("cancel_has_no_provider_push"));
    }
    if signed.body.audience != ramflux_protocol::NOTIFY_WAKE_AUDIENCE {
        return Err(ProtocolError::NotificationContract("audience"));
    }
    let effective = effective_expiry(signed.body.expires_at, now, signed.body.class);
    if now >= effective {
        return Err(ProtocolError::NotificationContract("expires_at"));
    }
    let remaining = effective.saturating_sub(now);
    let ttl = u32::try_from(remaining).unwrap_or(u32::MAX);
    let (delivery_class, priority) = match signed.body.class {
        WakeClass::CallWake => {
            (NotificationDeliveryClass::CallWakeNotification, PushPriority::High)
        }
        WakeClass::Message => {
            (NotificationDeliveryClass::UserContentNotification, PushPriority::Normal)
        }
    };
    Ok(NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
        version: 2,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE_V2.to_owned(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: signed.body.signing_key_id.clone(),
            signature_alg: SignatureAlg::Ed25519,
            signature: signed.signature.clone(),
        },
        wake_id: signed.body.wake_id.clone(),
        push_alias: signed.body.target_delivery_id.clone(),
        delivery_class,
        priority,
        ttl,
        absolute_expires_at: effective,
        collapse_key: None,
        encrypted_hint: None,
    })
}
