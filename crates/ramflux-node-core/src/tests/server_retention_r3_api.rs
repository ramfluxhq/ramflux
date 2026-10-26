// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r2 follow-ups that need new APIs: checkpoint retry and explicit deregistration.
use super::*;

#[test]
fn failed_checkpoint_saves_are_retried_not_dropped() {
    let mut inbox = OpaqueDeviceInbox::new();
    let mut message = envelope("expiring", "mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = 1_000;
    message.ttl = 10;
    inbox.append_at(message, 1_000);
    let _creation = inbox.take_checkpoint_due();
    assert_eq!(inbox.expire(1_010), 1);
    let due = inbox.take_checkpoint_due();
    assert_eq!(due.len(), 1);
    // The store write failed: the cursor stays due for the next sweep.
    inbox.requeue_checkpoints(due.iter().map(|cursor| cursor.target_delivery_id.clone()));
    let retried = inbox.take_checkpoint_due();
    assert_eq!(retried, due);
}

#[test]
fn explicit_deregistration_deletes_only_the_bound_owners_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut store = NotifyRedbStore::open_with_route_key(
        temp_store_path("r3_deregister")?,
        NodeSecret::ephemeral()?,
    )?;
    store.set_push_route_authorizer(|_| Ok(true));
    let mut open = gateway_open_frame("phone", "stream");
    open.target_delivery_id = "dereg-delivery".into();
    let owner = gateway_registered_key(&open)?;
    let now = now_unix_seconds();
    let mut route = notify_webpush_route("dereg-delivery", "web");
    route.registered_at = now;
    route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
    store.register_authenticated_push_route(&owner, &route)?;
    let mut stranger_open = gateway_open_frame("tablet", "stream");
    stranger_open.target_delivery_id = "dereg-delivery".into();
    let stranger = gateway_registered_key(&stranger_open)?;
    assert!(store.delete_authenticated_push_routes(&stranger, None).is_err());
    assert_eq!(store.delete_authenticated_push_routes(&owner, Some(&PushProviderKind::Fcm))?, 0);
    assert_eq!(store.delete_authenticated_push_routes(&owner, None)?, 1);
    assert_eq!(store.load_state()?.unwrap_or_default().push_routes("dereg-delivery", now).len(), 0);
    Ok(())
}

#[test]
fn route_deletion_controls_are_domain_separated_from_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let key = NodeServiceSigningKey::from_seed([29; 32]);
    let body = PushRouteDeleteBody {
        authority: gateway_registered_key(&gateway_open_frame("phone", "stream"))?,
        provider: None,
        issued_at: 100,
        client_seq: None,
    };
    let bytes = ramflux_protocol::canonical_json_bytes(&body)?;
    let control = PushRouteDeleteControl {
        body: body.clone(),
        signature: key.sign_push_route_delete(&bytes),
    };
    control.verify(&key, 100)?;
    let cross = PushRouteDeleteControl { body, signature: key.sign_push_route_control(&bytes) };
    assert!(cross.verify(&key, 100).is_err());
    Ok(())
}
