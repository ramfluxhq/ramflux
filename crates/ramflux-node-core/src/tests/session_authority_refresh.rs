// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session-open authority is never reused after sibling activation or revocation.
use super::*;
#[test]
fn old_session_refreshes_set_before_cross_node_delivery_and_revocation_refuses_it()
-> Result<(), Box<dyn std::error::Error>> {
    let router = RouterCore::new();
    let first = registration_request(&router, "alice", "first", 1, None, "192.0.2.1")?;
    router.mvp1_register_identity(&first)?;
    let mut message = signed_registered_envelope(
        envelope("long-lived-session", "peer", DeliveryClass::OpaqueEvent),
        "alice",
        "first",
        1,
    )?;
    router.refresh_registered_envelope_authority(&mut message)?;
    let stale = message.ext.ext["source_device_authority"].clone();
    let sibling = registration_request(&router, "alice", "second", 2, None, "192.0.2.1")?;
    router.mvp1_register_identity(&sibling)?;
    router.refresh_registered_envelope_authority(&mut message)?;
    let (authority, _) = DeviceAuthKeyResponse::forwarded_envelope_source(&message)?;
    let latest = authority.signed_device_set.ok_or("set")?;
    assert_eq!(latest.device_set_epoch, 2);
    assert_ne!(message.ext.ext["source_device_authority"], stale);
    let remote = RouterCore::new();
    let source = remote.authenticated_envelope_source_from(
        &message,
        None,
        RouterEnvelopeOrigin::Federation,
    )?;
    assert!(matches!(
        remote.submit_envelope_at(&source, message.clone(), message.created_at),
        RouterSubmitOutcome::OfflineQueued(_)
    ));
    let root = ramflux_crypto::create_identity_root(
        "alice",
        ramflux_crypto::blake3_256("ramflux.test.registration_root.v1", b"alice"),
    );
    let mut devices = latest.devices;
    let device = devices.iter_mut().find(|d| d.device_id == "first").ok_or("first")?;
    device.status = ramflux_protocol::DeviceSetStatus::Revoked;
    device.revoked_at = Some(first.now + 5);
    let next = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 3,
            devices,
        },
    )?;
    let store = RouterRedbStore::open(temp_store_path("session-revocation")?)?;
    router.publish_signed_device_set(
        &crate::DeviceSetPublishRequest { root_public_key: first.root_public_key, record: next },
        &store,
    )?;
    message.ext.ext.insert("source_device_authority".into(), stale);
    assert!(matches!(
        router.authenticated_envelope_source(&message),
        Err(crate::NodeCoreError::SourceAuthorityRefused {
            reason_code: crate::EnvelopeAuthorityReason::Revoked
        })
    ));
    assert!(router.refresh_registered_envelope_authority(&mut message).is_err());
    assert!(router.authenticated_envelope_source(&message).is_err());
    Ok(())
}
#[test]
fn federation_new_root_budget_is_per_peer_durable_and_does_not_charge_known_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("peer-root-budget")?;
    let store = FederationRedbStore::open(&path)?;
    let now = 1_760_000_010;
    let mut last = None;
    for i in 0_u64..65 {
        let root = ramflux_crypto::create_identity_root(
            &format!("root-{i}"),
            ramflux_crypto::blake3_256("ramflux.test.peer-budget.v1", &i.to_be_bytes()),
        );
        let forward =
            super::federation::root_bound_forward(&root, "device", None, &format!("new-{i}"))?;
        let (_, source) = DeviceAuthKeyResponse::forwarded_envelope_source(&forward.envelope)?;
        let result = store.accept_inbound_forward_once(&source, &forward, now);
        if i < 64 {
            assert!(result?);
        } else {
            assert!(matches!(
                result,
                Err(NodeCoreError::Capacity { resource: "foreign_roots_per_peer" })
            ));
            last = Some((source, forward));
        }
    }
    drop(store);
    let store = FederationRedbStore::open(&path)?;
    let (source, mut forward) = last.ok_or("last")?;
    assert!(matches!(
        store.accept_inbound_forward_once(&source, &forward, now + 1),
        Err(NodeCoreError::Capacity { resource: "foreign_roots_per_peer" })
    ));
    forward.source_node_id = "another-authenticated-peer".into();
    assert!(store.accept_inbound_forward_once(&source, &forward, now + 1)?);
    forward.source_node_id = "node_a.example".into();
    assert!(store.accept_inbound_forward_once(&source, &forward, now + 1)?);
    Ok(())
}
