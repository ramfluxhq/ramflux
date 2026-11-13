// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route binding only: inner author signature, group membership and permissions have separate gates.
use super::*;
use ramflux_protocol::custody::DeviceRef;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> (Route, g::Inner) {
    let source = ramflux_protocol::encode_base64url([1; 32]);
    let target = ramflux_protocol::encode_base64url([2; 32]);
    let route = Route {
        version: 1,
        source: DeviceRef {
            account_anchor: source.clone(),
            device_id: "phone".into(),
            device_epoch: 1,
        },
        recipient_root: target,
        conversation_id: "conversation".into(),
        traffic: Traffic::Dm,
        envelope_hash: ramflux_protocol::encode_base64url([3; 32]),
        authority_head_hash: ramflux_protocol::encode_base64url([4; 32]),
        issued_at: 1_760_000_000,
        expires_at: 1_760_003_600,
    };
    let inner = g::Inner {
        layer: 1,
        kind: 1,
        identity: Some(g::EventIdentity {
            conversation_id: route.conversation_id.clone(),
            author: Some(g::QualifiedDevice {
                account_anchor: source,
                device_id: "phone".into(),
                device_epoch: 1,
            }),
            ..Default::default()
        }),
        body: Vec::new(),
    };
    (route, inner)
}
#[test]
fn cr_decrypted_kind_and_identity_cannot_borrow_a_dm_label() -> TestResult {
    let (route, inner) = fixture();
    bind_inner(&route, &inner)?;
    let mut changed = inner.clone();
    changed.kind = 6;
    assert!(
        bind_inner(&route, &changed).is_err(),
        "a receipt cannot inherit ordinary DM permission"
    );
    changed.kind = 12;
    assert!(bind_inner(&route, &changed).is_err(), "a foreign DM cannot claim same-root SelfSync");
    changed = inner.clone();
    changed.identity.as_mut().ok_or("identity")?.group_id = Some("group".into());
    assert!(
        bind_inner(&route, &changed).is_err(),
        "group content must use group admission and membership"
    );
    changed = inner;
    changed.identity.as_mut().ok_or("identity")?.author.as_mut().ok_or("author")?.device_epoch = 2;
    assert!(
        bind_inner(&route, &changed).is_err(),
        "inner author incarnation must equal the signed branch route"
    );
    Ok(())
}
#[test]
fn cr_same_root_label_does_not_authorize_a2i_or_arbitrary_own_copy() -> TestResult {
    let (mut route, mut inner) = fixture();
    route.recipient_root = route.source.account_anchor.clone();
    route.traffic = Traffic::OwnCopy;
    assert!(
        bind_inner(&route, &inner).is_err(),
        "same-root does not turn ordinary content into an own copy"
    );
    inner.kind = 8;
    inner.body = g::Control { operation: 11, ..Default::default() }.encode_to_vec();
    assert!(
        matches!(
            bind_inner(&route, &inner),
            Err(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                ..
            })
        ),
        "a pair signature cannot activate Control11 authority"
    );
    inner.body = g::Control { operation: 15, ..Default::default() }.encode_to_vec();
    bind_inner(&route, &inner)?;
    Ok(())
}

#[test]
fn cr_group_route_keeps_distinct_signed_conversation_and_group_ids() -> TestResult {
    let (mut route, mut inner) = fixture();
    route.traffic = Traffic::Group;
    let identity = inner.identity.as_mut().ok_or("identity")?;
    identity.group_id = Some("different-group-id".into());
    identity.group_epoch = Some(1);
    bind_inner(&route, &inner)?;
    inner.identity.as_mut().ok_or("identity")?.conversation_id = "other-thread".into();
    assert!(
        bind_inner(&route, &inner).is_err(),
        "group identity may have its own group id but cannot change the signed conversation"
    );
    Ok(())
}
