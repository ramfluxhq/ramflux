// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer controls 5/9/11/12 through the real seal, open and W1 receive path.
use super::*;
use crate::client::recovery::{
    SdkGuardianAcceptMessage, SdkGuardianInviteMessage, SdkGuardianRecoveryShare,
};

const APPLIED: &str = "routed/native-control-applied/";

fn scope(a: &Fixture, b: &Fixture) -> Result<String, SdkError> {
    g::dm_scope::derive(&a.client.own_account_anchor()?, &b.client.own_account_anchor()?)
        .map_err(|_| invalid("DM scope"))
}

/// Seal producer bytes on the direct control route.
fn seal_control(
    a: &Fixture,
    b: &Fixture,
    id: &str,
    raw: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    let mut draft = message(id, &scope(a, b)?);
    draft.envelope_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    draft.source_principal_id = a.config()?.principal_id;
    draft.sender_id = a.id.clone();
    draft.recipient_device_id = Some(b.reference()?);
    seal_as(a, b, draft, raw, Route::control())
}

/// Hand-built Control with a fixed event id, so a changed payload can reuse the identity.
fn manual_entry(
    a: &Fixture,
    b: &Fixture,
    id: &str,
    control: &g::Control,
    unknown: bool,
) -> Result<GatewayInboxEntry, SdkError> {
    let mut body = control.encode_to_vec();
    if unknown {
        body.extend_from_slice(&[0xf8, 0x07, 1]);
    }
    let conversation = scope(a, b)?;
    let mut identity = generated_identity(a, id)?;
    identity.conversation_id = conversation.clone();
    identity.id = g::identity::derive(
        identity.author.as_ref().ok_or_else(|| invalid("author"))?,
        &conversation,
        identity.device_sequence,
    )
    .map_err(|_| invalid("control identity"))?
    .to_vec();
    let raw =
        g::Inner { layer: g::registry::COMPILED_LAYER, kind: 8, identity: Some(identity), body }
            .encode_to_vec();
    seal_control(a, b, id, &raw)
}

fn signed_fields(device: &str) -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: device.into(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: String::new(),
    }
}

fn invite(
    owner: &Fixture,
    guardian: &Fixture,
    id: &str,
) -> Result<SdkGuardianInviteMessage, SdkError> {
    let branch = owner.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let target = guardian.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let now = crate::time::now_unix_timestamp();
    let mut invite = SdkGuardianInviteMessage {
        schema: "ramflux.sdk.recovery.guardian_invite.v1".into(),
        version: 1,
        invite_id: id.into(),
        inviter_principal_id: branch.principal_id.clone(),
        inviter_device_id: branch.device_id.clone(),
        inviter_device_epoch: branch.device_epoch,
        inviter_device_public_key_base64url: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        guardian_principal_id: target.principal_id.clone(),
        recovery_quorum_id: "quorum".into(),
        share: SdkGuardianRecoveryShare {
            share_id: 2,
            threshold: 2,
            total: 3,
            member_kind: ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
            value_base64: ramflux_protocol::encode_base64url([0x33u8; 32]),
        },
        issued_at: now,
        expires_at: now + 300,
        signed: signed_fields(&branch.device_id),
    };
    invite.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &invite)?;
    Ok(invite)
}

fn accept(
    guardian: &Fixture,
    invite: &SdkGuardianInviteMessage,
) -> Result<SdkGuardianAcceptMessage, SdkError> {
    let branch = guardian.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut accept = SdkGuardianAcceptMessage {
        schema: "ramflux.sdk.recovery.guardian_accept.v1".into(),
        version: 1,
        accept_id: format!("guardian_accept:{}", invite.invite_id),
        invite_id: invite.invite_id.clone(),
        owner_principal_id: invite.inviter_principal_id.clone(),
        guardian_principal_id: branch.principal_id.clone(),
        guardian_device_id: branch.device_id.clone(),
        guardian_device_epoch: branch.device_epoch,
        guardian_device_public_key_base64url: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        recovery_quorum_id: invite.recovery_quorum_id.clone(),
        accepted_at: crate::time::now_unix_timestamp(),
        signed: signed_fields(&branch.device_id),
    };
    accept.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &accept)?;
    Ok(accept)
}

fn a2i_event(
    a: &Fixture,
    b: &Fixture,
    id: &str,
) -> Result<ramflux_protocol::A2iControlEvent, SdkError> {
    let branch = a.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut event: ramflux_protocol::A2iControlEvent = serde_json::from_value(serde_json::json!({
        "schema": ramflux_protocol::domain::A2I_CONTROL,
        "version": 1,
        "domain": ramflux_protocol::domain::A2I_CONTROL,
        "signing_key_id": branch.device_id,
        "signature_alg": "ed25519",
        "signature": "",
        "event_type": "a2i.control",
        "control_domain": "mcp_tool",
        "action": "approve",
        "subject": {"tool": "search", "n": 1},
        "correlation_id": id,
        "source_device_id": branch.device_id,
        "target_device_id": b.client.owned_device_identity()?.device_id(),
    }))?;
    event.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &event)?;
    Ok(event)
}

fn refused<T>(result: &Result<T, SdkError>, code: crate::error::GeneratedRefusalCode) -> bool {
    matches!(result, Err(SdkError::GeneratedRefused { code: got, .. }) if *got == code)
}

async fn run(b: &mut Fixture, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    apply(b, entry).await.map(|_| ())
}

async fn received_object_reference(author: &Fixture, receiver: &mut Fixture, id: &str) -> Result<(), SdkError> {
    commit_content(author, receiver, id, g::content::Value::Message(g::Message {
        text: "received object message".into(), ..Default::default()
    })).await?;
    let message = ramflux_protocol::encode_base64url(generated_identity(author, id)?.id);
    let db = receiver.client.account_db()?;
    let reference = serde_json::json!({"reference":{"object_id":"obj-1","manifest_hash":"manifest"}});
    let metadata = serde_json::json!({"owner":author.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id,
        "message_id":message,"conversation_id":"c"});
    db.register_object_reference(ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: "received-reference", wire_id: "obj-1", manifest_hash: "manifest",
            selector: "obj-1", message_id: &message, reference: &reference, metadata: &metadata,
        })?;
    db.persist_client_record("object", "obj-1", &metadata)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_object_revoke_requires_the_owner_of_the_received_reference()
-> Result<(), SdkError> {
    use crate::error::GeneratedRefusalCode::Authority;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let revoke = |b: &Fixture| -> Result<g::Control, SdkError> {
        Ok(g::Control {
            operation: 12,
            payload: Some(g::control::Payload::ObjectRevoke(g::ObjectRevokeAccess {
                object_id: "obj-1".into(),
                recipient_principal_id: b.client.own_account_anchor()?,
                link_id: "link".into(),
                reason: "removed".into(),
                effective_at: 9,
            })),
        })
    };
    // The object belongs to a third root: the authenticated sender cannot revoke it.
    let (a, mut b) = pair(201, 203)?;
    let other = Fixture::new("third", 231)?;
    b.client.establish_friend_link("third-link", &other.client.own_account_anchor()?, &b.client.own_account_anchor()?)?;
    received_object_reference(&other, &mut b, "third-object-message").await?;
    let db = b.client.account_db()?;
    let mut display = db.client_record("object", "obj-1")?.ok_or_else(|| invalid("reference"))?;
    display["owner"] = serde_json::json!("alice");
    db.persist_client_record("object", "obj-1", &display)?;
    let entry = manual_entry(&a, &b, "revoke-foreign", &revoke(&b)?, true)?;
    assert!(refused(&run(&mut b, &entry).await, Authority), "foreign revoke executed");
    assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 0);
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);

    // A revoke for a reference this account never received is refused, not deferred.
    let (a, mut b) = pair(205, 207)?;
    let entry = manual_entry(&a, &b, "revoke-missing", &revoke(&b)?, false)?;
    assert!(refused(&run(&mut b, &entry).await, Authority), "revoke invented a reference");

    // The owner's revoke reaches the native tombstone once; replay is exact.
    let (a, mut b) = pair(209, 211)?;
    received_object_reference(&a, &mut b, "owned-object-message").await?;
    let entry = manual_entry(&a, &b, "revoke-own", &revoke(&b)?, false)?;
    run(&mut b, &entry).await?;
    assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 1);
    assert!(
        b.client.account_db()?.object_is_tombstoned("obj-1")?,
        "native object tombstone missing after owner revoke"
    );
    let repeat = manual_entry(&a, &b, "revoke-own", &revoke(&b)?, false)?;
    run(&mut b, &repeat).await?;
    assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 1);
    let mut changed = revoke(&b)?;
    if let Some(g::control::Payload::ObjectRevoke(body)) = changed.payload.as_mut() {
        body.reason = "other".into();
    }
    let conflict = manual_entry(&a, &b, "revoke-own", &changed, false)?;
    assert!(matches!(run(&mut b, &conflict).await, Err(SdkError::ReplayMismatch)));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_recovery_invite_waits_for_local_acceptance_and_needs_contact_and_signature()
-> Result<(), SdkError> {
    use crate::error::GeneratedRefusalCode::Authority;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    // No accepted contact link: refused before any share is stored.
    let (a, mut b) = pair(213, 215)?;
    b.client.remove_friend_link("link", "both")?;
    let native = invite(&a, &b, "invite-no-contact")?;
    let raw = a.client.generated_guardian_invite_inner(&native, &b.client.own_account_anchor()?)?;
    let entry = seal_control(&a, &b, "invite-no-contact", &raw)?;
    assert!(run(&mut b, &entry).await.is_err(), "invite accepted without contact");
    assert_eq!(b.client.pending_guardian_invites()?.len(), 0);

    // A signature that does not cover the delivered fields is refused.
    let (a, mut b) = pair(217, 219)?;
    let mut forged = invite(&a, &b, "invite-forged")?;
    forged.expires_at += 1;
    let raw = a.client.generated_guardian_invite_inner(&forged, &b.client.own_account_anchor()?)?;
    let entry = seal_control(&a, &b, "invite-forged", &raw)?;
    assert!(refused(&run(&mut b, &entry).await, Authority), "forged invite admitted");
    assert_eq!(b.client.pending_guardian_invites()?.len(), 0);

    // Verified invite: stored as pending, never as an accepted share; producer retry and
    // redelivery reuse the same event and leave exactly one row.
    let (a, mut b) = pair(221, 223)?;
    let native = invite(&a, &b, "invite-good")?;
    let guardian_root = b.client.own_account_anchor()?;
    let raw = a.client.generated_guardian_invite_inner(&native, &guardian_root)?;
    let retry = a.client.generated_guardian_invite_inner(&native, &guardian_root)?;
    assert_eq!(raw.as_slice(), retry.as_slice(), "producer retry changed the captured event");
    let entry = seal_control(&a, &b, "invite-good", &raw)?;
    run(&mut b, &entry).await?;
    assert_eq!(b.client.pending_guardian_invites()?.first().map(|row| &row.invite), Some(&native));
    assert!(
        b.client.guardian_recovery_shares_for_owner(&native.inviter_principal_id)?.is_empty(),
        "receiving an invite accepted it without the local user"
    );
    let again = seal_control(&a, &b, "invite-good", &retry)?;
    run(&mut b, &again).await?;
    assert_eq!(b.client.pending_guardian_invites()?.len(), 1);
    assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 1);
    // The user's decision stores the share through the native accept and erases the pending copy;
    // a later redelivery of the same event cannot bring the pending share back.
    let selected = b.client.pending_guardian_invites()?.into_iter().next().ok_or_else(|| invalid("pending invite"))?;
    let reply = b.client.decide_pending_guardian_invite(&selected.handle, true)?;
    assert!(reply.is_some_and(|accept| accept.invite_id == "invite-good"));
    assert_eq!(b.client.pending_guardian_invites()?.len(), 0);
    assert_eq!(b.client.guardian_recovery_shares_for_owner(&native.inviter_principal_id)?.len(), 1);
    let late = seal_control(&a, &b, "invite-good", &raw)?;
    run(&mut b, &late).await?;
    assert!(b.client.pending_guardian_invites()?.is_empty(), "redelivery restored an erased share");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_recovery_accept_is_bound_to_a_locally_issued_invite() -> Result<(), SdkError> {
    use crate::error::GeneratedRefusalCode::Authority;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    // The owner never issued this invite: a valid guardian signature is not enough.
    let (guardian, mut owner) = pair(225, 227)?;
    let native = invite(&owner, &guardian, "invite-unissued")?;
    let reply = accept(&guardian, &native)?;
    let raw = guardian
        .client
        .generated_guardian_accept_inner(&reply, &owner.client.own_account_anchor()?)?;
    let entry = seal_control(&guardian, &owner, "accept-unissued", &raw)?;
    assert!(refused(&run(&mut owner, &entry).await, Authority), "unissued accept recorded");
    assert_eq!(owner.client.account_db()?.actor_state_keys("recovery/guardian-accept/")?.len(), 0);

    let (guardian, mut owner) = pair(229, 231)?;
    let native = invite(&owner, &guardian, "invite-issued")?;
    owner
        .client
        .generated_guardian_invite_inner(&native, &guardian.client.own_account_anchor()?)?;
    let reply = accept(&guardian, &native)?;
    let raw = guardian
        .client
        .generated_guardian_accept_inner(&reply, &owner.client.own_account_anchor()?)?;
    let entry = seal_control(&guardian, &owner, "accept-issued", &raw)?;
    run(&mut owner, &entry).await?;
    assert_eq!(owner.client.account_db()?.actor_state_keys("recovery/guardian-accept/")?.len(), 1);
    assert_eq!(owner.client.account_db()?.actor_state_keys(APPLIED)?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn guardian_pending_decisions_bind_source_fingerprint_and_transaction() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for reverse in [false, true] {
        let a = Fixture::owned("shared-device", "alice", 31, 32)?;
        let c = Fixture::owned("shared-device", "carol", 33, 34)?;
        let mut b = Fixture::new("bob", 35)?;
        for (link, sender) in [("a-link", &a), ("c-link", &c)] {
            b.client.establish_friend_link(link, &sender.client.own_account_anchor()?, &b.client.own_account_anchor()?)?;
        }
        let senders = if reverse { [&c, &a] } else { [&a, &c] };
        for sender in senders {
            let native = invite(sender, &b, "colliding-id")?;
            let raw = sender.client.generated_guardian_invite_inner(&native, &b.client.own_account_anchor()?)?;
            let entry = seal_control(sender, &b, "colliding-id", &raw)?;
            run(&mut b, &entry).await?;
        }
        let pending = b.client.pending_guardian_invites()?;
        assert_eq!(pending.len(), 2);
        let source_a = a.client.owned_device_identity()?;
        let selected = pending.iter().find(|row| row.handle.source == source_a.storage_key())
            .ok_or_else(|| invalid("source a selection"))?;
        let mut changed = selected.handle.clone();
        changed.fingerprint.push('x');
        assert!(b.client.decide_pending_guardian_invite(&changed, true).is_err());
        let rollback: Result<(), SdkError> = b.client.account_db()?.write_transaction(|| {
            b.client.decide_pending_guardian_invite(&selected.handle, false)?;
            Err(invalid("injected decision rollback"))
        });
        assert!(rollback.is_err());
        assert_eq!(b.client.pending_guardian_invites()?.len(), 2);
        b.client.remove_friend_link("a-link", "both")?;
        assert!(b.client.decide_pending_guardian_invite(&selected.handle, true).is_err(), "revoked contact accepted");
        assert_eq!(b.client.pending_guardian_invites()?.len(), 2);
        assert!(b.client.decide_pending_guardian_invite(&selected.handle, false)?.is_none());
        let remaining = b.client.pending_guardian_invites()?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].handle.source, c.client.owned_device_identity()?.storage_key());
        assert!(b.client.decide_pending_guardian_invite(&remaining[0].handle, true)?.is_some());
        assert_eq!(b.client.pending_guardian_invites()?.len(), 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_a2i_requires_pinned_signature_and_device_binding() -> Result<(), SdkError> {
    use crate::error::GeneratedRefusalCode::Authority;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for (grant, unknown) in [None, Some("missing"), Some("foreign"), Some("revoked")].into_iter().flat_map(|grant| [false, true].map(|unknown| (grant, unknown))) {
        let (a, mut b) = pair(233, 235)?;
        let mut event = a2i_event(&a, &b, "a2i-closed")?;
        event.grant_id = grant.map(str::to_owned);
        let branch = a.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        event.signed.signature = String::new();
        event.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(branch, &event)?;
        let control = g::Control {
            operation: 11,
            payload: Some(g::control::Payload::A2i(crate::client::routed::native_control::a2i::to_generated(&event)?)),
        };
            let entry = manual_entry(&a, &b, "a2i-closed", &control, unknown)?;
            let result = run(&mut b, &entry).await;
            assert!(refused(&result, Authority), "signed A2I grant={grant:?} unknown={unknown}: {result:?}");
        assert!(refused(&a.client.generated_a2i_inner(&event, &b.client.own_account_anchor()?), Authority));
        let db = b.client.account_db()?;
        assert_eq!(db.actor_state_keys("a2i/scoped/")?.len(), 0);
        assert_eq!(db.actor_state_keys("routed/control/")?.len(), 0);
        assert_eq!(db.actor_state_keys(APPLIED)?.len(), 0);
        assert_eq!(db.unsupported_raw_quota(None)?.raw_bytes, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_group_key_off_its_group_route_is_refused_without_retention()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let key = |event: bool| g::Control {
        operation: 5,
        payload: Some(g::control::Payload::GroupKeyControl(g::GroupKeyControl {
            schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".into(),
            version: 1,
            membership_event: event.then(|| g::NativeGroupEvent { canonical: vec![1] }),
            actor_manifest_url: None,
            distribution: Some(g::GroupKeyDistribution {
                schema: "ramflux.sdk.group_sender_key.distribution.v4".into(),
                version: 4,
                group_id: "group".into(),
                sender_id: "device".into(),
                group_key_epoch: 1,
                group_state_hash: Some("head".into()),
                sender_key_seed: vec![7; 32],
                sender_key_signature: Some("sig".into()),
                sender_device_signing_public_key: Some("key".into()),
            }),
        })),
    };
    for (id, event, code, why) in [
        ("group-key-direct", false, crate::error::GeneratedRefusalCode::Authority, "route"),
        ("group-key-bootstrap", true, crate::error::GeneratedRefusalCode::Content, "bootstrap"),
    ] {
        let (a, mut b) = pair(245, 247)?;
        let entry = manual_entry(&a, &b, id, &key(event), true)?;
        let result = run(&mut b, &entry).await;
        // The reason is part of the assertion: later sender checks must not mask a lost route check.
        assert!(
            matches!(&result, Err(SdkError::GeneratedRefused { code: got, reason })
                if *got == code && reason.contains(why)),
            "{id} was not refused for its {why}: {result:?}"
        );
        assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 0);
        assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn peer_control_author_must_be_the_authenticated_pair_peer() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(249, 251)?;
    b.client.account_db()?.persist_client_record(
        "object",
        "obj-1",
        &serde_json::json!({"owner": a.client.own_account_anchor()?}),
    )?;
    let control = g::Control {
        operation: 12,
        payload: Some(g::control::Payload::ObjectRevoke(g::ObjectRevokeAccess {
            object_id: "obj-1".into(),
            recipient_principal_id: b.client.own_account_anchor()?,
            link_id: "link".into(),
            reason: "removed".into(),
            effective_at: 9,
        })),
    };
    // A well-formed identity whose author is another device of the same root: the transport
    // peer is the object owner, the stated author is not the transport peer.
    let conversation = scope(&a, &b)?;
    let mut identity = generated_identity(&a, "revoke-other-author")?;
    identity.conversation_id = conversation.clone();
    if let Some(author) = identity.author.as_mut() {
        author.device_id = "another-device".into();
    }
    identity.id = g::identity::derive(
        identity.author.as_ref().ok_or_else(|| invalid("author"))?,
        &conversation,
        identity.device_sequence,
    )
    .map_err(|_| invalid("control identity"))?
    .to_vec();
    let raw = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 8,
        identity: Some(identity),
        body: control.encode_to_vec(),
    }
    .encode_to_vec();
    let entry = seal_control(&a, &b, "revoke-other-author", &raw)?;
    assert!(run(&mut b, &entry).await.is_err(), "control with a foreign author executed");
    assert_eq!(b.client.account_db()?.actor_state_keys(APPLIED)?.len(), 0);
    Ok(())
}

#[test]
fn no_known_control_operation_reaches_inbound_pending() {
    let source = include_str!("generated_receive.rs");
    assert!(!source.contains("not yet activated"), "deferred control executor string remains");
    let start = source.find("fn project_known_generated_control").unwrap_or(0);
    let end =
        source[start..].find("fn project_known_generated(").map_or(source.len(), |at| start + at);
    let dispatcher = &source[start..end];
    for arm in [
        "ContactControl",
        "GroupState",
        "GroupKeyControl",
        "OwnContactSync",
        "OwnHistory",
        "RecoveryControl",
        "A2i",
        "ObjectRevoke",
        "OwnContactTombstone",
        "OwnGroupConsent",
        "OwnMessageCopy",
        "Friend",
    ] {
        assert!(
            dispatcher.contains(&format!("Payload::{arm}(")),
            "control arm {arm} has no executor branch"
        );
    }
    assert!(dispatcher.contains("matches!(control.operation, 1 | 2)"));
    assert!(dispatcher.contains("matches!(control.operation, 8 | 10)"));
    assert_eq!(
        dispatcher.matches("InboundPending").count(),
        1,
        "one fallthrough for unknown kinds"
    );
}
