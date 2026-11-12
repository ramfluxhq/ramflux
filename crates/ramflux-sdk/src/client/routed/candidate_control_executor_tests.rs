// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

fn friend_entry(
    a: &Fixture,
    b: &Fixture,
    id: &str,
    friend: g::FriendControl,
    unknown: bool,
) -> Result<GatewayInboxEntry, SdkError> {
    let mut body = g::Control { operation: 16, payload: Some(g::control::Payload::Friend(friend)) }
        .encode_to_vec();
    if unknown {
        body.extend_from_slice(&[0xf8, 0x07, 1]);
    }
    let conversation =
        g::dm_scope::derive(&a.client.own_account_anchor()?, &b.client.own_account_anchor()?)
            .map_err(|_| invalid("DM scope"))?;
    let mut identity = generated_identity(a, id)?;
    identity.conversation_id = conversation.clone();
    identity.id = g::identity::derive(
        identity.author.as_ref().ok_or_else(|| invalid("author"))?,
        &conversation,
        identity.device_sequence,
    )
    .map_err(|_| invalid("Friend identity"))?
    .to_vec();
    let raw =
        g::Inner { layer: g::registry::COMPILED_LAYER, kind: 8, identity: Some(identity), body }
            .encode_to_vec();
    let mut draft = message(id, &conversation);
    draft.envelope_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    seal_as(a, b, draft, &raw, Route::control())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_friend_actions_reach_native_state_with_endpoint_roles() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    for action in 1..=5 {
        let (a, mut b) = pair(141, 143)?;
        let peer = a.client.own_account_anchor()?;
        let own = b.client.own_account_anchor()?;
        let (requester, target) = if action == 2 { (own, peer) } else { (peer, own) };
        if action == 2 {
            b.client.record_pending_friend_link("typed-friend", &requester, &target)?;
        }
        if action >= 3 {
            b.client.establish_friend_link("typed-friend", &requester, &target)?;
        }
        let friend = g::FriendControl {
            action,
            link_id: "typed-friend".into(),
            requester,
            target,
            remove_scope: if action == 3 { Some("both".into()) } else { None },
            blocked: action == 4,
            capability_revoked_at: None,
        };
        let entry = friend_entry(&a, &b, "typed-friend-event", friend, false)?;
        apply(&mut b, &entry).await?;
        let link = b.client.account_db()?.friend_link("typed-friend")?;
        let expected = match action {
            1 => "pending",
            3 => "removed",
            4 => "blocked",
            _ => "accepted",
        };
        assert_eq!(link.state, expected, "Friend native executor action {action}");
        assert_eq!(link.blocked, action == 4);
        assert_eq!(b.client.account_db()?.actor_state_keys("routed/friend-applied/")?.len(), 1);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_friend_wrong_actor_is_refused_before_unsupported_retention()
-> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(145, 147)?;
    // Requested is authored by requester, never by target. Both roots are otherwise valid.
    let friend = g::FriendControl {
        action: 1,
        link_id: "forged-role".into(),
        requester: b.client.own_account_anchor()?,
        target: a.client.own_account_anchor()?,
        ..Default::default()
    };
    let entry = friend_entry(&a, &b, "forged-friend", friend, true)?;
    assert!(
        apply(&mut b, &entry).await.is_err(),
        "wrong Friend endpoint role reached retention/execution"
    );
    assert!(b.client.account_db()?.find_friend_link("forged-role")?.is_none());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_friend_replay_is_exact_and_cannot_rebind_a_link() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(149, 151)?;
    let friend = g::FriendControl {
        action: 1,
        link_id: "stable-link".into(),
        requester: a.client.own_account_anchor()?,
        target: b.client.own_account_anchor()?,
        ..Default::default()
    };
    let entry = friend_entry(&a, &b, "same-friend-id", friend.clone(), false)?;
    apply(&mut b, &entry).await?;
    let row = b.client.account_db()?.friend_link("stable-link")?;
    let again = friend_entry(&a, &b, "same-friend-id", friend.clone(), false)?;
    apply(&mut b, &again).await?;
    assert_eq!(b.client.account_db()?.friend_link("stable-link")?, row);
    let changed = g::FriendControl { link_id: "different-link".into(), ..friend };
    let conflict = friend_entry(&a, &b, "same-friend-id", changed, false)?;
    assert!(
        matches!(apply(&mut b, &conflict).await, Err(SdkError::ReplayMismatch)),
        "changed Friend bytes reused a logical id"
    );
    assert!(b.client.account_db()?.find_friend_link("different-link")?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_friend_accept_cannot_invent_a_local_request() -> Result<(), SdkError> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(153, 155)?;
    let friend = g::FriendControl {
        action: 2,
        link_id: "unrequested-accept".into(),
        requester: b.client.own_account_anchor()?,
        target: a.client.own_account_anchor()?,
        ..Default::default()
    };
    let entry = friend_entry(&a, &b, "unrequested-accept-event", friend, true)?;
    assert!(apply(&mut b, &entry).await.is_err(), "Friend accept fabricated local consent");
    assert!(b.client.account_db()?.find_friend_link("unrequested-accept")?.is_none());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_unknown_control_retention_never_parses_legacy_cache_json() -> Result<(), SdkError>
{
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (a, mut b) = pair(157, 159)?;
    let friend = g::FriendControl {
        action: 1,
        link_id: "future-friend".into(),
        requester: a.client.own_account_anchor()?,
        target: b.client.own_account_anchor()?,
        ..Default::default()
    };
    let entry = friend_entry(&a, &b, "future-friend-event", friend, true)?;
    let result = apply(&mut b, &entry).await;
    assert!(
        result.is_ok(),
        "generated Control fell back to legacy cache: {:?}",
        result.as_ref().err()
    );
    assert!(b.client.account_db()?.find_friend_link("future-friend")?.is_none());
    assert_eq!(b.client.account_db()?.unsupported_raw_quota(None)?.owners, 1);
    assert_eq!(
        b.client.account_db()?.actor_state_keys("routed/friend-applied/")?,
        Vec::<String>::new()
    );
    Ok(())
}
