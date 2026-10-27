// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer dispatch requires independent admission and exact immutable evidence bindings.
use super::*;
use crate::{MigrationPeerCall, MigrationPeerReply};
fn dispatch(s: &Scenario, call: &MigrationPeerCall, now: u64) -> TestResult<MigrationPeerReply> {
    Ok(s.a.core.handle_migration_peer(
        s.a.store()?,
        &s.a.node,
        MigrationPeer { node_id: "B", node_key: &public(9) },
        call,
        now,
    )?)
}
#[test]
fn peer_preflight_binds_owner_destination_request_and_independent_pin() -> TestResult {
    let s = Scenario::prepared()?;
    let owner = attest_request(&s.anchor, "B", &hash(81), NOW)?;
    let call = s.b.node.peer_attest_call(owner, NOW)?;
    let MigrationPeerReply::Attested(home) = dispatch(&s, &call, NOW)? else {
        return Err("attestation refused".into());
    };
    crypto::verify_node(&home.attestation, "A", &public(8))?;
    assert_eq!(home.authority.record, publication()?.record);
    assert_eq!(home.attestation.body.nonce, hash(81));
    assert!(call.verify(MigrationPeer { node_id: "B", node_key: &public(10) }, "A", NOW).is_err());
    assert!(call.verify(MigrationPeer { node_id: "B", node_key: &public(9) }, "C", NOW).is_err());
    let mut changed = call.clone();
    let MigrationPeerCall::Attest { owner, .. } = &mut changed else {
        return Err("attest".into());
    };
    owner.payload.destination_node = "C".into();
    assert!(matches!(
        dispatch(&s, &changed, NOW)?,
        MigrationPeerReply::Refused(Refusal::PeeringUnavailable)
    ));
    assert!(matches!(
        dispatch(&s, &call, NOW + 31 + SKEW_SECONDS)?,
        MigrationPeerReply::Refused(Refusal::PeeringUnavailable)
    ));
    Ok(())
}
#[test]
fn peer_commit_and_status_recover_lost_replies_without_false_noncommit() -> TestResult {
    let mut s = Scenario::prepared()?;
    let sealed = s.seal()?.sealed_evidence()?;
    let early = s.b.node.peer_status_call(s.authorization.clone(), NOW + 1)?;
    assert!(matches!(
        dispatch(&s, &early, NOW + 1)?,
        MigrationPeerReply::Refused(Refusal::CommitOutcomeUnknown)
    ));
    let commit = s.b.node.peer_commit_call(sealed, NOW + 2)?;
    let MigrationPeerReply::Committed(record) = dispatch(&s, &commit, NOW + 2)? else {
        return Err("commit".into());
    };
    s.verify((*record).clone())?;
    s.a.restart()?;
    let status = s.b.node.peer_status_call(s.authorization.clone(), NOW + 3)?;
    let MigrationPeerReply::Committed(recovered) = dispatch(&s, &status, NOW + 3)? else {
        return Err("lost outcome".into());
    };
    assert_eq!(record_hash(&record.record)?, record_hash(&recovered.record)?);
    let mut changed = commit;
    let MigrationPeerCall::Commit { sealed, .. } = &mut changed else {
        return Err("commit".into());
    };
    sealed.delivery_map.clear();
    assert!(matches!(
        dispatch(&s, &changed, NOW + 3)?,
        MigrationPeerReply::Refused(Refusal::PeeringUnavailable)
    ));
    Ok(())
}
#[test]
fn peer_expiry_fence_is_signed_and_never_grants_cancellation_before_deadline() -> TestResult {
    let s = Scenario::prepared()?;
    let deadline = crypto::hard_deadline(&s.authorization.body)?;
    let call = s.b.node.peer_status_call(s.authorization.clone(), deadline + 1)?;
    let MigrationPeerReply::Fenced(fence) = dispatch(&s, &call, deadline + 1)? else {
        return Err("expiry fence".into());
    };
    crypto::verify_node(&fence, "A", &public(8))?;
    assert_eq!(fence.body.authorization_hash, message_hash(&s.authorization)?);
    Ok(())
}

#[test]
fn former_home_read_requires_current_home_and_exact_current_owner_control() -> TestResult {
    let s = Scenario::prepared()?;
    let mut control = attest_request(&s.anchor, "B", &hash(82), NOW + 2)?.control.body;
    control.action = Action::Status;
    let pubn = publication()?;
    let authority = verify_record(&pubn.record, NOW + 2, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let control = crypto::sign_actor(control, &branch, &authority, NOW + 2)?;
    let call = s.a.node.peer_read_call("B", control, NOW + 2)?;
    let invoke = |call: &MigrationPeerCall| {
        s.b.core
            .handle_migration_peer(
                s.b.store()?,
                &s.b.node,
                MigrationPeer { node_id: "A", node_key: &public(8) },
                call,
                NOW + 2,
            )
            .map_err(Into::into)
    };
    let result: TestResult<MigrationPeerReply> = invoke(&call);
    assert!(matches!(result?, MigrationPeerReply::Refused(Refusal::BaseMismatch)));
    let op = s.seal()?;
    let committed = s.commit(&op)?;
    s.b.store()?.activate_home_migration(
        &s.b.node,
        &ResolveResult { home: committed, predecessors: vec![] },
        NOW + 2,
    )?;
    let result: TestResult<MigrationPeerReply> = invoke(&call);
    let MigrationPeerReply::Authorized(reply) = result? else {
        return Err("read authority refused".into());
    };
    crypto::verify_node(&reply, "B", &public(9))?;
    let MigrationPeerCall::AuthorizeRead { authentication, .. } = &call else {
        return Err("read query".into());
    };
    assert_eq!(reply.body.nonce, authentication.body.nonce);
    assert_eq!(reply.body.audience_node, "A");
    assert_eq!(reply.body.authority_record_hash, object_hash(&pubn.record)?);
    let mut changed = call;
    let MigrationPeerCall::AuthorizeRead { owner, .. } = &mut changed else {
        return Err("read query".into());
    };
    owner.body.action = Action::Abort;
    let result: TestResult<MigrationPeerReply> = invoke(&changed);
    assert!(matches!(result?, MigrationPeerReply::Refused(Refusal::PeeringUnavailable)));
    Ok(())
}

#[test]
fn public_peer_resolve_is_purpose_bound_and_returns_no_private_operation_state() -> TestResult {
    let s = Scenario::prepared()?;
    let call = s.b.node.peer_resolve_call(
        "A",
        ramflux_protocol::home_migration::ResolvePayload {
            target_anchor: s.anchor.clone(),
            after_home_hash: None,
            limit: 64,
            old_node_hint: None,
        },
        &s.authorization.body.migration_id,
        NOW,
    )?;
    let reply = dispatch(&s, &call, NOW)?;
    let MigrationPeerReply::Resolved(result) = &reply else {
        return Err("resolve".into());
    };
    assert_eq!(record_hash(&result.home.record)?, s.base.hash());
    let value = serde_json::to_value(&reply)?;
    assert!(value["evidence"].get("backlog_progress").is_none());
    assert!(value["evidence"].get("delivery_map").is_none());
    let mut changed = call;
    let MigrationPeerCall::Resolve { authentication, .. } = &mut changed else {
        return Err("resolve".into());
    };
    let mut body = authentication.body.clone();
    body.kind = ramflux_protocol::home_migration::PeerQueryKind::Attest;
    *authentication = crypto::sign_node(body, "B", &s.b.node.key)?;
    assert!(matches!(
        dispatch(&s, &changed, NOW)?,
        MigrationPeerReply::Refused(Refusal::PeeringUnavailable)
    ));
    Ok(())
}
