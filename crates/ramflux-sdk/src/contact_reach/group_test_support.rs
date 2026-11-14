// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signatures seed the verified-mirror boundary; no home/page verification claim.
use super::SavedReachState;
use crate::{
    client::native_test_support::{Fixture, TestResult},
    custody::ReachCommandContext,
};
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{
    contact_reach::{
        Decision, GROUP_JOIN_NOTICE_DOMAIN, GroupJoinNotice, Permissions, StateRecord, Subject,
    },
    custody,
};
use std::collections::BTreeMap;
pub(super) fn install_grant(peer: &Fixture, state: &VerifiedGroupState) -> TestResult {
    let account = peer.client.born_v3_account.as_ref().ok_or("native peer")?;
    let now = crate::custody::network_now()?;
    let subject = Subject::Group {
        group_id: state.view().group_id.clone(),
        conversation_id: state.view().conversation_id.clone(),
        genesis_hash: state.genesis_hash()?,
        group_epoch: state.view().epoch,
        membership_hash: state.snapshot().state_hash.clone(),
    };
    let home = ramflux_protocol::encode_base64url([24; 32]);
    let context = ReachCommandContext {
        actor: &account.record().body.master_certificate.body.primary_device_ref,
        home_head_hash: &home,
        expected_revision: 1,
        now,
    };
    let notice = GroupJoinNotice {
        version: 1,
        recipient_root: account.record().body.account_anchor.clone(),
        group_id: state.view().group_id.clone(),
        conversation_id: state.view().conversation_id.clone(),
        genesis_hash: state.genesis_hash()?,
        epoch: state.view().epoch,
        membership_hash: state.snapshot().state_hash.clone(),
        inviter_root: state.creator().identity.root_commitment.clone(),
        member_root_count: 2,
    };
    let mut body = account.reach_decision_body(&context, subject.clone(), Decision::Allow)?;
    body.permissions = Some(Permissions::UNACCEPTED);
    body.grant_until = Some(0);
    body.notice_hash = Some(custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, &notice)?);
    body.evidence_hash = Some(state.snapshot().state_hash.clone());
    let update = account.group_primary(peer.vault.as_ref())?.sign_reach_admission(
        body,
        account.verified(),
        now,
    )?;
    let mirror = SavedReachState {
        root: account.record().body.account_anchor.clone(),
        revision: 2,
        admission_revision: 2,
        home_head_hash: home,
        state_hash: ramflux_protocol::encode_base64url([25; 32]),
        records: vec![StateRecord::Grant {
            subject,
            permissions: Permissions::UNACCEPTED,
            grant_until: 0,
            update,
        }],
        restrictions: BTreeMap::new(),
        conflict: false,
    };
    // Seed the already verified mirror boundary; this test does not assert home/page verification.
    peer.client.account_db()?.persist_client_record(
        "reach",
        "state",
        &serde_json::to_value(mirror)?,
    )?;
    Ok(())
}
